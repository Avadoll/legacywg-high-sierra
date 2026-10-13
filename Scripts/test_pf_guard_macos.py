"""Disposable CI experiment, never a shipped firewall or end-user command.

Only a random owned child of the existing Apple wildcard is changed. Fixed
synthetic benchmark UDP traffic is captured on the guest's egress Ethernet
NIC. No global load/flush/disable/state kill, foreign state or route mutation.
Two references are ours; retaining the second models reference coexistence,
not proof of coexistence with arbitrary third-party rules. A pinned netstack
fixture separately checks native established TCP on an owned utun. Physical
TCP/IPv6, DNS leak policy, crash/power-loss and High Sierra remain untested.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import signal
import socket
import stat
import struct
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
STATE=Path('/var/run/legacywg-pf-ci')
DEST='198.18.99.90'
WARM=45101
FRESH=45102
ENV={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LANG':'C','LC_ALL':'C'}
EMPTY=hashlib.sha256(b'').hexdigest()

def run(program,arguments,input_text=None):
    result=subprocess.run([program,*arguments],input=input_text,capture_output=True,
                          text=True,timeout=8,env=ENV)
    if result.returncode or len(result.stdout.encode())+len(result.stderr.encode())>512*1024:
        raise RuntimeError('bounded native operation failed')
    return result.stdout,result.stderr

def pf(*args,input_text=None):
    return run('/sbin/pfctl',args,input_text)[0]

def digest(text):return hashlib.sha256(text.encode()).hexdigest()

def enabled():
    info=pf('-s','info')
    match=re.search(r'^Status:\s+(Enabled|Disabled)\b',info,re.M)
    count=re.search(r'^\s*current entries\s+(\d+)\b',info,re.M)
    if not match or not count:raise RuntimeError('unknown native information format')
    return match[1]=='Enabled',int(count[1])

def directory_valid():
    metadata=STATE.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid!=0 or stat.S_IMODE(metadata.st_mode)!=0o700:
        raise RuntimeError('unsafe developer state directory')

def write_state(data):
    directory_valid()
    temporary=STATE/'next.json'
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        blob=(json.dumps(data,sort_keys=True,separators=(',',':'))+'\n').encode()
        with os.fdopen(fd,'wb') as stream:stream.write(blob);stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,STATE/'state.json')
        fd=os.open(STATE,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
    except BaseException:
        # An ambiguous record is preserved; no generic recursive cleanup.
        raise

def read_state():
    directory_valid()
    fd=os.open(STATE/'state.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        metadata=os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid!=0 or stat.S_IMODE(metadata.st_mode)!=0o600 or metadata.st_nlink!=1:
            raise RuntimeError('unsafe developer recovery record')
        blob=stream.read(4097)
    if len(blob)>4096:raise RuntimeError('oversized developer record')
    data=json.loads(blob)
    if set(data)!={'version','anchor','tokens','rules_hashes'} or data['version']!=1:
        raise RuntimeError('unknown developer record')
    if not re.fullmatch(r'com\.apple/legacywg-ci-[0-9a-f]{32}',data['anchor']):
        raise RuntimeError('invalid owned anchor identity')
    if type(data['tokens']) is not list or len(data['tokens'])>2 or len(set(data['tokens']))!=len(data['tokens']):
        raise RuntimeError('invalid owned reference set')
    if any(type(token) is not int or not 0<token<2**64 for token in data['tokens']):
        raise RuntimeError('invalid owned reference')
    if type(data['rules_hashes']) is not list or len(data['rules_hashes'])>16 or any(not re.fullmatch('[0-9a-f]{64}',item) for item in data['rules_hashes']):
        raise RuntimeError('invalid rule identity')
    if blob!=(json.dumps(data,sort_keys=True,separators=(',',':'))+'\n').encode():
        raise RuntimeError('noncanonical developer record')
    return data

def acquire(data):
    output,error=run('/sbin/pfctl',['-E'])
    tokens=re.findall(r'\bToken\s*:\s*(\d+)\b',output+'\n'+error)
    if len(tokens)!=1 or not 0<int(tokens[0])<2**64:
        # Never fall back to global -d if a token cannot be recovered.
        raise RuntimeError('owned reference acquisition unconfirmed')
    data['tokens'].append(int(tokens[0]));write_state(data)

def release(data):
    token=data['tokens'][-1]
    run('/sbin/pfctl',['-X',str(token)])
    data['tokens'].pop();write_state(data)

def load(data,rules):
    # Dry-run syntax before the ONLY permitted ruleset load: this owned child.
    pf('-n','-a',data['anchor'],'-f','-',input_text=rules)
    pf('-a',data['anchor'],'-f','-',input_text=rules)
    actual=pf('-a',data['anchor'],'-s','rules')
    hashed=digest(actual)
    if hashed not in data['rules_hashes']:data['rules_hashes'].append(hashed)
    write_state(data)

def admit_stateless_candidate(data,rules):
    # Experimental admission gate, not a production fail-closed claim. Existing
    # states are preserved and refused BEFORE any candidate rule mutation.
    # A post-load recheck catches a state created during admission; complete
    # foreign-rule concurrency guarantees still require a separate proof.
    if enabled()[1]!=0:return False
    load(data,rules)
    if enabled()[1]!=0:raise RuntimeError('new state appeared during stateless admission')
    return True

def cleanup():
    if not STATE.exists():return {'status':'NO_OWNED_RECORD'}
    data=read_state()
    current=pf('-a',data['anchor'],'-s','rules')
    if digest(current) not in data['rules_hashes']:
        raise RuntimeError('owned rules changed or last commit unconfirmed; refusing deletion')
    if current:load(data,'')
    if pf('-a',data['anchor'],'-s','rules'):raise RuntimeError('owned rules still present')
    while data['tokens']:release(data)
    (STATE/'state.json').unlink()
    STATE.rmdir()
    return {'status':'PASS','own_anchor_empty':True,'own_references_released':True,
            'state_kill_used':False,'global_disable_used':False,'global_rules_loaded':False}

def only_default_calls(text):
    lines=[line.strip() for line in text.splitlines() if line.strip()]
    # Enabling PF must not activate an unknown existing filter/NAT policy.
    return all(line=='}' or line=='scrub-anchor "com.apple/*" all fragment reassemble' or
        re.fullmatch(r'(?:anchor|scrub-anchor|nat-anchor|rdr-anchor) "[A-Za-z0-9_.*/-]+"(?: all)?(?: \{)?',line) for line in lines)

def capture_counts(path):
    blob=path.read_bytes()
    if len(blob)>128*1024 or len(blob)<24:raise RuntimeError('invalid bounded capture')
    byteorders={b'\xd4\xc3\xb2\xa1':'<',b'\xa1\xb2\xc3\xd4':'>'}
    order=byteorders.get(blob[:4])
    if order is None:raise RuntimeError('unknown capture format')
    _,_,_,_,snaplen,kind=struct.unpack(order+'HHIIII',blob[4:24])
    if kind!=1 or snaplen!=128:raise RuntimeError('capture is not Ethernet')
    result={WARM:0,FRESH:0};offset=24
    while offset<len(blob):
        if offset+16>len(blob):raise RuntimeError('truncated packet header')
        _,_,length,original=struct.unpack(order+'IIII',blob[offset:offset+16]);offset+=16
        if length>128 or length>original or offset+length>len(blob):raise RuntimeError('invalid packet size')
        frame=blob[offset:offset+length];offset+=length
        if len(frame)<42 or frame[12:14]!=b'\x08\x00':continue
        packet=frame[14:];header=(packet[0]&15)*4
        if packet[0]>>4!=4 or packet[9]!=17 or packet[16:20]!=socket.inet_aton(DEST) or header<20 or header+8>len(packet):continue
        _,port=struct.unpack('!HH',packet[header:header+4])
        if port in result:result[port]+=1
    return result

def transmit(warm,fresh):
    # Darwin can surface asynchronous ICMP refusal from the nonexistent
    # benchmark peer on a later send, including on an unconnected UDP socket.
    # Eight attempts still require three actual captured packets in controls,
    # even when the first send consumes a pending ICMP error.
    for _ in range(8):
        for stream,port in ((warm,WARM),(fresh,FRESH)):
            if stream is not None:
                try:stream.sendto(b'LegacyWG-disposable-PF-fixture',(DEST,port))
                except OSError:pass # PF can reject at send; packet capture is the assertion.
        time.sleep(0.08)

def captured(data,iface,phase,warm,fresh):
    path=STATE/(phase+'.pcap')
    expression=f'ip and dst host {DEST} and udp and (dst port {WARM} or dst port {FRESH})'
    process=subprocess.Popen(['/usr/sbin/tcpdump','-n','-U','-i',iface,'-s','128','-w',str(path),expression],
                             stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,env=ENV)
    try:
        time.sleep(0.6)
        if process.poll() is not None:raise RuntimeError('capture unavailable')
        transmit(warm,fresh);time.sleep(0.6)
    finally:
        process.send_signal(signal.SIGINT) if process.poll() is None else None
        try:_,error=process.communicate(timeout=4)
        except subprocess.TimeoutExpired:process.kill();process.communicate();raise RuntimeError('capture did not stop')
    if process.returncode or b'listening on' not in error or not re.search(rb'\b0 packets dropped by kernel\b',error):
        raise RuntimeError('capture invalid or dropped packets')
    try:return capture_counts(path)
    finally:path.unlink(missing_ok=True) # Own narrow capture is never uploaded.

def experiment(report):
    report['last_step']='read_only_preflight'
    before={'rules':pf('-s','rules'),'nat':pf('-s','nat'),
            'recursive_rules':pf('-a','*','-s','rules'),'recursive_nat':pf('-a','*','-s','nat')}
    active,states=enabled()
    settings={'timeouts':pf('-s','timeouts'),'limits':pf('-s','memory')}
    report['preflight']={'pf_enabled':active,'state_count':states,
        'rule_sets':{name:{'sha256':digest(text),'only_empty_anchor_calls':only_default_calls(text),
            'line_count':len(text.splitlines()),'brace_count':text.count('{')+text.count('}')}
            for name,text in before.items()}}
    if active or states or not all(only_default_calls(text) for text in before.values()):
        raise RuntimeError('fresh disabled empty-state default-only PF required')
    if not re.search(r'^anchor "com\.apple/\*"',before['rules'],re.M):
        raise RuntimeError('existing root wildcard absent')
    route,_=run('/sbin/route',['-n','get','-inet',DEST])
    match=re.search(r'^\s*interface:\s*(en[0-9]+)\s*$',route,re.M)
    if not match or not re.search(r'^\s*gateway:\s*\d+\.\d+\.\d+\.\d+\s*$',route,re.M):
        raise RuntimeError('synthetic benchmark has no egress Ethernet gateway')
    iface=match[1]
    STATE.mkdir(mode=0o700)
    data={'version':1,'anchor':'com.apple/legacywg-ci-'+secrets.token_hex(16),'tokens':[],'rules_hashes':[EMPTY]}
    write_state(data)
    if pf('-a',data['anchor'],'-s','rules'):raise RuntimeError('owned anchor already occupied')
    warm=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);fresh=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    # Stable source ports retain the same UDP tuple without connected-socket
    # asynchronous ICMP errors from a deliberately nonexistent benchmark peer.
    warm.bind(('0.0.0.0',0));fresh.bind(('0.0.0.0',0))
    try:
        report['last_step']='egress_baseline_capture'
        baseline=captured(data,iface,'baseline',warm,fresh)
        report['baseline_packets']={'existing_udp':baseline[WARM],'fresh_udp':baseline[FRESH]}
        if min(baseline.values())<3:raise RuntimeError('synthetic baseline absent from egress capture')
        report['last_step']='owned_reference_and_pass_rule'
        acquire(data)
        load(data,f'pass out quick on {iface} inet proto udp from any to {DEST} port {WARM} keep state\n')
        report['last_step']='warmed_udp_state_capture'
        warmed=captured(data,iface,'warmed',warm,None)
        if warmed[WARM]<3 or DEST+':'+str(WARM) not in pf('-s','states'):
            raise RuntimeError('owned UDP state not confirmed')
        report['last_step']='owned_replacement_block_capture'
        load(data,f'block drop out quick on {iface} inet proto udp from any to {DEST} port {{ {WARM}, {FRESH} }}\n')
        blocked=captured(data,iface,'blocked',warm,fresh)
        counters=pf('-a',data['anchor'],'-v','-s','rules')
        block_packets=sum(int(item) for item in re.findall(r'\bPackets:\s*(\d+)\b',counters))
        report['block_rule_packet_count']=block_packets
        if block_packets<3:raise RuntimeError('owned block rule did not confirm benchmark packets')
        if blocked[FRESH]!=0:raise RuntimeError('fresh UDP was not blocked at egress')
        report.update({'baseline_packets':{'existing_udp':baseline[WARM],'fresh_udp':baseline[FRESH]},
                       'blocked_phase_packets':{'existing_udp':blocked[WARM],'fresh_udp':blocked[FRESH]},
                       'new_udp_egress_blocked':True,'existing_udp_state_confirmed':True,
                       'existing_udp_bypasses_replacement_block':blocked[WARM]>0,
                       'capture':'guest egress Ethernet NIC, fixed synthetic IPv4 UDP only'})
        report['last_step']='refuse_nonempty_state_candidate'
        candidate=(f'pass out quick on {iface} inet proto udp from any to {DEST} port {WARM} no state\n'
                   f'block drop out quick on {iface} inet proto udp from any to {DEST} port {FRESH}\n')
        prior_states=pf('-s','states');prior_rules=pf('-a',data['anchor'],'-s','rules')
        prior_tokens=data['tokens'].copy()
        if admit_stateless_candidate(data,candidate):raise RuntimeError('nonempty-state candidate incorrectly admitted')
        if pf('-s','states')!=prior_states or pf('-a',data['anchor'],'-s','rules')!=prior_rules or data['tokens']!=prior_tokens:
            raise RuntimeError('refused admission changed states, rules or references')
        refused=captured(data,iface,'refused-candidate',warm,None)
        if refused[WARM]<3:raise RuntimeError('existing flow changed by refused admission')
        report['nonempty_state_admission']={'status':'REFUSED','states_rules_references_preserved':True,
            'existing_udp_packets_after_refusal':refused[WARM]}
        # Developer fixture only: stop sending and let the normal PF timeout
        # expire the one state we deliberately created. Never kill it or change
        # a global timeout. Production admission would refuse immediately.
        report['last_step']='wait_normal_own_fixture_state_expiry'
        started=time.monotonic();deadline=started+90
        while enabled()[1]!=0 and time.monotonic()<deadline:time.sleep(2)
        if enabled()[1]!=0:raise RuntimeError('fixture state did not expire; no forced cleanup permitted')
        report['fixture_state_expiry']={'status':'PASS','elapsed_seconds':round(time.monotonic()-started,1),
            'state_kill_or_timeout_change':False}
        report['last_step']='stateless_candidate_admission'
        if not admit_stateless_candidate(data,candidate):raise RuntimeError('empty-state candidate refused')
        stateless=captured(data,iface,'stateless-candidate',warm,fresh)
        if stateless[WARM]<3 or stateless[FRESH]!=0 or enabled()[1]!=0:
            raise RuntimeError('stateless exception or fresh block failed')
        report['stateless_udp_exception']={'status':'PASS','allowed_packets':stateless[WARM],
            'blocked_packets':stateless[FRESH],'state_count_after_traffic':0}
        # Remove that exception. Previously permitted traffic must now hit the
        # block instead of inheriting a keep-state permission.
        report['last_step']='close_stateless_udp_exception'
        load(data,f'block drop out quick on {iface} inet proto udp from any to {DEST} port {{ {WARM}, {FRESH} }}\n')
        closed=captured(data,iface,'closed-exception',warm,fresh)
        closed_counters=pf('-a',data['anchor'],'-v','-s','rules')
        closed_packets=sum(int(item) for item in re.findall(r'\bPackets:\s*(\d+)\b',closed_counters))
        if any(closed.values()) or closed_packets<6 or enabled()[1]!=0:
            raise RuntimeError('removed stateless exception left an egress bypass')
        report['stateless_exception_removal']={'status':'PASS','previously_allowed_packets':closed[WARM],
            'fresh_packets':closed[FRESH],'native_block_counter':closed_packets,'state_count_after_traffic':0}
        report['last_step']='owned_utun_tcp_state_policy'
        from test_pf_tcp_macos import test_tcp
        base_rules=f'block drop out quick on {iface} inet proto udp from any to {DEST} port {{ {WARM}, {FRESH} }}\n'
        report['tcp_fixture']={'status':'RUNNING'}
        test_tcp(data,base_rules,load=load,pf=pf,enabled=enabled,admit=admit_stateless_candidate,report=report['tcp_fixture'])
        report['established_tcp']='PASS on owned-utun fixture; physical Ethernet TCP NOT_RUN'
        report['ipv6']='PASS on owned-utun TCP fixture; physical IPv6 NOT_RUN'
        load(data,base_rules)
        report['last_step']='second_owned_reference'
        acquire(data);release(data)
        if not enabled()[0]:raise RuntimeError('other owned reference was lost')
        held=captured(data,iface,'second-reference',None,fresh)
        if held[FRESH]!=0:raise RuntimeError('guard lost while another owned reference held')
        report['second_owned_reference_preserved']=True
        # Clear only our verified child then release only our final token.
        report['last_step']='release_and_egress_restoration'
        load(data,'');release(data)
        if enabled()[0]:raise RuntimeError('PF remained enabled after our final release')
        restored=captured(data,iface,'restored',None,fresh)
        if restored[FRESH]<3:raise RuntimeError('ordinary synthetic egress not restored')
        after={name:pf(*args) for name,args in {
            'rules':('-s','rules'),'nat':('-s','nat'),
            'recursive_rules':('-a','*','-s','rules'),'recursive_nat':('-a','*','-s','nat')}.items()}
        if after!=before:raise RuntimeError('foreign rule text changed')
        if settings!={'timeouts':pf('-s','timeouts'),'limits':pf('-s','memory')}:
            raise RuntimeError('global timeout or limit settings changed')
        report.update({'ordinary_synthetic_egress_restored':True,'root_and_foreign_rules_unchanged':True,
                       'initial_rule_hashes':{key:digest(value) for key,value in before.items()},
                       'state_count_after_reference_release':enabled()[1],
                       'existing_state_cleanup':'Normal expiry of own fixture confirmed; never kill/flush state table',
                       'ruleset_packet_counter_proof':'PASS',
                       'global_timeouts_and_limits_unchanged':True})
        report['last_step']='completed'
    finally:warm.close();fresh.close()

def main():
    if platform.system()!='Darwin' or os.geteuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_OS')!='macOS':
        raise SystemExit('Only the root disposable GitHub macOS CI experiment is permitted')
    if sys.argv[1:]==['--cleanup']:
        try:print(json.dumps(cleanup()))
        except Exception:print(json.dumps({'status':'REFUSED','reason':'owned cleanup unconfirmed; no global fallback'}));sys.exit(1)
        return
    if sys.argv[1:]:raise SystemExit('No paths, rules or endpoints accepted')
    report={'kind':'developer-only-scoped-PF-egress-experiment','source_commit':os.environ.get('GITHUB_SHA'),
            'host_os':platform.mac_ver()[0],'host_arch':platform.machine(),
            'protection_ready':False,'high_sierra':'NOT_RUN','established_tcp':'NOT_RUN',
            'ipv6':'NOT_RUN','dns_leak_policy':'NOT_RUN','crash_power_loss_recovery':'NOT_RUN',
            'foreign_quick_anchor_coexistence':'NOT_RUN','pf_api_stability':'NOT_GUARANTEED'}
    try:experiment(report);report['status']='PASS'
    except Exception as error:
        report['status']='FAIL'
        # Only fixed exceptions from this script; subprocess diagnostics not exported.
        report['reason']=str(error) if type(error) is RuntimeError else 'developer experiment failed'
    finally:
        try:report['owned_cleanup']=cleanup()
        except Exception:
            report['owned_cleanup']={'status':'REFUSED','reason':'owned cleanup unconfirmed; no global fallback'}
            report['status']='FAIL'
    output=ROOT/'Build/CI';output.mkdir(parents=True,exist_ok=True)
    (output/'pf-guard-ci.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    if report['status']!='PASS':sys.exit(1)

if __name__=='__main__':main()
