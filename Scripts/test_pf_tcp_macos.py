"""Owned-utun established TCP/PF proof, not physical or encrypted traffic."""
from __future__ import annotations
import json
import os
from pathlib import Path
import re
import selectors
import socket
import subprocess
import time

ROOT=Path(__file__).resolve().parents[1]
V4='198.18.99.130'
V6='fd00:198:18:99::130'

def read_reply(process):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout,selectors.EVENT_READ)
        if not selector.select(5):raise RuntimeError('owned TCP fixture reply timeout')
    line=process.stdout.readline(4097)
    if len(line)>4096 or not line.endswith('\n'):raise RuntimeError('invalid bounded TCP fixture reply')
    result=json.loads(line)
    if not isinstance(result,dict):raise RuntimeError('invalid TCP fixture reply')
    return result

def stats(process):
    process.stdin.write('stats\n');process.stdin.flush();value=read_reply(process)
    if set(value)!={'tcp4_packets','tcp6_packets','accepted'} or any(type(x) is not int or x<0 for x in value.values()):
        raise RuntimeError('invalid TCP fixture counters')
    return value

def connect(address,port=45111):
    stream=socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET,socket.SOCK_STREAM)
    stream.settimeout(2)
    try:stream.connect((address,port));return stream
    except BaseException:stream.close();raise

def echo(stream,marker):
    stream.settimeout(2);stream.sendall(marker)
    data=b''
    while len(data)<len(marker):
        part=stream.recv(len(marker)-len(data))
        if not part:raise RuntimeError('owned TCP echo closed')
        data+=part
    if data!=marker:raise RuntimeError('owned TCP echo mismatch')

def wait_empty(enabled,timeout):
    started=time.monotonic();deadline=started+timeout
    while enabled()[1]!=0 and time.monotonic()<deadline:time.sleep(2)
    if enabled()[1]!=0:raise RuntimeError('owned TCP state did not expire; no forced state kill')
    return round(time.monotonic()-started,1)

def test_tcp(data,base_rules,*,load,pf,enabled,admit,report):
    if os.geteuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true':raise RuntimeError('disposable native TCP test only')
    interfaces=subprocess.check_output(['/sbin/ifconfig','-l'],text=True).split()
    process=subprocess.Popen([str(ROOT/'Build/Research/legacywg-pf-state-fixture')],stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,bufsize=1,
        env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LANG':'C','LC_ALL':'C','GITHUB_ACTIONS':'true'})
    streams=[];result=report
    result.update({'scope':'native kernel TCP to owned utun/netstack; physical Ethernet TCP NOT_RUN',
                   'encrypted_traffic':'NOT_RUN','state_kill_used':False,'stage':'fixture_start'})
    try:
        ready=read_reply(process)
        name=ready.get('interface')
        if ready.get('ready') is not True or not isinstance(name,str) or not re.fullmatch('utun[0-9]{1,10}',name) or type(ready.get('index')) is not int:
            raise RuntimeError('owned TCP fixture not ready')
        tcp_block=(f'block drop out quick on {name} inet proto tcp from any to {V4} port {{ 45111, 45112 }}\n'
                   f'block drop out quick on {name} inet6 proto tcp from any to {V6} port {{ 45111, 45112 }}\n')
        tcp_pass=(f'pass out quick on {name} inet proto tcp from any to {V4} port {{ 45111, 45112 }} no state\n'
                  f'pass out quick on {name} inet6 proto tcp from any to {V6} port {{ 45111, 45112 }} no state\n')
        result['stage']='established_ipv4_keep_state_echo'
        load(data,f'pass out quick on {name} inet proto tcp from any to {V4} port 45111 keep state\n'+base_rules)
        old=connect(V4);streams.append(old);echo(old,b'LegacyWG-owned-established-TCP')
        if enabled()[1]==0:raise RuntimeError('established TCP state not confirmed')
        result['stage']='existing_tcp_state_bypass_and_admission_refusal'
        load(data,tcp_block+base_rules)
        # Native established TCP really exchanges data through its old state.
        before=stats(process);echo(old,b'LegacyWG-old-state-still-passes');after=stats(process)
        if after['tcp4_packets']<=before['tcp4_packets']:raise RuntimeError('existing TCP bypass not observed')
        prior_states=pf('-s','states');prior_rules=pf('-a',data['anchor'],'-s','rules')
        prior_tokens=data['tokens'].copy()
        if admit(data,tcp_pass+base_rules) or pf('-s','states')!=prior_states or pf('-a',data['anchor'],'-s','rules')!=prior_rules or data['tokens']!=prior_tokens:
            raise RuntimeError('TCP state refusal failed or mutated existing policy')
        result['established_keep_state_bypass_confirmed']=True
        result['nonempty_tcp_state_admission_refused_without_mutation']=True
        result['stage']='graceful_close_and_normal_state_expiry'
        old.shutdown(socket.SHUT_WR)
        old.settimeout(2)
        if old.recv(1)!=b'':raise RuntimeError('owned TCP fixture did not close gracefully')
        old.close();streams.remove(old)
        result['normal_tcp_state_expiry_seconds']=wait_empty(enabled,150)
        result['stage']='stateless_dual_stack_established_echo'
        if not admit(data,tcp_pass+base_rules):raise RuntimeError('empty-state TCP candidate not admitted')
        for address in (V4,V6):
            connection=connect(address);streams.append(connection);echo(connection,b'LegacyWG-stateless-TCP-echo')
        if enabled()[1]!=0:raise RuntimeError('no-state TCP exception created PF state')
        result['stage']='stateless_exception_removal_blocks_existing_and_fresh_tcp'
        load(data,tcp_block+base_rules)
        time.sleep(.2) # Drain packets emitted before the synchronous rule commit.
        before=stats(process)
        blocked_marker=b'LegacyWG-must-not-reach-owned-peer'
        for connection in streams:
            connection.settimeout(.5);connection.sendall(blocked_marker)
            try:
                if connection.recv(1):raise RuntimeError('existing stateless TCP escaped removed exception')
                raise RuntimeError('existing stateless TCP closed unexpectedly')
            except socket.timeout:pass
        for address in (V4,V6):
            probe=socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET,socket.SOCK_STREAM)
            probe.settimeout(.5)
            try:
                try:probe.connect((address,45112))
                except socket.timeout:pass
                else:raise RuntimeError('fresh TCP escaped scoped block')
            finally:probe.close()
        after=stats(process)
        counters=pf('-a',data['anchor'],'-v','-s','rules')
        blocked_count=sum(int(item) for item in re.findall(r'\bPackets:\s*(\d+)\b',counters))
        if after['tcp4_packets']!=before['tcp4_packets'] or after['tcp6_packets']!=before['tcp6_packets'] or blocked_count<4 or enabled()[1]!=0:
            raise RuntimeError('native TCP block/counter proof failed')
        result.update({'stateless_ipv4_ipv6_established_and_fresh_blocked':True,
            'peer_tcp_packet_delta_while_blocked':0,'native_block_counter':blocked_count,'state_count_after_block':0})
        result['stage']='explicit_reallow_resumes_tcp'
        load(data,tcp_pass+base_rules)
        # Previously queued kernel TCP data resumes only after reallowing it.
        for connection in streams:
            connection.settimeout(6);received=b''
            while len(received)<len(blocked_marker):
                packet=connection.recv(len(blocked_marker)-len(received))
                if not packet:raise RuntimeError('TCP did not resume after exception restored')
                received+=packet
            if received!=blocked_marker:raise RuntimeError('TCP resumed with wrong data')
            echo(connection,b'LegacyWG-stateless-restored')
        if enabled()[1]!=0:raise RuntimeError('restored no-state TCP created PF state')
        result['stateless_connections_resume_after_explicit_reallow']=True
        result['stage']='fixture_shutdown'
    finally:
        for connection in streams:connection.close()
        if process.stdin and not process.stdin.closed:process.stdin.close()
        try:process.wait(timeout=4)
        except subprocess.TimeoutExpired:process.kill();process.wait(timeout=4)
        if process.stdout:process.stdout.close()
        # utun disappearance is the cleanup for its interface-bound routes.
        if set(subprocess.check_output(['/sbin/ifconfig','-l'],text=True).split())!=set(interfaces):
            raise RuntimeError('owned TCP interface cleanup unconfirmed')
        result['fixture_exit_code']=process.returncode
    result['owned_interface_set_restored']=True
    if process.returncode!=0:raise RuntimeError('owned TCP fixture did not exit cleanly')
    result['status']='PASS';result['stage']='completed'
    return result
