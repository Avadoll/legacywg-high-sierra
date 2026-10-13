"""Disposable PF reference crash experiment; never called by the product.

Tests write-before-effect acquisition intent and identity refusal. Private
token/PID/boot metadata stays in root-only state and pipes. Does not establish
atomic compare-and-release, durable production storage, reboot or High Sierra.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import platform
import re
import selectors
import stat
import subprocess
import sys
import time

from test_pf_guard_macos import pf, enabled, only_default_calls, digest, ENV

ROOT=Path(__file__).resolve().parents[1]
STATE=Path('/var/run/legacywg-ref-ci')
NAME='legacywg-ref'

def boot():
    value=subprocess.check_output(['/usr/sbin/sysctl','-n','kern.bootsessionuuid'],env=ENV,timeout=3,text=True).strip()
    if not re.fullmatch('[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}',value):
        raise RuntimeError('unknown boot identity')
    return value.upper()

def validate(data):
    if type(data) is not dict or set(data)!={'version','boot','intents'} or type(data['version']) is not int or data['version']!=1:
        raise RuntimeError('unknown developer intent schema')
    if type(data['boot']) is not str or not re.fullmatch('[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}',data['boot']):
        raise RuntimeError('invalid recorded boot')
    if type(data['intents']) is not list or len(data['intents'])>2:raise RuntimeError('invalid developer intent set')
    for item in data['intents']:
        if type(item) is not dict or set(item)!={'pid','name','after','before','token'} or item['name']!=NAME:
            raise RuntimeError('invalid developer owner identity')
        if any(type(item[k]) is not int for k in ('pid','after','before','token')) or not 0<item['pid']<2**31 or not 0<item['after']<=item['before']<=item['after']+5 or not 0<=item['token']<2**64:
            raise RuntimeError('invalid bounded intent identity')
    if len({x['pid'] for x in data['intents']})!=len(data['intents']):raise RuntimeError('duplicate developer owner')
    return data

def directory_valid():
    m=STATE.lstat()
    if not stat.S_ISDIR(m.st_mode) or m.st_uid!=0 or stat.S_IMODE(m.st_mode)!=0o700:
        raise RuntimeError('unsafe developer intent directory')

def write(data):
    validate(data);directory_valid()
    fd=os.open(STATE/'next.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write((json.dumps(data,sort_keys=True,separators=(',',':'))+'\n').encode());stream.flush();os.fsync(stream.fileno())
    os.replace(STATE/'next.json',STATE/'state.json')
    fd=os.open(STATE,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)

def read():
    directory_valid()
    fd=os.open(STATE/'state.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        m=os.fstat(stream.fileno())
        if not stat.S_ISREG(m.st_mode) or m.st_uid!=0 or stat.S_IMODE(m.st_mode)!=0o600 or m.st_nlink!=1:
            raise RuntimeError('unsafe developer intent record')
        blob=stream.read(4097)
    if len(blob)>4096:raise RuntimeError('oversized developer intent record')
    value=validate(json.loads(blob))
    if blob!=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode():raise RuntimeError('noncanonical developer intent record')
    return value

def reply(process):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout,selectors.EVENT_READ)
        if not selector.select(3):raise RuntimeError('private reference reply timeout')
    line=process.stdout.readline(4097)
    if len(line)>4096 or not line.endswith('\n'):raise RuntimeError('invalid private reference reply')
    value=json.loads(line)
    if type(value) is not dict:raise RuntimeError('unknown private reference reply')
    return value

def command(process,text):
    process.stdin.write(text+'\n');process.stdin.flush();return reply(process)

def start(children):
    process=subprocess.Popen([str(ROOT/'Build/Research'/NAME)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,text=True,bufsize=1,env={**ENV,'GITHUB_ACTIONS':'true'})
    children.append(process)
    ready=reply(process)
    if set(ready)!={'ready','pid','epoch'} or ready['ready'] is not True or ready['pid']!=process.pid or type(ready['epoch']) is not int or abs(time.time()-ready['epoch'])>2:
        raise RuntimeError('private reference owner not ready')
    return process,{'pid':process.pid,'name':NAME,'after':ready['epoch'],'before':ready['epoch']+5,'token':0}

def stop(process,kill=False):
    if kill and process.poll() is None:process.kill()
    if process.stdin and not process.stdin.closed:process.stdin.close()
    process.wait(timeout=3)
    if process.stdout and not process.stdout.closed:process.stdout.close()
    if process.returncode not in (0,-9):raise RuntimeError('private reference owner did not stop as expected')

def references():
    children=[]
    try:
        process,_=start(children);value=command(process,'references')
        if set(value)!={'references'} or type(value['references']) is not list or len(value['references'])>16:
            raise RuntimeError('unknown bounded kernel reference set')
        entries=value['references']
        for entry in entries:
            if type(entry) is not dict or set(entry)!={'token','epoch','pid','name'} or type(entry['name']) is not str or len(entry['name'])>63 or any(type(entry[k]) is not int or entry[k]<=0 for k in ('token','epoch','pid')) or entry['token']>=2**64 or entry['pid']>=2**31:
                raise RuntimeError('invalid kernel reference identity')
        if len({x['token'] for x in entries})!=len(entries):raise RuntimeError('ambiguous kernel reference set')
        return sorted(entries,key=lambda x:x['token'])
    finally:
        for child in children:stop(child)

def matches(entry,intent):
    return entry['pid']==intent['pid'] and entry['name']==intent['name'] and intent['after']<=entry['epoch']<=intent['before']

def select(data,intent,entries):
    validate(data)
    if intent not in data['intents'] or data['boot']!=boot():raise RuntimeError('unconfirmed developer recovery boot or intent')
    try:os.kill(intent['pid'],0)
    except ProcessLookupError:pass
    else:raise RuntimeError('owner still alive or PID reused; recovery refused')
    candidates=[entry for entry in entries if matches(entry,intent)]
    if len(candidates)>1:raise RuntimeError('ambiguous developer acquisition intent')
    by_token=[entry for entry in entries if entry['token']==intent['token']]
    if intent['token'] and by_token and not matches(by_token[0],intent):
        raise RuntimeError('recorded token now has different ownership; recovery refused')
    if candidates and intent['token'] and candidates[0]['token']!=intent['token']:
        raise RuntimeError('recorded reference identity differs; recovery refused')
    return candidates[0] if candidates else None

def recover(data,intent):
    before=references();entry=select(data,intent,before)
    if entry is None:return 'ALREADY_ABSENT'
    # Separate inspection/release operations are NOT an atomic kernel API.
    # This disposable test has no competing PF administrators. A second
    # exact snapshot detects ordinary changes, not an adversarial ABA race.
    if references()!=before:raise RuntimeError('kernel reference set changed; recovery refused')
    pf('-X',str(entry['token']))
    if references()!=[x for x in before if x!=entry]:raise RuntimeError('owned release or foreign preservation unconfirmed')
    return 'RELEASED'

def cleanup():
    if not STATE.exists():return {'status':'NO_OWNED_RECORD'}
    data=read()
    # Validate EVERY owner before any effect; preserve ambiguity intact.
    entries=references()
    for intent in data['intents']:select(data,intent,entries)
    for intent in data['intents']:recover(data,intent)
    (STATE/'state.json').unlink();STATE.rmdir()
    return {'status':'PASS','global_disable_used':False,'state_kill_used':False}

def acquisition(process,intent):
    if time.time()>intent['before']:raise RuntimeError('developer acquisition window elapsed')
    value=command(process,'acquire')
    if set(value)!={'acquired','token'} or value['acquired'] is not True or type(value['token']) is not int or not 0<value['token']<2**64:
        raise RuntimeError('developer acquisition unconfirmed')
    actual=references()
    if len([x for x in actual if matches(x,intent) and x['token']==value['token']])!=1:
        raise RuntimeError('native acquisition metadata differs from intent')
    return value['token']

def assert_foreign(entry):
    if references()!=[entry] or enabled()!=(True,0):raise RuntimeError('other reference or PF state changed')

def negative(data,intent,expected):
    before=references()
    try:recover(data,intent)
    except RuntimeError as error:
        if str(error)!=expected:raise RuntimeError('refusal failed for an unexpected reason')
    else:raise RuntimeError('unconfirmed recovery was accepted')
    if references()!=before:raise RuntimeError('refusal mutated kernel references')

def experiment(report,children):
    report['last_step']='read_only_preflight'
    before={name:pf(*args) for name,args in {'rules':('-s','rules'),'nat':('-s','nat'),
        'recursive_rules':('-a','*','-s','rules'),'recursive_nat':('-a','*','-s','nat')}.items()}
    settings={'timeouts':pf('-s','timeouts'),'limits':pf('-s','memory')}
    if enabled()!=(False,0) or references() or not all(only_default_calls(x) for x in before.values()):
        raise RuntimeError('fresh disabled empty-state default-only PF required')
    STATE.mkdir(mode=0o700);data={'version':1,'boot':boot(),'intents':[]};write(data)
    report['last_step']='hold_other_owned_reference'
    foreign,other=start(children);data['intents'].append(other);write(data)
    other['token']=acquisition(foreign,other);write(data)
    foreign_entry=references()[0]
    negative(data,other,'owner still alive or PID reused; recovery refused');report['live_owner_refused_without_mutation']=True
    report['last_step']='kill_after_acquire_before_token_commit'
    owner,pending=start(children);data['intents'].append(pending);write(data)
    secret=acquisition(owner,pending);stop(owner,kill=True)
    entries=references()
    if len(entries)!=2 or not any(x['token']==secret and matches(x,pending) for x in entries):
        raise RuntimeError('native reference did not survive owner death')
    report['kernel_reference_survives_sigkill']=True
    report['lost_token_not_recorded']=read()['intents'][1]['token']==0
    if not report['lost_token_not_recorded']:raise RuntimeError('lost-token checkpoint was not tested')
    # Controlled mismatched metadata exercises refusal; not actual kernel ABA.
    mismatch=json.loads(json.dumps(data));mismatch['intents'][1]['token']=other['token']
    negative(mismatch,mismatch['intents'][1],'recorded token now has different ownership; recovery refused');report['synthetic_foreign_token_mismatch_refused']=True
    wrong_boot=json.loads(json.dumps(data));wrong_boot['boot']='00000000-0000-0000-0000-000000000000'
    negative(wrong_boot,wrong_boot['intents'][1],'unconfirmed developer recovery boot or intent');report['synthetic_boot_mismatch_refused']=True
    if recover(read(),read()['intents'][1])!='RELEASED':raise RuntimeError('lost-token ownership recovery failed')
    assert_foreign(foreign_entry);report['lost_token_recovered_other_reference_preserved']=True
    # Deliberately keep stale intent after the effect; repeat must be idempotent.
    if recover(read(),read()['intents'][1])!='ALREADY_ABSENT':raise RuntimeError('stale pending intent was not idempotent')
    report['release_before_journal_update_idempotent']=True
    data['intents'].pop();write(data)
    report['last_step']='kill_before_acquire'
    owner,pending=start(children);data['intents'].append(pending);write(data);stop(owner,kill=True)
    if recover(read(),read()['intents'][1])!='ALREADY_ABSENT':raise RuntimeError('before-effect recovery differed')
    assert_foreign(foreign_entry);data['intents'].pop();write(data)
    report['before_effect_sigkill_preserves_other_reference']=True
    report['last_step']='release_before_recorded_token_update'
    owner,pending=start(children);data['intents'].append(pending);write(data)
    pending['token']=acquisition(owner,pending);write(data)
    if command(owner,'release')!={'released':True}:raise RuntimeError('native own release failed')
    stop(owner)
    if recover(read(),read()['intents'][1])!='ALREADY_ABSENT':raise RuntimeError('recorded token stale recovery differed')
    assert_foreign(foreign_entry);data['intents'].pop();write(data)
    report['recorded_token_release_before_commit_idempotent']=True
    report['last_step']='release_final_owned_reference'
    if command(foreign,'release')!={'released':True}:raise RuntimeError('final native own release failed')
    stop(foreign)
    if references() or enabled()!=(False,0):raise RuntimeError('initial PF status or references not restored')
    after={name:pf(*args) for name,args in {'rules':('-s','rules'),'nat':('-s','nat'),
        'recursive_rules':('-a','*','-s','rules'),'recursive_nat':('-a','*','-s','nat')}.items()}
    if after!=before or settings!={'timeouts':pf('-s','timeouts'),'limits':pf('-s','memory')}:
        raise RuntimeError('foreign rules or global settings changed')
    report.update({'root_recursive_filter_nat_unchanged':True,'global_timeouts_limits_unchanged':True,
        'initial_rule_hashes':{k:digest(v) for k,v in before.items()},'pf_disabled_restored':True,
        'final_reference_count':0,'final_state_count':0,'last_step':'completed'})

def main():
    if platform.system()!='Darwin' or platform.machine()!='x86_64' or os.geteuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_OS')!='macOS':
        raise SystemExit('Only the root disposable Intel GitHub macOS CI experiment is permitted')
    if sys.argv[1:]==['--cleanup']:
        try:print(json.dumps(cleanup()))
        except Exception:print('{"status":"REFUSED","reason":"unconfirmed own reference; no global fallback"}');sys.exit(1)
        return
    if sys.argv[1:]:raise SystemExit('No paths, tokens, rules or owner arguments accepted')
    report={'kind':'developer-only-PF-reference-recovery-experiment','source_commit':os.environ.get('GITHUB_SHA'),
        'host_os':platform.mac_ver()[0],'host_arch':platform.machine(),'production_ready':False,
        'private_pf_api':'UNSUPPORTED','high_sierra':'NOT_RUN','reboot_power_loss':'NOT_RUN',
        'atomic_compare_and_release':'NOT_AVAILABLE','actual_token_reuse':'NOT_RUN','foreign_quick_rules':'NOT_RUN'}
    children=[]
    try:experiment(report,children);report['status']='PASS'
    except Exception as error:
        report['status']='FAIL';report['reason']=str(error) if type(error) is RuntimeError else 'developer reference experiment failed'
    finally:
        for child in children:
            try:stop(child,kill=True)
            except Exception:report['status']='FAIL'
        try:report['owned_cleanup']=cleanup()
        except Exception:report['owned_cleanup']={'status':'REFUSED','reason':'unconfirmed own reference; no global fallback'};report['status']='FAIL'
    output=ROOT/'Build/CI';output.mkdir(parents=True,exist_ok=True)
    (output/'pf-reference-ci.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    if report['status']!='PASS':sys.exit(1)

if __name__=='__main__':main()
