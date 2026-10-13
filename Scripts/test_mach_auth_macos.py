"""Exercise real kernel-trailer IPC authentication on the authorized CI host."""
from __future__ import annotations
import json
import os
from pathlib import Path
import plistlib
import re
import subprocess
import base64
import time

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'Build' / 'CI'
TEST = ROOT / 'Build' / 'MachAuth'
SERVICE = 'org.legacywg.helper'
HELPER = Path('/Library/PrivilegedHelperTools') / SERVICE
POLICY_DIR = Path('/Library/Application Support/LegacyWG')
PLIST = Path('/Library/LaunchDaemons') / (SERVICE + '.plist')


def run(args: list[str], timeout: int = 45) -> str:
    result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        print(result.stdout, result.stderr)
        raise RuntimeError('Native authentication test command failed: ' + args[0])
    return result.stdout + result.stderr


def cdhash(path: Path) -> str:
    output = run(['/usr/bin/codesign', '-d', '--verbose=4', str(path)])
    match = re.search(r'^CDHash=([0-9a-f]{40})$', output, re.M)
    if not match: raise RuntimeError('Code directory hash missing')
    return match[1]


def cleanup_recovery_directory() -> None:
    # Called only after a fresh disposable installation created by this test.
    # Never clear an ambiguous journal; an unfinished transaction must fail QA.
    state=POLICY_DIR/'State'
    if not state.exists():return
    deadline=time.monotonic()+5
    while time.monotonic()<deadline:
        result=subprocess.run(['/usr/bin/sudo','-n','/usr/bin/pgrep','-f',
            '^/Library/Application Support/LegacyWG/legacywg-worker$'],capture_output=True)
        if result.returncode==1:break
        if result.returncode!=0:raise RuntimeError('Cannot verify owned worker exit')
        time.sleep(.05)
    else:raise RuntimeError('Owned worker did not exit before journal cleanup')
    info=state.lstat()
    if state.is_symlink() or info.st_uid!=0 or info.st_mode&0o777!=0o700:
        raise RuntimeError('Recovery test directory ownership mismatch')
    run(['/usr/bin/sudo','-n','/bin/rm','-f',str(state/'lock')])
    run(['/usr/bin/sudo','-n','/bin/rmdir',str(state)])


def test_public_journal_recovery(client: Path, requirement: str) -> dict:
    # The enclosing test owns this fresh disposable installation. None of
    # these fixtures are installed on the user's Mac or shipped in the app.
    state=POLICY_DIR/'State'
    if state.exists():raise RuntimeError('Recovery fixture directory already exists')
    interfaces=run(['/sbin/ifconfig','-l'])
    def request(op: str, profile: str | None=None, ok: bool=True) -> dict:
        result=subprocess.run([str(client),requirement,op],input=profile,
            capture_output=True,text=True,timeout=25)
        reply=json.loads(result.stdout)
        assert reply['ok'] is ok and result.returncode==(0 if ok else 1)
        return reply
    def restart() -> None:
        run(['/usr/bin/sudo','-n','/bin/launchctl','bootout','system/'+SERVICE])
        # Avoid racing the old verified idle worker after helper pipe EOF.
        deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            old=subprocess.run(['/usr/bin/sudo','-n','/usr/bin/pgrep','-f',
                '^/Library/Application Support/LegacyWG/legacywg-worker$'],capture_output=True)
            if old.returncode==1:break
            if old.returncode!=0:raise RuntimeError('Worker absence check failed')
            time.sleep(0.05)
        else:raise RuntimeError('Previous fixture worker remains live')
        run(['/usr/bin/sudo','-n','/bin/launchctl','bootstrap','system',str(PLIST)])
    clean=request('status')
    assert clean['status']['state']=='Disconnected' and not state.exists()
    # Stop the idle worker before inserting the owned startup crash fixture.
    restart()
    run(['/usr/bin/sudo','-n','/usr/bin/install','-d','-o','root','-g','wheel','-m','0700',str(state)])
    marker=b'owned-corrupt-journal-fixture\n'
    fixture=TEST/'owned-journal-fixture'
    fixture.write_bytes(marker)
    fixture.chmod(0o600)
    run(['/usr/bin/sudo','-n','/usr/bin/install','-o','root','-g','wheel','-m','0600',
         str(fixture),str(state/'utun.json')])
    startup=request('status')
    assert startup['status']['state']=='RecoveryRequired' and startup['status']['tunnel_started'] is False
    profile='[Interface]\nPrivateKey='+base64.b64encode(os.urandom(32)).decode()+\
        '\nAddress=198.18.0.1/32\n[Peer]\nPublicKey='+base64.b64encode(os.urandom(32)).decode()+\
        '\nEndpoint=blocked-journal.test:51820\nAllowedIPs=198.18.0.2/32\n'
    for op in ('start','recover','stop'):
        denied=request(op,profile if op=='start' else None,False)
        assert denied['error']=='owned network recovery requires attention'
        assert denied['status']['state']=='RecoveryRequired'
        assert 'owned-corrupt-journal-fixture' not in json.dumps(denied)
        assert run(['/usr/bin/sudo','-n','/bin/cat',str(state/'utun.json')]).encode()==marker
    # Remove only the exact corrupt fixture created by this developer test.
    # Production recovery refused to remove it; there is no public force flag.
    run(['/usr/bin/sudo','-n','/bin/rm','-f',str(state/'utun.json')])
    for _ in range(2):assert request('recover')['status']['state']=='Disconnected'
    assert run(['/usr/bin/sudo','-n','/bin/ls','-A',str(state)]).strip()=='lock'
    restart()
    boot=run(['/usr/sbin/sysctl','-n','kern.bootsessionuuid']).strip().lower()
    record={'version':1,'id':os.urandom(16).hex(),'boot':boot,'pid':2147483647,'phase':'intent',
        'interface':'','interface_index':0,'dns_requested':False}
    fixture.write_text(json.dumps(record,separators=(',',':'))+'\n')
    run(['/usr/bin/sudo','-n','/usr/bin/install','-o','root','-g','wheel','-m','0600',
         str(fixture),str(state/'utun.json')])
    assert request('status')['status']['state']=='Disconnected'
    assert run(['/usr/bin/sudo','-n','/bin/ls','-A',str(state)]).strip()=='lock'
    assert run(['/sbin/ifconfig','-l'])==interfaces
    assert request('stop')['status']['state']=='Disconnected'
    fixture.unlink()
    return {'startup_corrupt_journal':'PASS','blocked_start_recover_stop':'PASS',
        'ambiguous_record_preserved':'PASS','explicit_recovery_idempotent':'PASS',
        'startup_stale_journal_cleanup':'PASS','no_connection_intent_or_interface_created':'PASS',
        'high_sierra':'NOT_RUN'}


def main() -> None:
    if os.uname().sysname != 'Darwin' or os.uname().machine != 'x86_64':
        raise SystemExit('Requires the authorized Intel macOS CI host')
    if HELPER.exists() or POLICY_DIR.exists() or PLIST.exists():
        raise SystemExit('Existing LegacyWG installation found; refusing to replace user files')
    TEST.mkdir(parents=True, exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)
    common = ['/usr/bin/xcrun', 'clang', '-arch', 'x86_64', '-mmacosx-version-min=10.13',
              '-fobjc-arc', '-Wall', '-Wextra', '-Werror', '-Wunguarded-availability',
              '-Wno-deprecated-declarations', '-framework', 'Foundation', '-framework', 'Security',
              '-framework', 'SystemConfiguration', '-lbsm',
              str(ROOT / 'Shared' / 'LWMach.m')]
    helper = TEST / 'helper'
    allowed = TEST / 'allowed-client'
    rejected = TEST / 'rejected-client'
    client_build=ROOT/'Build/Client'
    if (client_build/'org.legacywg.helper').exists():
        import shutil
        shutil.copyfile(client_build/'org.legacywg.helper',helper);helper.chmod(0o755)
    else:
        run(common + [str(ROOT / 'Helper' / 'main.m'), '-o', str(helper)])
    run(common + [str(ROOT / 'Tests' / 'MachClient.m'), '-o', str(allowed)])
    run(common + ['-DLW_UNTRUSTED_TEST=1', str(ROOT / 'Tests' / 'MachClient.m'), '-o', str(rejected)])
    for binary, identifier in ((helper, SERVICE), (allowed, 'org.legacywg.testclient'),
                               (rejected, 'org.legacywg.testclient')):
        if binary!=helper or not (client_build/'org.legacywg.helper').exists():
            run(['/usr/bin/codesign', '--force', '--sign', '-', '--timestamp=none', '--identifier', identifier, str(binary)])
        run(['/usr/bin/codesign', '--verify', '--strict', str(binary)])
    # A different binary with the same bundle ID must not be accepted.
    assert cdhash(allowed) != cdhash(rejected)
    policy = TEST / 'AllowedClient.req'
    policy.write_text('identifier "org.legacywg.testclient" and cdhash H"' + cdhash(allowed) + '"\n')
    helper_requirement = 'identifier "' + SERVICE + '" and cdhash H"' + cdhash(helper) + '"'
    plist = TEST / 'helper.plist'
    plist.write_bytes(plistlib.dumps({'Label': SERVICE, 'ProgramArguments': [str(HELPER)],
        'MachServices': {SERVICE: True}, 'RunAtLoad': True, 'ProcessType': 'Interactive'}))
    installed = False
    created_helper_directory = not HELPER.parent.exists()
    results = {}
    try:
        if created_helper_directory:
            run(['/usr/bin/sudo', '-n', '/usr/bin/install', '-d', '-o', 'root', '-g', 'wheel', '-m', '0755', str(HELPER.parent)])
        run(['/usr/bin/sudo', '-n', '/usr/bin/install', '-d', '-o', 'root', '-g', 'wheel', '-m', '0755', str(POLICY_DIR)])
        installed = True
        run(['/usr/bin/sudo', '-n', '/usr/bin/install', '-o', 'root', '-g', 'wheel', '-m', '0755', str(helper), str(HELPER)])
        run(['/usr/bin/sudo', '-n', '/usr/bin/install', '-o', 'root', '-g', 'wheel', '-m', '0644', str(policy), str(POLICY_DIR / policy.name)])
        if (client_build/'legacywg-worker').exists():
            worker=client_build/'legacywg-worker'
            worker_policy=TEST/'Worker.req'
            worker_policy.write_text('identifier "org.legacywg.worker" and cdhash H"'+cdhash(worker)+'"\n')
            run(['/usr/bin/sudo','-n','/usr/bin/install','-o','root','-g','wheel','-m','0755',str(worker),str(POLICY_DIR/worker.name)])
            run(['/usr/bin/sudo','-n','/usr/bin/install','-o','root','-g','wheel','-m','0644',str(worker_policy),str(POLICY_DIR/worker_policy.name)])
            network=client_build/'legacywg-network'
            network_policy=TEST/'Network.req'
            network_policy.write_text('identifier "org.legacywg.network" and cdhash H"'+cdhash(network)+'"\n')
            run(['/usr/bin/sudo','-n','/usr/bin/install','-o','root','-g','wheel','-m','0755',str(network),str(POLICY_DIR/network.name)])
            run(['/usr/bin/sudo','-n','/usr/bin/install','-o','root','-g','wheel','-m','0644',str(network_policy),str(POLICY_DIR/network_policy.name)])
        run(['/usr/bin/sudo', '-n', '/usr/bin/install', '-o', 'root', '-g', 'wheel', '-m', '0644', str(plist), str(PLIST)])
        run(['/usr/bin/sudo', '-n', '/bin/launchctl', 'bootstrap', 'system', str(PLIST)])
        response = json.loads(run([str(allowed), helper_requirement]))
        assert response['ok'] is True and response['authenticated_uid'] == os.getuid()
        results['allowed_client'] = 'PASS'
        attack = subprocess.run([str(rejected), helper_requirement], capture_output=True, text=True, timeout=20)
        denial = json.loads(attack.stdout)
        assert attack.returncode == 1 and denial['ok'] is False and denial['error'] == 'Unauthorized client'
        results['same_identifier_different_binary'] = 'PASS'
        spoofed = subprocess.run([str(allowed), 'identifier "org.legacywg.wrong-server"'], capture_output=True, text=True, timeout=20)
        assert spoofed.returncode == 1 and json.loads(spoofed.stdout)['ok'] is False
        results['wrong_server_requirement'] = 'PASS'
        rejected_recovery=subprocess.run([str(rejected),helper_requirement,'recover'],capture_output=True,text=True,timeout=20)
        assert rejected_recovery.returncode==1 and json.loads(rejected_recovery.stdout)['error']=='Unauthorized client'
        results['unauthorized_recovery_refused']='PASS'
        if (client_build/'legacywg-network').exists():
            # Same component identifier is insufficient: the helper must
            # reject a substituted root component before launching a worker.
            import shutil
            substitute=TEST/'rejected-network'
            shutil.copyfile(client_build/'dns-probe',substitute);substitute.chmod(0o755)
            run(['/usr/bin/codesign','--force','--sign','-','--timestamp=none','--identifier',
                 'org.legacywg.network',str(substitute)])
            assert cdhash(substitute)!=cdhash(client_build/'legacywg-network')
            profile='[Interface]\nPrivateKey='+base64.b64encode(os.urandom(32)).decode()+\
                '\nAddress=198.18.0.1/32\n[Peer]\nPublicKey='+base64.b64encode(os.urandom(32)).decode()+\
                '\nEndpoint=127.0.0.1:51820\nAllowedIPs=198.18.0.2/32\n'
            try:
                run(['/usr/bin/sudo','-n','/usr/bin/install','-o','root','-g','wheel','-m','0755',
                     str(substitute),str(POLICY_DIR/'legacywg-network')])
                attack=subprocess.run([str(allowed),helper_requirement,'start'],input=profile,
                    capture_output=True,text=True,timeout=20)
                refusal=json.loads(attack.stdout)
                assert attack.returncode==1 and refusal['ok'] is False and refusal['error']=='Installed engine integrity check failed'
                results['substituted_network_component']='PASS'
            finally:
                run(['/usr/bin/sudo','-n','/usr/bin/install','-o','root','-g','wheel','-m','0755',
                     str(client_build/'legacywg-network'),str(POLICY_DIR/'legacywg-network')])
        if (client_build/'peercheck').exists():
            recovery=test_public_journal_recovery(allowed,helper_requirement)
            (OUT/'public-recovery-ci.json').write_text(json.dumps({'status':'PASS',**recovery},indent=2)+'\n')
            results['public_startup_and_explicit_journal_recovery']='PASS'
            peer_result=run([str(client_build/'peercheck'),str(allowed),helper_requirement,str(client_build/'dns-probe')],timeout=180)
            report=json.loads(peer_result)
            assert report['status']=='PASS'
            (OUT/'native-peer-ci.json').write_text(json.dumps(report,indent=2)+'\n')
            results['native_authenticated_encrypted_peer']='PASS'
        results['audit_identity'] = 'kernel Mach trailer + SecCode audit guest'
        results['status'] = 'PASS'
    finally:
        if installed:
            subprocess.run(['/usr/bin/sudo', '-n', '/bin/launchctl', 'bootout', 'system/' + SERVICE], capture_output=True)
            cleanup_recovery_directory()
            # Exact files created by this test only; no recursive deletion.
            for path in (HELPER, PLIST, POLICY_DIR / 'AllowedClient.req', POLICY_DIR/'legacywg-worker', POLICY_DIR/'Worker.req',
                         POLICY_DIR/'legacywg-network',POLICY_DIR/'Network.req'):
                subprocess.run(['/usr/bin/sudo', '-n', '/bin/rm', '-f', str(path)], check=True)
            run(['/usr/bin/sudo', '-n', '/bin/rmdir', str(POLICY_DIR)])
        if created_helper_directory:
            run(['/usr/bin/sudo', '-n', '/bin/rmdir', str(HELPER.parent)])
        (OUT / 'mach-auth-ci.json').write_text(json.dumps(results, indent=2)+'\n')
    print(json.dumps(results, indent=2))


if __name__ == '__main__': main()
