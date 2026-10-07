"""Exercise real kernel-trailer IPC authentication on the authorized CI host."""
from __future__ import annotations
import json
import os
from pathlib import Path
import plistlib
import re
import subprocess

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


def main() -> None:
    if os.uname().sysname != 'Darwin' or os.uname().machine != 'x86_64':
        raise SystemExit('Requires the authorized Intel macOS CI host')
    if HELPER.exists() or POLICY_DIR.exists() or PLIST.exists():
        raise SystemExit('Existing LegacyWG installation found; refusing to replace user files')
    TEST.mkdir(parents=True, exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)
    common = ['/usr/bin/xcrun', 'clang', '-arch', 'x86_64', '-mmacosx-version-min=10.13',
              '-fobjc-arc', '-Wall', '-Wextra', '-Werror', '-Wunguarded-availability',
              '-Wno-deprecated-declarations', '-framework', 'Foundation', '-framework', 'Security', '-lbsm',
              str(ROOT / 'Shared' / 'LWMach.m')]
    helper = TEST / 'helper'
    allowed = TEST / 'allowed-client'
    rejected = TEST / 'rejected-client'
    run(common + [str(ROOT / 'Helper' / 'main.m'), '-o', str(helper)])
    run(common + [str(ROOT / 'Tests' / 'MachClient.m'), '-o', str(allowed)])
    run(common + ['-DLW_UNTRUSTED_TEST=1', str(ROOT / 'Tests' / 'MachClient.m'), '-o', str(rejected)])
    for binary, identifier in ((helper, SERVICE), (allowed, 'org.legacywg.testclient'),
                               (rejected, 'org.legacywg.testclient')):
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
    results = {}
    try:
        run(['/usr/bin/sudo', '-n', '/usr/bin/install', '-d', '-o', 'root', '-g', 'wheel', '-m', '0755', str(POLICY_DIR)])
        installed = True
        run(['/usr/bin/sudo', '-n', '/usr/bin/install', '-o', 'root', '-g', 'wheel', '-m', '0755', str(helper), str(HELPER)])
        run(['/usr/bin/sudo', '-n', '/usr/bin/install', '-o', 'root', '-g', 'wheel', '-m', '0644', str(policy), str(POLICY_DIR / policy.name)])
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
        results['audit_identity'] = 'kernel Mach trailer + SecCode audit guest'
        results['status'] = 'PASS'
    finally:
        if installed:
            subprocess.run(['/usr/bin/sudo', '-n', '/bin/launchctl', 'bootout', 'system/' + SERVICE], capture_output=True)
            # Exact files created by this test only; no recursive deletion.
            for path in (HELPER, PLIST, POLICY_DIR / 'AllowedClient.req'):
                subprocess.run(['/usr/bin/sudo', '-n', '/bin/rm', '-f', str(path)], check=True)
            run(['/usr/bin/sudo', '-n', '/bin/rmdir', str(POLICY_DIR)])
        (OUT / 'mach-auth-ci.json').write_text(json.dumps(results, indent=2)+'\n')
    print(json.dumps(results, indent=2))


if __name__ == '__main__': main()
