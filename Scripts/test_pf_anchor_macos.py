"""Run actual journal-bound PF anchor staging/cancellation in disposable CI.

PF must remain disabled. No references, packet-protection or full tunnel claim.
Only Go test code accepts the private TempDir/crash-checkpoint environment.
"""
import json
import os
from pathlib import Path
import platform
import subprocess

ROOT = Path(__file__).resolve().parents[1]

def main():
    if platform.system() != 'Darwin' or platform.machine() != 'x86_64' or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise SystemExit('Disposable native Intel CI only')
    output = ROOT/'Build/CI'
    output.mkdir(parents=True, exist_ok=True)
    build = ROOT/'Build/PFAnchor'
    build.mkdir(parents=True, exist_ok=True)
    acl = build/'acl-probe'
    subprocess.run(['/usr/bin/xcrun', 'clang', '-arch', 'x86_64', '-mmacosx-version-min=10.13',
        '-Wall', '-Wextra', '-Werror', str(ROOT/'Tests/ACLProbe.c'), '-o', str(acl)], check=True, timeout=30)
    go = ROOT/'.tools/go1.24.13/go/bin/go'
    env = {**os.environ, 'GOCACHE':str(ROOT/'.cache/macos-build'), 'GOMODCACHE':str(ROOT/'.cache/gomod')}
    result = subprocess.run([str(go), 'test', '-json', '-count=1', '-timeout=240s', '-run',
        '^TestRootPFAnchor', '-exec', '/usr/bin/sudo -n /usr/bin/env GITHUB_ACTIONS=true LEGACYWG_PF_ANCHOR_TESTS=1 LEGACYWG_ACL_TEST_HELPER='+str(acl),
        './RecoveryCore'], capture_output=True, text=True, env=env, timeout=270)
    events = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    # No paths, foreign rules, anchor identities, tokens or raw subprocess data.
    sanitized = [{key:event[key] for key in ('Action','Test','Elapsed') if key in event} for event in events]
    (output/'pf-anchor-tests.json').write_text(json.dumps(sanitized, indent=2)+'\n')
    passed = {event.get('Test') for event in events if event.get('Action') == 'pass'}
    stages = ('pf_install_intent_committed', 'pf_anchor_loaded', 'pf_removal_intent_committed', 'pf_anchor_emptied')
    required = {'TestRootPFAnchorStageAndCancel', 'TestRootPFAnchorEffectCrashRecovery'} | {
        'TestRootPFAnchorEffectCrashRecovery/'+stage for stage in stages}
    status = 'PASS' if result.returncode == 0 and required <= passed else 'FAIL'
    report = {'status':status, 'source_commit':os.environ['GITHUB_SHA'], 'host_os':platform.mac_ver()[0],
        'kind':'native journal-bound disabled-PF owned-anchor effects', 'required_tests':sorted(required),
        'actual_sigkill_checkpoints':4 if status == 'PASS' else 'INCOMPLETE',
        'own_anchor_load_verify_cancel':status, 'same_boot_dead_owner_pre_reference_recovery':status,
        'foreign_filter_and_nat_baseline_preserved':status, 'pf_remains_disabled':status,
        'reference_operations':'NOT_RUN', 'packet_protection':'NOT_RUN', 'power_loss':'NOT_RUN',
        'high_sierra':'NOT_RUN', 'protection_ready':False,
        'concurrent_privileged_writer_atomicity':'NOT_PROVEN', 'client_request_integration':False}
    (output/'pf-anchor-ci.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))
    if status != 'PASS':
        # Test failures carry fixed explanations, not native foreign policy.
        for event in events:
            if event.get('Action') == 'output' and ('.go:' in event.get('Output','') or 'FAIL' in event.get('Output','')):
                print(event['Output'].strip())
        raise SystemExit('Owned PF anchor effect tests failed')

if __name__ == '__main__':
    main()
