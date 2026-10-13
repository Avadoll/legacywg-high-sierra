"""Actual private reference + durable anchor lifecycle in disposable Intel CI.

No client protection claim. The short compiled test filename intentionally
matches the fixed production reference owner name; it is never packaged.
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
    build = ROOT/'Build/PFReference'
    build.mkdir(parents=True, exist_ok=True)
    acl, other, test = build/'acl-probe', build/'legacywg-ref', build/'legacywg-worker'
    clang = ['/usr/bin/xcrun','clang','-std=c11','-arch','x86_64','-mmacosx-version-min=10.13','-Wall','-Wextra','-Werror']
    subprocess.run([*clang,str(ROOT/'Tests/ACLProbe.c'),'-o',str(acl)],check=True,timeout=30)
    subprocess.run([*clang,str(ROOT/'Tests/PFReferenceProbe.c'),'-o',str(other)],check=True,timeout=30)
    go = ROOT/'.tools/go1.24.13/go/bin/go'
    env = {**os.environ,'GOCACHE':str(ROOT/'.cache/macos-build'),'GOMODCACHE':str(ROOT/'.cache/gomod')}
    subprocess.run([str(go),'test','-c','-o',str(test),'./RecoveryCore'],env=env,check=True,timeout=180)
    result = subprocess.run([str(go),'tool','test2json','-p','legacywg/RecoveryCore','-t',
        '/usr/bin/sudo','-n','/usr/bin/env','GITHUB_ACTIONS=true','LEGACYWG_PF_REFERENCE_TESTS=1',
        'LEGACYWG_ACL_TEST_HELPER='+str(acl),'LEGACYWG_PF_FOREIGN_TEST_HELPER='+str(other),
        str(test),'-test.run=^TestRootPFReference','-test.v=test2json','-test.timeout=180s'],
        capture_output=True,text=True,env=env,timeout=210)
    events = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    sanitized = [{key:event[key] for key in ('Action','Test','Elapsed') if key in event} for event in events]
    (output/'pf-lifecycle-tests.json').write_text(json.dumps(sanitized,indent=2)+'\n')
    passed = {event.get('Test') for event in events if event.get('Action')=='pass'}
    stages = ('pf_reference_intent_committed','pf_reference_acquired_kernel','pf_reference_confirmation_committed',
        'pf_active_committed','pf_reference_cleanup_intent_committed','pf_reference_released_kernel',
        'pf_reference_release_confirmation_committed','pf_anchor_emptied')
    required = {'TestRootPFReferenceActivationAndSerializedStop','TestRootPFReferenceCancellationBeforeAcquire',
        'TestRootPFReferenceEffectCrashRecovery','TestRootPFReferenceOtherOwnerPreserved'} | {
        'TestRootPFReferenceEffectCrashRecovery/'+stage for stage in stages}
    status = 'PASS' if result.returncode==0 and required<=passed else 'FAIL'
    def checked(test_name):
        return 'PASS' if test_name in passed else 'NOT_CONFIRMED'
    report = {'status':status,'source_commit':os.environ['GITHUB_SHA'],'host_os':platform.mac_ver()[0],
        'kind':'native journal-bound private-PF reference and owned-anchor lifecycle',
        'required_tests':sorted(required),'record_version':2,
        'actual_sigkill_checkpoints':sum('TestRootPFReferenceEffectCrashRecovery/'+stage in passed for stage in stages),
        'actual_same_process_acquire_verify_release':checked('TestRootPFReferenceActivationAndSerializedStop'),
        'two_concurrent_activation_requests_only_one_reference':checked('TestRootPFReferenceActivationAndSerializedStop'),
        'cancellation_before_acquire_records_actual_absence':checked('TestRootPFReferenceCancellationBeforeAcquire'),
        'dead_owner_lost_token_and_release_confirmation_recovery':checked('TestRootPFReferenceEffectCrashRecovery'),
        'other_actual_owner_reference_and_enabled_pf_preserved':checked('TestRootPFReferenceOtherOwnerPreserved'),
        'foreign_token_mismatch_selection_refused':checked('TestRootPFReferenceOtherOwnerPreserved'),
        'own_anchor_reference_and_displayed_baselines_restored':'PASS' if status=='PASS' else 'NOT_CONFIRMED',
        'private_kernel_abi':'UNSUPPORTED','atomic_compare_release':'NOT_AVAILABLE',
        'adversarial_privileged_concurrency':'NOT_PROVEN','actual_kernel_token_reuse':'NOT_RUN',
        'packet_leak_captures':'NOT_RUN','power_loss':'NOT_RUN','reboot':'NOT_RUN','high_sierra':'NOT_RUN',
        'client_request_integration':False,'protection_ready':False}
    (output/'pf-lifecycle-ci.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    if status!='PASS':
        for event in events:
            if event.get('Action')=='output' and ('.go:' in event.get('Output','') or 'FAIL' in event.get('Output','')):
                print(event['Output'].strip())
        raise SystemExit('Journal-bound PF reference lifecycle tests failed')

if __name__=='__main__':
    main()
