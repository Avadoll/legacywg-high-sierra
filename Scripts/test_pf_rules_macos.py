"""Actual typed own-rule generations and SIGKILL resolution in native CI."""
import json
import os
from pathlib import Path
import platform
import subprocess

ROOT = Path(__file__).resolve().parents[1]

def main():
    if platform.system()!='Darwin' or platform.machine()!='x86_64' or os.environ.get('GITHUB_ACTIONS')!='true':
        raise SystemExit('Disposable native Intel CI only')
    output=ROOT/'Build/CI';output.mkdir(parents=True,exist_ok=True)
    build=ROOT/'Build/PFRules';build.mkdir(parents=True,exist_ok=True)
    acl,test=build/'acl-probe',build/'legacywg-worker'
    subprocess.run(['/usr/bin/xcrun','clang','-std=c11','-arch','x86_64','-mmacosx-version-min=10.13',
        '-Wall','-Wextra','-Werror',str(ROOT/'Tests/ACLProbe.c'),'-o',str(acl)],check=True,timeout=30)
    go=ROOT/'.tools/go1.24.13/go/bin/go'
    env={**os.environ,'GOCACHE':str(ROOT/'.cache/macos-build'),'GOMODCACHE':str(ROOT/'.cache/gomod')}
    subprocess.run([str(go),'test','-c','-o',str(test),'./RecoveryCore'],env=env,check=True,timeout=180)
    result=subprocess.run([str(go),'tool','test2json','-p','legacywg/RecoveryCore','-t',
        '/usr/bin/sudo','-n','/usr/bin/env','GITHUB_ACTIONS=true','LEGACYWG_PF_REFERENCE_TESTS=1',
        'LEGACYWG_PF_RULE_TESTS=1','LEGACYWG_ACL_TEST_HELPER='+str(acl),str(test),
        '-test.run=^TestRootPFRule','-test.v=test2json','-test.timeout=180s'],
        capture_output=True,text=True,env=env,timeout=210)
    events=[json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    sanitized=[{key:event[key] for key in ('Action','Test','Elapsed') if key in event} for event in events]
    (output/'pf-rules-tests.json').write_text(json.dumps(sanitized,indent=2)+'\n')
    passed={event.get('Test') for event in events if event.get('Action')=='pass'}
    stages=('pf_rule_update_intent_committed','pf_rule_update_loaded_kernel','pf_rule_update_confirmation_committed')
    required={'TestRootPFRuleCanonicalGenerationsAndRefusals','TestRootPFRuleOwnedTunnelPolicy',
        'TestRootPFRuleEffectCrashResolution'}|{'TestRootPFRuleEffectCrashResolution/'+stage for stage in stages}
    status='PASS' if result.returncode==0 and required<=passed else 'FAIL'
    def checked(name):return 'PASS' if name in passed else 'NOT_CONFIRMED'
    report={'status':status,'source_commit':os.environ['GITHUB_SHA'],'host_os':platform.mac_ver()[0],
        'kind':'native journal-bound typed own-PF rule generations','record_version':2,'required_tests':sorted(required),
        'actual_sigkill_checkpoints':sum('TestRootPFRuleEffectCrashResolution/'+stage in passed for stage in stages),
        'dual_family_numeric_udp_loopback_deny_generations':checked('TestRootPFRuleCanonicalGenerationsAndRefusals'),
        'wrong_index_unassigned_source_unowned_tunnel_refusals':checked('TestRootPFRuleCanonicalGenerationsAndRefusals'),
        'identical_policy_does_not_increment_generation':checked('TestRootPFRuleCanonicalGenerationsAndRefusals'),
        'native_journal_owned_tunnel_policy':checked('TestRootPFRuleOwnedTunnelPolicy'),
        'actual_old_hash_rollback_new_hash_confirmation_after_crash':checked('TestRootPFRuleEffectCrashResolution'),
        'kernel_rules_reference_and_displayed_baselines_restored':'PASS' if status=='PASS' else 'NOT_CONFIRMED',
        'packet_leak_captures':'NOT_RUN','physical_scoped_endpoint_path':'NOT_RUN','interface_generation_reuse':'NOT_RUN',
        'foreign_kernel_anchor_enumeration':'NOT_PROVEN','privileged_writer_atomicity':'NOT_PROVEN',
        'power_loss':'NOT_RUN','reboot':'NOT_RUN','high_sierra':'NOT_RUN','client_request_integration':False,'protection_ready':False}
    (output/'pf-rules-ci.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    if status!='PASS':
        for event in events:
            if event.get('Action')=='output' and ('.go:' in event.get('Output','') or 'FAIL' in event.get('Output','')):
                print(event['Output'].strip())
        raise SystemExit('Journal-bound native PF rule generation tests failed')

if __name__=='__main__':main()
