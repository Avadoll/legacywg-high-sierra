"""Actual typed own-rule generations and SIGKILL resolution in native CI."""
import json
import os
from pathlib import Path
import platform
import subprocess
from build_pf_single_rule_probe import build_probe

ROOT = Path(__file__).resolve().parents[1]

def main():
    if platform.system()!='Darwin' or platform.machine()!='x86_64' or os.environ.get('GITHUB_ACTIONS')!='true':
        raise SystemExit('Disposable native Intel CI only')
    output=ROOT/'Build/CI';output.mkdir(parents=True,exist_ok=True)
    build=ROOT/'Build/PFRules';build.mkdir(parents=True,exist_ok=True)
    scope=os.environ.get('LEGACYWG_PF_RULE_SCOPE','full')
    if scope not in ('full','single-class','coordinator'):raise SystemExit('Unknown native PF scope')
    pattern='^TestRootPFRule'
    if scope=='single-class':pattern='^TestRootPFRuleSingleClass(RealPolicy|CodecPrimaryABI)$'
    if scope=='coordinator':pattern='^TestRootPFRule(CanonicalGenerationsAndRefusals|OwnedTunnelPolicy|CanceledAndThirdHashRemainBoundToIntent|EffectCrashResolution|EffectCrashChild|LoaderCrashRecovery|LoaderCrashChild|SingleClassCodecPrimaryABI)$'
    singleton,abi=build_probe(build)
    acl,test=build/'acl-probe',build/'legacywg-worker'
    subprocess.run(['/usr/bin/xcrun','clang','-std=c11','-arch','x86_64','-mmacosx-version-min=10.13',
        '-Wall','-Wextra','-Werror',str(ROOT/'Tests/ACLProbe.c'),'-o',str(acl)],check=True,timeout=30)
    transaction=build/'pf-transaction-probe'
    subprocess.run(['/usr/bin/xcrun','clang','-std=c11','-arch','x86_64','-mmacosx-version-min=10.13',
        '-Wall','-Wextra','-Werror',str(ROOT/'Tests/PFTransactionProbe.c'),'-o',str(transaction)],check=True,timeout=30)
    go=ROOT/'.tools/go1.24.13/go/bin/go'
    env={**os.environ,'GOCACHE':str(ROOT/'.cache/macos-build'),'GOMODCACHE':str(ROOT/'.cache/gomod')}
    subprocess.run([str(go),'test','-c','-o',str(test),'./RecoveryCore'],env=env,check=True,timeout=180)
    result=subprocess.run([str(go),'tool','test2json','-p','legacywg/RecoveryCore','-t',
        '/usr/bin/sudo','-n','/usr/bin/env','GITHUB_ACTIONS=true','LEGACYWG_PF_REFERENCE_TESTS=1',
        'LEGACYWG_PF_RULE_TESTS=1','LEGACYWG_ACL_TEST_HELPER='+str(acl),
        'LEGACYWG_PF_TRANSACTION_HELPER='+str(transaction),
        'LEGACYWG_PF_SINGLE_RULE_HELPER='+str(singleton),str(test),
        '-test.run='+pattern,
        '-test.v=test2json','-test.timeout=300s'],
        capture_output=True,text=True,env=env,timeout=330)
    events=[json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    sanitized=[{key:event[key] for key in ('Action','Test','Elapsed') if key in event} for event in events]
    (output/'pf-rules-tests.json').write_text(json.dumps(sanitized,indent=2)+'\n')
    passed={event.get('Test') for event in events if event.get('Action')=='pass'}
    stages=('pf_rule_update_intent_committed','pf_rule_update_loaded_kernel','pf_rule_update_confirmation_committed',
            'pf_filter_transaction_begin_kernel','pf_filter_rules_staged_kernel','pf_filter_transaction_committed_kernel')
    loader_points=('pf_filter_transaction_begin_kernel','pf_filter_rules_staged_kernel','pf_filter_transaction_committed_kernel')
    loader_cases={'TestRootPFRuleLoaderCrashRecovery/'+role+'/'+point for role in ('stage','remove') for point in loader_points}
    required={'TestRootPFRuleCanonicalGenerationsAndRefusals','TestRootPFRuleOwnedTunnelPolicy',
        'TestRootPFRuleCanceledAndThirdHashRemainBoundToIntent',
        'TestRootPFRuleEnumerationForeignFilterAndNATRefused',
        'TestRootPFRuleEmptyTransactionNamespace',
        'TestRootPFRuleEffectCrashResolution'}|{'TestRootPFRuleEffectCrashResolution/'+stage for stage in stages}
    required|={'TestRootPFRuleLoaderCrashRecovery'}|loader_cases
    if scope=='single-class':required={'TestRootPFRuleSingleClassRealPolicy','TestRootPFRuleSingleClassCodecPrimaryABI'}
    if scope=='coordinator':
        required-={'TestRootPFRuleEnumerationForeignFilterAndNATRefused','TestRootPFRuleEmptyTransactionNamespace'}
        required.add('TestRootPFRuleSingleClassCodecPrimaryABI')
    status='PASS' if result.returncode==0 and required<=passed else 'FAIL'
    def checked(name):return 'PASS' if name in passed else 'NOT_CONFIRMED'
    report={'status':status,'source_commit':os.environ['GITHUB_SHA'],'host_os':platform.mac_ver()[0],
        'kind':'standalone single-class real-policy prototype' if scope=='single-class' else 'native journal-bound typed own-PF rule generations',
        'scope':scope,'full_rule_generation_suite':status if scope=='full' else 'NOT_RUN',
        'journal_bound_single_filter_coordinator':status if scope=='coordinator' else 'NOT_RUN',
        'record_version':2,'required_tests':sorted(required),'compiler_primary_abi_comparison':abi,
        'actual_sigkill_checkpoints':sum('TestRootPFRuleEffectCrashResolution/'+stage in passed for stage in stages),
        'go_loader_actual_stage_removal_sigkill_checkpoints':sum(name in passed for name in loader_cases),
        'go_loader_owned_inactive_queue_and_namespace_crash_cleanup':checked('TestRootPFRuleLoaderCrashRecovery'),
        'dual_family_numeric_udp_loopback_deny_generations':checked('TestRootPFRuleCanonicalGenerationsAndRefusals'),
        'wrong_index_unassigned_source_unowned_tunnel_refusals':checked('TestRootPFRuleCanonicalGenerationsAndRefusals'),
        'identical_policy_does_not_increment_generation':checked('TestRootPFRuleCanonicalGenerationsAndRefusals'),
        'native_journal_owned_tunnel_policy':checked('TestRootPFRuleOwnedTunnelPolicy'),
        'pre_load_cancellation_and_unknown_third_hash_preserve_intent':checked('TestRootPFRuleCanceledAndThirdHashRemainBoundToIntent'),
        'actual_old_hash_rollback_new_hash_confirmation_after_crash':checked('TestRootPFRuleEffectCrashResolution'),
        'kernel_rules_reference_and_displayed_baselines_restored':'PASS' if status=='PASS' and scope=='full' else 'NOT_CONFIRMED',
        'standalone_real_deny_loopback_rollback_and_exact_namespace_cleanup':checked('TestRootPFRuleSingleClassRealPolicy'),
        'standalone_exact_namespace_cycles':3 if 'TestRootPFRuleSingleClassRealPolicy' in passed else 0,
        'standalone_actual_sigkill_checkpoints':3 if 'TestRootPFRuleSingleClassRealPolicy' in passed else 0,
        'standalone_own_inactive_queue_cleanup_after_sigkill':checked('TestRootPFRuleSingleClassRealPolicy'),
        'go_rule_codec_complete_primary_struct_comparison':checked('TestRootPFRuleSingleClassCodecPrimaryABI'),
        'shared_pool_staging':'USED_NOT_ATOMIC','production_loader_integration':True,'installed_client_guard_integration':False,
        'packet_leak_captures':'NOT_RUN','physical_scoped_endpoint_path':'NOT_RUN','interface_generation_reuse':'NOT_RUN',
        'bounded_direct_kernel_anchor_enumeration':checked('TestRootPFRuleEnumerationForeignFilterAndNATRefused'),
        'actual_nested_foreign_quick_and_nat_refused_without_mutation':checked('TestRootPFRuleEnumerationForeignFilterAndNATRefused'),
        'empty_single_class_transaction_namespace_retired':checked('TestRootPFRuleEmptyTransactionNamespace/single'),
        'empty_multi_class_transaction_namespace_retired':checked('TestRootPFRuleEmptyTransactionNamespace/multi'),
        'privileged_writer_atomicity':'NOT_PROVEN',
        'power_loss':'NOT_RUN','reboot':'NOT_RUN','high_sierra':'NOT_RUN','client_request_integration':False,'protection_ready':False}
    (output/'pf-rules-ci.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    if status!='PASS':
        for event in events:
            if event.get('Action')=='output' and ('.go:' in event.get('Output','') or 'FAIL' in event.get('Output','')):
                print(event['Output'].strip())
        raise SystemExit('Journal-bound native PF rule generation tests failed')

if __name__=='__main__':main()
