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
    if scope not in ('full','single-class','coordinator','packets','encrypted','transport','scoped','routes','protection','admitted','ephemeral','route-wire'):raise SystemExit('Unknown native PF scope')
    pattern='^(TestRootPFRule|TestProtectedEndpointInput$)'
    if scope=='single-class':pattern='^TestRootPFRuleSingleClass(RealPolicy|CodecPrimaryABI)$'
    if scope=='coordinator':pattern='^TestRootPFRule(CanonicalGenerationsAndRefusals|OwnedTunnelPolicy|CanceledAndThirdHashRemainBoundToIntent|EffectCrashResolution|EffectCrashChild|LoaderCrashRecovery|LoaderCrashChild|SingleClassCodecPrimaryABI)$'
    if scope=='packets':pattern='^TestRootPFRuleNativePackets$'
    if scope=='encrypted':pattern='^TestRootPFRule(EncryptedPackets|GuardedEncryptedPackets|ScopedGuardedEncryptedPackets)$'
    if scope=='transport':pattern='^TestRootPFRule(Socket|GuardTransport|GuardedEncryptedPackets)'
    if scope=='scoped':pattern='^TestRootPFRuleScopedGuard'
    if scope=='routes':pattern='^TestRootPFRuleOwnedEndpoint'
    if scope=='protection':pattern='^(TestRootPFRuleProtectedTransport|TestProtectedEndpointInput$)'
    if scope=='admitted':pattern='^TestRootPFRuleProtectedAdmittedCrash'
    if scope=='ephemeral':pattern='^TestRootPFRule(ProtectedAdmittedCrashChild|EphemeralAdmittedCrashReuse|OwnInterfaceFlagWire|OwnInterfaceLeaseWire|OwnInterfaceReferencedRefused)$'
    if scope=='route-wire':pattern='^TestRootPFRule(OwnedEndpointWire|OwnInterfaceFlagWire|OwnInterfaceLeaseWire)$'
    # The full package already measured 880s before adding transaction-owner
    # lifecycle/encrypted cases. Keep explicit Go and outer process limits.
    test_timeout=1200 if scope=='full' else 600 if scope in ('routes','protection') else 300
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
        'LEGACYWG_PF_NONROOT_UID='+str(os.getuid()),'LEGACYWG_PF_NONROOT_GID='+str(os.getgid()),
        'LEGACYWG_PF_TRANSACTION_HELPER='+str(transaction),
        'LEGACYWG_PF_SINGLE_RULE_HELPER='+str(singleton),
        'LEGACYWG_PF_NESTED_RULE_HELPER='+str(build/'pf-nested-rule-probe'),
        'LEGACYWG_PF_PACKET_TESTS='+('1' if scope in ('packets','full') else '0'),
        'LEGACYWG_PF_ENCRYPTED_PACKET_TESTS='+('1' if scope in ('encrypted','transport','scoped','routes','protection','full') else '0'),str(test),
        '-test.run='+pattern,
        '-test.v=test2json','-test.timeout='+str(test_timeout)+'s'],
        capture_output=True,text=True,env=env,timeout=test_timeout+30)
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
        'TestRootPFRuleEffectCrashResolution'}|{'TestRootPFRuleEffectCrashResolution/'+stage for stage in stages}
    required|={'TestRootPFRuleLoaderCrashRecovery'}|loader_cases
    if scope=='single-class':required={'TestRootPFRuleSingleClassRealPolicy','TestRootPFRuleSingleClassCodecPrimaryABI'}
    if scope=='coordinator':
        required-={'TestRootPFRuleEnumerationForeignFilterAndNATRefused'}
        required.add('TestRootPFRuleSingleClassCodecPrimaryABI')
    if scope=='packets':required={'TestRootPFRuleNativePackets'}
    if scope=='encrypted':required={'TestRootPFRuleEncryptedPackets','TestRootPFRuleEncryptedPackets/outer4','TestRootPFRuleEncryptedPackets/outer6'}
    if scope=='full':required|={'TestRootPFRuleNativePackets','TestRootPFRuleEncryptedPackets','TestRootPFRuleEncryptedPackets/outer4','TestRootPFRuleEncryptedPackets/outer6'}
    guarded={'TestRootPFRuleGuardedEncryptedPackets','TestRootPFRuleGuardedEncryptedPackets/outer4','TestRootPFRuleGuardedEncryptedPackets/outer6'}
    transport={'TestRootPFRuleSocketPortLease','TestRootPFRuleSocketDualFamilyAndAdmission',
        'TestRootPFRuleGuardTransportCloseReopenAndStorePin','TestRootPFRuleGuardTransportCanceledAdmissionRetainsPorts',
        'TestRootPFRuleGuardTransportThirdHashRetainsPorts','TestRootPFRuleGuardTransportGarbageCollectionRetainsPorts',
        'TestRootPFRuleGuardTransportBoundedWriteShutdown'}
    if scope in ('full','encrypted'):required|=guarded
    if scope=='full':required|=transport
    if scope=='transport':required=transport|guarded
    scoped_encrypted={'TestRootPFRuleScopedGuardedEncryptedPackets','TestRootPFRuleScopedGuardedEncryptedPackets/outer4','TestRootPFRuleScopedGuardedEncryptedPackets/outer6'}
    scoped=scoped_encrypted|{'TestRootPFRuleScopedGuardLossAfterConfirmedAdmission','TestRootPFRuleScopedGuardLossDuringSocketOpen'}
    if scope=='scoped':required=scoped
    if scope=='full':required|=scoped
    if scope=='encrypted':required|=scoped_encrypted
    endpoint_crash_points=('endpoint_plan_committed','endpoint_add_intent_committed','endpoint_added_kernel','endpoint_installed_committed','endpoint_deleted_kernel')
    owned_encrypted={'TestRootPFRuleOwnedEndpointEncryptedPackets','TestRootPFRuleOwnedEndpointEncryptedPackets/outer4','TestRootPFRuleOwnedEndpointEncryptedPackets/outer6'}
    endpoint_routes={'TestRootPFRuleOwnedEndpointLifecycle','TestRootPFRuleOwnedEndpointGuestGateway','TestRootPFRuleOwnedEndpointCrashRecovery'}|owned_encrypted|{'TestRootPFRuleOwnedEndpointCrashRecovery/'+point for point in endpoint_crash_points}
    if scope=='routes':required=endpoint_routes
    if scope=='route-wire':required={'TestRootPFRuleOwnedEndpointWire','TestRootPFRuleOwnInterfaceFlagWire'}|{'TestRootPFRuleOwnInterfaceFlagWire/'+name for name in (
        'fresh_zero_references','set_clear_verified','replacement_has_no_skip','disabled_policy_baseline_unchanged')}
    if scope=='full':required|=endpoint_routes
    protected={'TestProtectedEndpointInput','TestRootPFRuleProtectedTransportLifecycle',
               'TestRootPFRuleProtectedTransportBorrowed','TestRootPFRuleProtectedTransportInterruptedPreparation',
               'TestRootPFRuleProtectedTransportRefusesOwnTunnel','TestRootPFRuleProtectedTransportEmptyStopVerifiesGuard',
               'TestRootPFRuleProtectedTransportEncryptedPackets',
               'TestRootPFRuleProtectedTransportEncryptedPackets/outer4','TestRootPFRuleProtectedTransportEncryptedPackets/outer6'}
    if scope=='protection':required=protected
    if scope=='full':required|=protected
    admitted={'TestRootPFRuleProtectedAdmittedCrashReuse'}|{'TestRootPFRuleProtectedAdmittedCrashReuse/'+name for name in (
        'actual_sigkill','replacement_instance_after_absence','dead_owner_policy_retained',
        'verified_deny_blocks_replacement','restored_baseline_positive_controls','no_inherited_tunnel_permission')}
    if scope=='admitted':required=admitted
    if scope=='full':required|=admitted
    ephemeral={'TestRootPFRuleEphemeralAdmittedCrashReuse','TestRootPFRuleOwnInterfaceFlagWire','TestRootPFRuleOwnInterfaceReferencedRefused'}|{'TestRootPFRuleEphemeralAdmittedCrashReuse/'+name for name in (
        'live_permission_positive_controls','actual_sigkill','replacement_instance_after_absence','replacement_has_no_skip',
        'dead_owner_policy_retained','verified_deny_blocks_replacement','restored_baseline_positive_controls','no_inherited_tunnel_permission')}
    if scope=='ephemeral':required=ephemeral
    if scope=='full':required|=ephemeral
    interface_lease={'TestRootPFRuleOwnInterfaceLeaseWire'}|{'TestRootPFRuleOwnInterfaceLeaseWire/'+name for name in (
        'retained_after_device_close','clear_before_last_descriptor_close','last_close_removes_interface','disabled_policy_baseline_unchanged')}
    if scope in ('route-wire','ephemeral','full'):required|=interface_lease
    if scope in ('ephemeral','full'):required|={'TestRootPFRuleOwnInterfaceReferencedRefused/cycle'+str(cycle) for cycle in range(3)}
    status='PASS' if result.returncode==0 and required<=passed else 'FAIL'
    def checked(name):return 'PASS' if name in passed else 'NOT_CONFIRMED'
    report={'status':status,'source_commit':os.environ['GITHUB_SHA'],'host_os':platform.mac_ver()[0],
        'kind':'standalone single-class real-policy prototype' if scope=='single-class' else 'native journal-bound typed own-PF rule generations',
        'scope':scope,'full_rule_generation_suite':status if scope=='full' else 'NOT_RUN',
        'owned_interface_flag_wire':checked('TestRootPFRuleOwnInterfaceFlagWire'),
        'owned_interface_lease_wire':checked('TestRootPFRuleOwnInterfaceLeaseWire'),
        'owned_interface_rule_reference_refusal':checked('TestRootPFRuleOwnInterfaceReferencedRefused'),
        'owned_interface_lease_scope':'test-only atomic CLOEXEC duplicate, official device Close, clear confirmed before final close; no cross-process lease or installed use',
        'owned_interface_flag_scope':'test-only own fresh TUN, disabled PF, set/clear and close/recreate; crash/packets/installed protection NOT_RUN',
        'ephemeral_admitted_owner_crash_candidate':checked('TestRootPFRuleEphemeralAdmittedCrashReuse'),
        'ephemeral_admitted_owner_live_positive_controls':checked('TestRootPFRuleEphemeralAdmittedCrashReuse/live_permission_positive_controls'),
        'ephemeral_admitted_owner_actual_sigkill':checked('TestRootPFRuleEphemeralAdmittedCrashReuse/actual_sigkill'),
        'ephemeral_admitted_owner_replacement_has_no_skip':checked('TestRootPFRuleEphemeralAdmittedCrashReuse/replacement_has_no_skip'),
        'ephemeral_admitted_owner_no_inherited_tunnel_permission':checked('TestRootPFRuleEphemeralAdmittedCrashReuse/no_inherited_tunnel_permission'),
        'ephemeral_admitted_owner_index_reused':'OBSERVED' if 'TestRootPFRuleEphemeralAdmittedCrashReuse/replacement_instance_after_absence/index_reused' in passed else 'NOT_OBSERVED' if 'TestRootPFRuleEphemeralAdmittedCrashReuse/replacement_instance_after_absence/index_changed' in passed else 'NOT_CONFIRMED',
        'ephemeral_admitted_owner_scope':'test-only skip permission without a tunnel-name rule; actual kill/replacement and synthetic packets; foreign skip admission/production lease/journal/installed/High Sierra NOT_RUN',
        'journal_bound_single_filter_coordinator':status if scope=='coordinator' else 'NOT_RUN',
        'packet_test_scope':'native kernel to journal-owned utun/pinned netstack; physical/encrypted/OS-resolver NOT_RUN',
        'owned_utun_udp_tcp_dns_port_packet_guard':checked('TestRootPFRuleNativePackets'),
        'outer_udp_escapes_fixed_root_socket_uid':checked('TestRootPFRuleCanonicalGenerationsAndRefusals'),
        'outer_udp_escapes_exact_nonzero_source_port':checked('TestRootPFRuleCanonicalGenerationsAndRefusals'),
        'root_wrong_source_port_refused_with_positive_controls':checked('TestRootPFRuleNativePackets'),
        'ordinary_process_outer_udp_refusal_with_positive_baseline_and_tunnel_permission':checked('TestRootPFRuleNativePackets'),
        'ordinary_process_uid_refusal_with_matching_live_source_port':checked('TestRootPFRuleNativePackets'),
        'owned_utun_packet_deny_survives_owner_sigkill':checked('TestRootPFRuleNativePackets'),
        'owned_utun_packet_guard_actual_sigkill_checkpoints':1 if 'TestRootPFRuleNativePackets' in passed else 0,
        'encrypted_packet_test_scope':'official StdNetBind/client native inner utun and isolated synthetic outer utun/netstack peer; physical/OS-resolver/installed guard NOT_RUN',
        'encrypted_inner_dual_stack_udp_tcp_dns_outer_ipv4':checked('TestRootPFRuleEncryptedPackets/outer4'),
        'encrypted_inner_dual_stack_udp_tcp_dns_outer_ipv6':checked('TestRootPFRuleEncryptedPackets/outer6'),
        'encrypted_outer_and_inner_exception_removal':checked('TestRootPFRuleEncryptedPackets'),
        'encrypted_actual_bind_port_and_explicit_revoke_close_reopen_readmit':checked('TestRootPFRuleEncryptedPackets'),
        'automatic_socket_lifetime_revocation':'PRIVATE_NATIVE_BIND_NOT_INSTALLED',
        'scoped_guard_existing_route_loss_native_encrypted':checked('TestRootPFRuleScopedGuardedEncryptedPackets'),
        'scoped_guard_loss_after_confirmed_pf_admission':checked('TestRootPFRuleScopedGuardLossAfterConfirmedAdmission'),
        'scoped_guard_loss_during_socket_open':checked('TestRootPFRuleScopedGuardLossDuringSocketOpen'),
        'scoped_guard_scope':'owned virtual interface; borrowed scoped routes; physical mutation/installed guard NOT_RUN',
        'owned_endpoint_host_route_lifecycle':checked('TestRootPFRuleOwnedEndpointLifecycle'),
        'owned_endpoint_host_route_native_wire':checked('TestRootPFRuleOwnedEndpointWire'),
        'owned_endpoint_host_route_crash_recovery':checked('TestRootPFRuleOwnedEndpointCrashRecovery'),
        'owned_endpoint_host_route_guest_gateway_without_payload':checked('TestRootPFRuleOwnedEndpointGuestGateway'),
        'owned_endpoint_host_route_encrypted_conflict':checked('TestRootPFRuleOwnedEndpointEncryptedPackets'),
        'owned_endpoint_host_route_sigkill_checkpoints':sum('TestRootPFRuleOwnedEndpointCrashRecovery/'+point in passed for point in endpoint_crash_points),
        'owned_endpoint_host_route_scope':'numeric host-only; owned utun traffic and guest IPv4 gateway allocation without payload; hardware/installed integration NOT_RUN; uncertain additions retained',
        'typed_protected_transport_preparation':checked('TestRootPFRuleProtectedTransportLifecycle'),
        'typed_protected_transport_borrowed_route_preservation':checked('TestRootPFRuleProtectedTransportBorrowed'),
        'typed_protected_transport_interrupted_preparation':checked('TestRootPFRuleProtectedTransportInterruptedPreparation'),
        'typed_protected_transport_own_tunnel_endpoint_refusal':checked('TestRootPFRuleProtectedTransportRefusesOwnTunnel'),
        'typed_protected_transport_empty_stop_checks_actual_guard':checked('TestRootPFRuleProtectedTransportEmptyStopVerifiesGuard'),
        'typed_protected_transport_encrypted_conflicting_route':checked('TestRootPFRuleProtectedTransportEncryptedPackets'),
        'typed_protected_transport_scope':'private worker facade only; numeric endpoints/owned topology/explicit disconnect; installed full routes/DNS/process death/target NOT_RUN',
        'admitted_owner_actual_sigkill':checked('TestRootPFRuleProtectedAdmittedCrashReuse/actual_sigkill'),
        'admitted_owner_replacement_instance_after_verified_absence':checked('TestRootPFRuleProtectedAdmittedCrashReuse/replacement_instance_after_absence'),
        'admitted_owner_replacement_index_reused':'OBSERVED' if 'TestRootPFRuleProtectedAdmittedCrashReuse/replacement_instance_after_absence/index_reused' in passed else 'NOT_OBSERVED' if 'TestRootPFRuleProtectedAdmittedCrashReuse/replacement_instance_after_absence/index_changed' in passed else 'NOT_CONFIRMED',
        'admitted_owner_policy_and_reference_retained':checked('TestRootPFRuleProtectedAdmittedCrashReuse/dead_owner_policy_retained'),
        'admitted_owner_controlled_deny_blocks_replacement':checked('TestRootPFRuleProtectedAdmittedCrashReuse/verified_deny_blocks_replacement'),
        'admitted_owner_restored_baseline_positive_controls':checked('TestRootPFRuleProtectedAdmittedCrashReuse/restored_baseline_positive_controls'),
        'admitted_owner_no_inherited_tunnel_permission':checked('TestRootPFRuleProtectedAdmittedCrashReuse/no_inherited_tunnel_permission'),
        'admitted_owner_lifetime_scope':'actual child admission and SIGKILL, parent-owned replacement/ordinary UID UDP/root UDP+TCP; controlled fixture cleanup is not production recovery authority',
        'native_udp_deadline_retains_port':checked('TestRootPFRuleSocketPortLease'),
        'native_dual_family_same_port_and_path_admission':checked('TestRootPFRuleSocketDualFamilyAndAdmission'),
        'automatic_deny_before_release_stale_callbacks_and_store_pin':checked('TestRootPFRuleGuardTransportCloseReopenAndStorePin'),
        'uncertain_admission_retains_ports_and_explicit_reconciliation':checked('TestRootPFRuleGuardTransportCanceledAdmissionRetainsPorts'),
        'unknown_policy_retains_ports':checked('TestRootPFRuleGuardTransportThirdHashRetainsPorts'),
        'retained_ports_survive_loss_of_external_references_and_gc':checked('TestRootPFRuleGuardTransportGarbageCollectionRetainsPorts'),
        'blocked_send_under_official_lock_order_bounded':'MODEL_PASS' if 'TestRootPFRuleGuardTransportBoundedWriteShutdown' in passed else 'NOT_CONFIRMED',
        'official_device_automatic_down_up_close_native_encrypted':checked('TestRootPFRuleGuardedEncryptedPackets'),
        'encrypted_packet_guard_deny_survives_owner_sigkill':checked('TestRootPFRuleEncryptedPackets'),
        'encrypted_packet_guard_actual_sigkill_checkpoints':sum('TestRootPFRuleEncryptedPackets/outer'+str(family) in passed for family in (4,6)),
        'packet_guard_native_sigkill_wait_status':'PASS' if 'TestRootPFRuleEncryptedPackets' in passed or 'TestRootPFRuleNativePackets' in passed else 'NOT_CONFIRMED',
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
