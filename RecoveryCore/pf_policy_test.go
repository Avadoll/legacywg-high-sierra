package recoverycore

import (
	"net/netip"
	"strings"
	"testing"
)

func TestPFPolicyTypedOrderingFreezeAndNativeGrammar(t *testing.T) {
	v4 := pfUDPEscape{path: pfInterface{"en0", 4}, source: netip.MustParseAddr("192.0.2.10"), endpoint: netip.MustParseAddrPort("198.51.100.20:51820"), sourcePort: 45120}
	v6 := pfUDPEscape{path: pfInterface{"en0", 4}, source: netip.MustParseAddr("2001:db8::10"), endpoint: netip.MustParseAddrPort("[2001:db8::20]:443"), sourcePort: 45120}
	tunnel := pfInterface{"utun9", 12}
	policy := pfPolicy{true, &tunnel, []pfUDPEscape{v6, v4, v4}}
	frozen, err := policy.frozen()
	if err != nil || len(frozen.escapes) != 2 {
		t.Fatal("typed deterministic dedup failed")
	}
	text, err := frozen.render()
	if err != nil || !strings.HasSuffix(text, stagedPFRule) || strings.Contains(text, "keep state") {
		t.Fatal("typed policy lost final deny or stateless semantics")
	}
	parsed, err := parsePFPolicy(text)
	if err != nil || !samePFPolicy(frozen, parsed) {
		t.Fatal("restricted typed/native semantic round trip failed")
	}
	policy.escapes[0].path.name = "invalid"
	tunnel.name = "invalid"
	again, err := frozen.render()
	if err != nil || again != text {
		t.Fatal("caller mutation changed frozen policy")
	}
	if _, err := parsePFPolicy(strings.ReplaceAll(text, " flags any", "")); err != nil {
		t.Fatal("equivalent native unrestricted flags display refused")
	}
	if _, err := parsePFPolicy(strings.ReplaceAll(text, "user = 0", "user = root")); err != nil {
		t.Fatal("equivalent native root UID display refused")
	}
}

func TestPFPolicyRefusesRuleInjectionUnboundedAndUnscopedFields(t *testing.T) {
	valid := pfUDPEscape{path: pfInterface{"en0", 4}, source: netip.MustParseAddr("192.0.2.10"), endpoint: netip.MustParseAddrPort("198.51.100.20:51820"), sourcePort: 45120}
	for _, change := range []func(*pfUDPEscape){
		func(e *pfUDPEscape) { e.path.name = "en0\npass out all" },
		func(e *pfUDPEscape) { e.path.name = "!en0" }, func(e *pfUDPEscape) { e.path.index = 0 },
		func(e *pfUDPEscape) { e.source = netip.MustParseAddr("0.0.0.0") },
		func(e *pfUDPEscape) { e.source = netip.MustParseAddr("::ffff:192.0.2.10") },
		func(e *pfUDPEscape) { e.source = netip.MustParseAddr("fe80::10%en0") },
		func(e *pfUDPEscape) { e.endpoint = netip.MustParseAddrPort("224.0.0.1:51820") },
		func(e *pfUDPEscape) { e.endpoint = netip.MustParseAddrPort("255.255.255.255:51820") },
		func(e *pfUDPEscape) { e.endpoint = netip.MustParseAddrPort("[::]:51820") },
		func(e *pfUDPEscape) { e.endpoint = netip.MustParseAddrPort("[2001:db8::20]:51820") },
		func(e *pfUDPEscape) { e.endpoint = netip.MustParseAddrPort("198.51.100.20:0") },
		func(e *pfUDPEscape) { e.sourcePort = 0 },
	} {
		escape := valid
		change(&escape)
		if _, err := (pfPolicy{escapes: []pfUDPEscape{escape}}).render(); err == nil {
			t.Fatal("invalid field or command injection accepted")
		}
	}
	conflicting := valid
	conflicting.path.index++
	if _, err := (pfPolicy{escapes: []pfUDPEscape{valid, conflicting}}).render(); err == nil {
		t.Fatal("conflicting interface identity silently deduplicated")
	}
	if _, err := (pfPolicy{escapes: make([]pfUDPEscape, 17)}).render(); err == nil {
		t.Fatal("unbounded exception set accepted")
	}
	if _, err := (pfPolicy{tunnel: &pfInterface{"en0", 4}}).render(); err == nil {
		t.Fatal("physical interface accepted as unrestricted tunnel")
	}
	text, _ := (pfPolicy{escapes: []pfUDPEscape{valid}}).render()
	for _, bad := range []string{
		"pass out all\n", "prefix" + stagedPFRule, strings.TrimSuffix(text, stagedPFRule),
		strings.Replace(text, "no state", "keep state", 1), strings.Replace(text, "quick", "", 1),
		strings.Replace(text, "192.0.2.10", "any", 1), strings.Replace(text, "192.0.2.10", "192.0.2.0/24", 1),
		strings.Replace(text, "udp", "tcp", 1), strings.Replace(text, "51820", "domain", 1),
		strings.Replace(text, "51820", "051820", 1), "table <x> { 192.0.2.10 }\n" + text,
		strings.Replace(text, " port = 45120", "", 1),
		strings.Replace(text, "port = 45120", "port = 0", 1),
		strings.Replace(text, "port = 45120", "port = 65536", 1),
		strings.Replace(text, "port = 45120", "port = 045120", 1),
		strings.Replace(text, "port = 45120", "port != 45120", 1),
		strings.Replace(text, "port = 45120", "port = 45120:45121", 1),
		strings.Replace(text, "port = 45120", "port = domain", 1),
		strings.Replace(text, "port = 45120", "port = { 45120, 45121 }", 1),
		text + "pass out all\n", "set skip on en0\n" + text,
		strings.Replace(text, " user = 0", "", 1),
		strings.Replace(text, "user = 0", "user = 501", 1),
		strings.Replace(text, "user = 0", "user != 0", 1),
		strings.Replace(text, "user = 0", "user = { 0, 501 }", 1),
	} {
		if _, err := parsePFPolicy(bad); err == nil {
			t.Fatal("unknown/wider/stateful/malformed native policy adopted")
		}
	}
}

func TestPFPolicyLocalPortChangesIdentityAndHash(t *testing.T) {
	first := pfUDPEscape{path: pfInterface{"en0", 4}, source: netip.MustParseAddr("192.0.2.10"), endpoint: netip.MustParseAddrPort("198.51.100.20:51820"), sourcePort: 45120}
	second := first
	second.sourcePort++
	policyA, err := (pfPolicy{escapes: []pfUDPEscape{first}}).frozen()
	if err != nil {
		t.Fatal("first admitted local port refused")
	}
	policyB, err := (pfPolicy{escapes: []pfUDPEscape{second}}).frozen()
	if err != nil || samePFPolicy(policyA, policyB) {
		t.Fatal("changed local UDP port retained prior semantic identity")
	}
	renderedA, errA := policyA.render()
	renderedB, errB := policyB.render()
	if errA != nil || errB != nil || pfDigest(renderedA) == pfDigest(renderedB) {
		t.Fatal("changed local UDP port retained prior durable rules hash")
	}
	combined, err := (pfPolicy{escapes: []pfUDPEscape{second, first, first}}).frozen()
	if err != nil || len(combined.escapes) != 2 || combined.escapes[0].sourcePort != first.sourcePort || combined.escapes[1].sourcePort != second.sourcePort {
		t.Fatal("distinct local UDP ports were collapsed or not canonically ordered")
	}
	for _, port := range []uint16{1, 65535} {
		escape := first
		escape.sourcePort = port
		policy, err := (pfPolicy{escapes: []pfUDPEscape{escape}}).frozen()
		text, renderErr := policy.render()
		parsed, parseErr := parsePFPolicy(text)
		if err != nil || renderErr != nil || parseErr != nil || !samePFPolicy(policy, parsed) {
			t.Fatal("valid exact local UDP port boundary lost in native round trip")
		}
	}
}
