package recoverycore

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	networkcore "legacywg/NetworkCore"
)

func TestProtectedEndpointInput(t *testing.T) {
	a := netip.MustParseAddrPort("198.18.111.130:45121")
	b := netip.MustParseAddrPort("[fd00:198:18:111::130]:45122")
	input := []netip.AddrPort{b, a, b}
	got, err := protectedEndpoints(input)
	if err != nil || len(got) != 2 || got[0] != a || got[1] != b || input[0] != b {
		t.Fatal("endpoint canonical copy failed")
	}
	for _, text := range []string{"127.0.0.1:1", "[::1]:1", "[fe80::1%en0]:1", "0.0.0.0:1", "224.0.0.1:1", "255.255.255.255:1", "198.18.111.130:0", "[::ffff:198.18.111.130]:1"} {
		if _, err := protectedEndpoints([]netip.AddrPort{netip.MustParseAddrPort(text)}); err == nil {
			t.Fatal("unsupported endpoint accepted")
		}
	}
	if _, err := protectedEndpoints(nil); err == nil {
		t.Fatal("empty initial endpoint set accepted")
	}
	if _, err := protectedEndpoints(make([]netip.AddrPort, maxPFReferences+1)); err == nil {
		t.Fatal("unbounded endpoint set accepted")
	}
}

type protectedFixture struct {
	store    *Store
	tunnel   tun.Device
	owner    *ProtectedTransport
	ctx      context.Context
	lastMark atomic.Value
}

func newProtectedFixture(t *testing.T) *protectedFixture {
	t.Helper()
	requirePFRuleCI(t)
	f := &protectedFixture{store: realBootStore(t, ownedReferenceTestDirectory(t))}
	f.lastMark.Store("none")
	f.store.checkpoint = func(mark string) { f.lastMark.Store(mark) }
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	f.ctx = ctx
	t.Cleanup(func() {
		cancel()
		f.store.checkpoint = nil
		cleanup, stop := context.WithTimeout(context.Background(), 40*time.Second)
		defer stop()
		if f.tunnel != nil {
			_ = f.tunnel.Close()
		}
		if f.owner != nil {
			if f.owner.Disconnect(cleanup) != nil {
				t.Error("protected fixture retained recovery ownership")
			}
		} else if f.store.FinishAfterClose(cleanup) != nil {
			t.Error("unprepared fixture journal retained")
		}
	})
	if f.store.begin() != nil {
		t.Fatal("protected fixture intent failed")
	}
	var err error
	f.tunnel, err = tun.CreateTUN("utun", 1280)
	if err != nil {
		t.Fatal("protected fixture tunnel failed")
	}
	name, err := f.tunnel.Name()
	if err != nil {
		t.Fatal("protected fixture tunnel name failed")
	}
	endpointFixedCommand(t, "/sbin/ifconfig", name, "inet", "198.18.112.129", "198.18.112.129", "netmask", "255.255.255.255", "alias")
	endpointFixedCommand(t, "/sbin/ifconfig", name, "up")
	iface, err := net.InterfaceByName(name)
	if err != nil || f.store.MarkInterface(name, iface.Index) != nil {
		t.Fatal("protected fixture tunnel identity failed")
	}
	return f
}

func protectedFixtureEndpoints(hosts []networkcore.ScopedHost) []netip.AddrPort {
	var endpoints []netip.AddrPort
	for _, host := range hosts {
		endpoints = append(endpoints, netip.AddrPortFrom(host.Destination, 45121), netip.AddrPortFrom(host.Destination, 45122))
	}
	return append(endpoints, endpoints[0])
}

func TestRootPFRuleProtectedTransportLifecycle(t *testing.T) {
	requirePFRuleCI(t)
	_, hosts := endpointOwnedLink(t)
	f := newProtectedFixture(t)
	var err error
	f.owner, err = f.store.PrepareProtectedTransport(f.ctx, protectedFixtureEndpoints(hosts))
	if err != nil || f.owner == nil {
		t.Fatal("typed protection preparation failed")
	}
	journal, err := f.store.readEndpointRoutes(endpointJournalFile)
	if err != nil || journal == nil || len(journal.Routes) != 2 || len(f.owner.bind.policy.escapes) != 4 {
		t.Fatal("destinations were not deduplicated independently of UDP ports")
	}
	f.store.Close()
	if f.store.closed || f.store.Finish() == nil {
		t.Fatal("ordinary close/finish abandoned a protected preparation")
	}
	if second, err := f.store.PrepareProtectedTransport(f.ctx, protectedFixtureEndpoints(hosts)); err == nil || second != nil {
		t.Fatal("second protection owner admitted")
	}
	bind, err := f.owner.Bind()
	if err != nil {
		t.Fatal("prepared transport unavailable")
	}
	if funcs, port, err := bind.Open(0); err != nil || len(funcs) != 2 || port == 0 {
		t.Fatal("typed preparation failed native dual-family admission")
	}
	select {
	case <-f.owner.Lost():
		t.Fatal("unchanged preparation lost its paths")
	default:
	}
	// Canceling an admission context must not skip independent deny/port cleanup.
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if f.owner.Stop(canceled) != nil {
		t.Fatal("protected stop failed to preserve deny-only")
	}
	if _, _, err := bind.Open(0); err == nil {
		t.Fatal("permanently stopped controller reopened")
	}
	if _, err := f.owner.Bind(); err == nil || f.owner.Disconnect(f.ctx) == nil {
		t.Fatal("live owned tunnel permitted protection release")
	}
	record, err := f.store.readPF(pfJournalFile)
	if err != nil || record == nil || record.RulesSHA256 != pfDigest(stagedPFRule) || f.owner.bind.current.Load() != nil {
		t.Fatal("stopped transport did not retain confirmed deny-only")
	}
	if f.tunnel.Close() != nil {
		t.Fatal("ordered explicit tunnel Close failed")
	}
	if f.owner.Disconnect(f.ctx) != nil {
		var phases []endpointRoutePhase
		f.store.mutex.Lock()
		journal, readErr := f.store.readEndpointRoutes(endpointJournalFile)
		if journal != nil {
			for _, entry := range journal.Routes {
				phases = append(phases, entry.Phase)
			}
		}
		f.store.mutex.Unlock()
		t.Fatalf("ordered explicit Disconnect failed: tunnel_gone=%t detached=%t context_ok=%t endpoint_phases=%v record_read_ok=%t last_mark=%v", admittedInterfaceNameAbsent(f.store.record.Interface), f.owner.bind.detached, f.ctx.Err() == nil, phases, readErr == nil, f.lastMark.Load())
	}
	if !f.store.closed || f.owner.Disconnect(f.ctx) != nil {
		t.Fatal("ordered explicit disconnect did not finish idempotently")
	}
	for _, host := range hosts {
		after, err := networkcore.EndpointRoute(f.ctx, host.Destination)
		if err != nil || after != host.Path {
			t.Fatal("typed disconnect changed endpoint baseline")
		}
	}
	after, err := readDisabledPF(f.ctx, record.Anchor)
	if err != nil || !after.matches(*record) || after.rules != pfDigest("") || len(fixturePFReferences(t, f.ctx)) != 0 {
		t.Fatal("typed disconnect PF baseline differs")
	}
}

func TestRootPFRuleProtectedTransportBorrowed(t *testing.T) {
	requirePFRuleCI(t)
	_, hosts := endpointOwnedLink(t)
	for _, host := range hosts {
		if networkcore.ChangeScopedHost(context.Background(), host, true) != nil {
			t.Fatal("borrowed route fixture insertion failed")
		}
		host := host
		t.Cleanup(func() {
			if networkcore.ChangeScopedHost(context.Background(), host, false) != nil {
				t.Error("borrowed fixture route removal failed")
			}
		})
	}
	f := newProtectedFixture(t)
	var err error
	f.owner, err = f.store.PrepareProtectedTransport(f.ctx, protectedFixtureEndpoints(hosts))
	if err != nil || f.owner == nil || f.store.endpointResidue() {
		t.Fatal("existing scoped routes were not borrowed")
	}
	bind, err := f.owner.Bind()
	if err != nil {
		t.Fatal("borrowed preparation unavailable")
	}
	if _, _, err := bind.Open(0); err != nil || f.owner.Stop(f.ctx) != nil || f.tunnel.Close() != nil || f.owner.Disconnect(f.ctx) != nil {
		t.Fatal("borrowed route preparation lifecycle failed")
	}
	for _, host := range hosts {
		after, err := networkcore.ScopedRoute(f.ctx, host.Destination, host.Path.InterfaceIndex)
		if err != nil || !host.Matches(after) {
			t.Fatal("explicit disconnect removed a borrowed route")
		}
	}
}

func TestRootPFRuleProtectedTransportInterruptedPreparation(t *testing.T) {
	requirePFRuleCI(t)
	_, hosts := endpointOwnedLink(t)
	f := newProtectedFixture(t)
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	f.store.checkpoint = func(point string) {
		if point == "endpoint_installed_committed" {
			cancel()
		}
	}
	var err error
	f.owner, err = f.store.PrepareProtectedTransport(ctx, protectedFixtureEndpoints(hosts))
	f.store.checkpoint = nil
	if err == nil || f.owner == nil || !f.store.endpointResidue() || !f.store.pfResidue() {
		t.Fatal("interrupted preparation abandoned its route/guard owner")
	}
	if bind, err := f.owner.Bind(); err == nil || bind != nil {
		t.Fatal("failed preparation exposed an engine transport")
	}
	select {
	case <-f.owner.Lost():
	default:
		t.Fatal("failed preparation did not publish refusal")
	}
	f.store.Close()
	if f.store.closed || f.owner.Disconnect(f.ctx) == nil {
		t.Fatal("interrupted preparation released ownership before tunnel deletion")
	}
	if f.tunnel.Close() != nil || f.owner.Disconnect(f.ctx) != nil || !f.store.closed {
		t.Fatal("interrupted preparation ordered recovery failed")
	}
}

func TestRootPFRuleProtectedTransportRefusesOwnTunnel(t *testing.T) {
	f := newProtectedFixture(t)
	owner, err := f.store.PrepareProtectedTransport(f.ctx, []netip.AddrPort{netip.MustParseAddrPort("198.18.112.129:45121")})
	if err == nil || owner != nil || f.store.protection != nil || f.store.pfResidue() || f.store.endpointResidue() {
		t.Fatal("own-tunnel endpoint admission mutated protection state")
	}
}

func TestRootPFRuleProtectedTransportEmptyStopVerifiesGuard(t *testing.T) {
	requirePFRuleCI(t)
	_, hosts := endpointOwnedLink(t)
	f := newProtectedFixture(t)
	var err error
	f.owner, err = f.store.PrepareProtectedTransport(f.ctx, protectedFixtureEndpoints(hosts))
	if err != nil || f.owner == nil {
		t.Fatal("empty transport fixture preparation failed")
	}
	record, err := f.store.readPF(pfJournalFile)
	if err != nil || record == nil {
		t.Fatal("empty transport guard identity unavailable")
	}
	foreign := pfPolicy{loopback: true}
	_, canonical, err := f.store.preparePFPolicy(f.ctx, *record, foreign)
	if err != nil || forceFixturePFPolicy(f.ctx, f.store, *record, record.RulesSHA256, foreign) != nil {
		t.Fatal("controlled changed guard fixture failed")
	}
	// Only this test may restore its own controlled substitution. Production
	// Stop/Disconnect must preserve it and refuse to infer deny from no sockets.
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		if forceFixturePFPolicy(cleanup, f.store, *record, pfDigest(canonical), pfPolicy{}) != nil {
			t.Error("controlled changed guard restoration failed")
		}
	})
	if f.owner.bind.current.Load() != nil || f.owner.Stop(f.ctx) == nil || f.owner.Disconnect(f.ctx) == nil {
		t.Fatal("empty socket set was treated as proof of deny-only")
	}
	after, err := readPFPolicy(f.ctx, record.Anchor, true)
	unchanged, journalErr := f.store.readPF(pfJournalFile)
	if err != nil || after.rules != pfDigest(canonical) || journalErr != nil || unchanged == nil || *unchanged != *record {
		t.Fatal("unknown policy or journal was modified by refused stop")
	}
	f.store.Close()
	if f.store.closed {
		t.Fatal("refused empty stop released protected Store ownership")
	}
}
