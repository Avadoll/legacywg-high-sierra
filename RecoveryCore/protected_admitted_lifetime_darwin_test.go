package recoverycore

// Isolated admitted-owner lifetime experiment on disposable owned topology.
import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func admittedLifetimeSetup(t *testing.T, link tun.Device) *net.Interface {
	t.Helper()
	name, err := link.Name()
	if err != nil || !utunName.MatchString(name) {
		t.Fatal("admitted lifetime interface identity failed")
	}
	endpointFixedCommand(t, "/sbin/ifconfig", name, "inet", "198.18.99.129", "198.18.99.129", "netmask", "255.255.255.255", "alias")
	endpointFixedCommand(t, "/sbin/ifconfig", name, "inet6", "fd00:198:18:99::129", "prefixlen", "128", "alias")
	endpointFixedCommand(t, "/sbin/ifconfig", name, "up")
	iface, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatal("admitted lifetime interface index failed")
	}
	return iface
}

func TestRootPFRuleProtectedAdmittedCrashChild(t *testing.T) {
	directory, outerName := os.Getenv("LEGACYWG_ADMITTED_DIR"), os.Getenv("LEGACYWG_ADMITTED_OUTER")
	if directory == "" || outerName == "" {
		t.Skip("separate admitted-owner lifetime child")
	}
	requirePFRuleCI(t)
	store := realBootStore(t, directory)
	defer store.Close()
	if store.begin() != nil {
		t.Fatal("admitted child journal intent failed")
	}
	link, err := tun.CreateTUN("utun", 1280)
	if err != nil {
		t.Fatal("admitted child tunnel failed")
	}
	defer link.Close()
	iface := admittedLifetimeSetup(t, link)
	if store.MarkInterface(iface.Name, iface.Index) != nil {
		t.Fatal("admitted child tunnel journal failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()
	hosts := endpointFixtureHosts(t, outerName)
	owner, err := store.PrepareProtectedTransport(ctx, []netip.AddrPort{netip.AddrPortFrom(hosts[0].Destination, 45121)})
	if err != nil || owner == nil {
		t.Fatal("admitted child protection preparation failed")
	}
	ephemeral := os.Getenv("LEGACYWG_EPHEMERAL_ADMITTED") == "1"
	if ephemeral {
		// Test-only candidate: never create a name-pinning tunnel rule.
		// The actual guarded outer UDP admission remains unchanged.
		owner.bind.policy.tunnel = nil
	}
	bind, err := owner.Bind()
	if err != nil {
		t.Fatal("admitted child Bind unavailable")
	}
	if _, _, err := bind.Open(0); err != nil {
		t.Fatal("admitted child native socket admission failed")
	}
	if store.MarkConfigured(false) != nil {
		t.Fatal("admitted child configured journal failed")
	}
	if ephemeral {
		fd, err := openPFReferences(ctx)
		if err != nil {
			t.Fatal("ephemeral child PF descriptor unavailable")
		}
		defer unix.Close(fd)
		if fixtureChangeOwnSkip(ctx, fd, link, true) != nil {
			t.Fatal("ephemeral child permission refused")
		}
		endpointFixedCommand(t, "/sbin/route", "-n", "add", "-inet", "-host", pfPacketServer4, "-interface", iface.Name)
		endpointFixedCommand(t, "/sbin/route", "-n", "add", "-inet6", "-host", pfPacketServer6, "-interface", iface.Name)
		admittedLifetimeEchoPeer(t, link)
		for _, family := range []int{4, 6} {
			source, destination := "198.18.99.129", pfPacketServer4
			if family == 6 {
				source, destination = "fd00:198:18:99::129", pfPacketServer6
			}
			for _, protocol := range []int{17, 6} {
				if !pfEncryptedEcho(ctx, iface, family, protocol, 45121, source, destination, time.Second) {
					t.Fatal("ephemeral pre-kill live permission positive control failed")
				}
			}
		}
		observed, err := fixtureReadPFInterface(ctx, fd, iface.Name)
		if err != nil || observed != (fixturePFInterface{fixturePFSkip, 0, 1}) {
			t.Fatal("ephemeral pre-kill interface became referenced or stateful")
		}
		fmt.Println("EPHEMERAL_LIVE_POSITIVE_CONTROLS")
	}
	fmt.Println("OWNED_PROTECTION_ADMITTED")
	select {}
}

func admittedLifetimeEchoPeer(t *testing.T, link tun.Device) {
	t.Helper()
	peer, stack, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(pfPacketServer4), netip.MustParseAddr(pfPacketServer6)}, nil, 1280)
	if err != nil {
		t.Fatal("admitted lifetime isolated echo peer unavailable")
	}
	done := make(chan struct{}, 2)
	go pfPacketBridge(link, peer, nil, done)
	go pfPacketBridge(peer, link, nil, done)
	var datagrams []net.PacketConn
	var listeners []net.Listener
	t.Cleanup(func() {
		for _, connection := range datagrams {
			_ = connection.Close()
		}
		for _, listener := range listeners {
			_ = listener.Close()
		}
		_ = link.Close()
		_ = peer.Close()
		for i := 0; i < 2; i++ {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("admitted lifetime echo bridge did not join")
			}
		}
	})
	for _, address := range []string{pfPacketServer4, pfPacketServer6} {
		endpoint := netip.AddrPortFrom(netip.MustParseAddr(address), 45121)
		udp, err := stack.ListenUDPAddrPort(endpoint)
		if err != nil {
			t.Fatal("admitted lifetime echo UDP responder unavailable")
		}
		datagrams = append(datagrams, udp)
		go pfServeUDPEcho(udp, false)
		tcp, err := stack.ListenTCPAddrPort(endpoint)
		if err != nil {
			t.Fatal("admitted lifetime echo TCP responder unavailable")
		}
		listeners = append(listeners, tcp)
		go pfServeTCPEcho(tcp, false)
	}
}

// Restore only this controlled child's own policy, after actual SIGKILL proof.
// This test-only authority is not a production dead-owner/third-policy API.
func admittedLifetimeCleanup(t *testing.T, ctx context.Context, store *Store, identity PFRecord) error {
	t.Helper()
	record, err := store.readPF(pfJournalFile)
	if err != nil || record == nil || record.ID != identity.ID || record.PID != identity.PID || processAlive(record.PID) {
		return ErrRecoveryRequired
	}
	if record.Phase != PFActive {
		return ErrRecoveryRequired
	}
	if record.RulesSHA256 != pfDigest(stagedPFRule) {
		if *record != identity {
			return ErrRecoveryRequired
		}
		next, err := record.BeginRuleUpdate(pfDigest(stagedPFRule))
		if err != nil || store.commitOwnedPF(next) != nil ||
			forceFixturePFPolicy(ctx, store, next, record.RulesSHA256, pfPolicy{}) != nil || store.resolvePFPolicy(ctx) != nil {
			return ErrRecoveryRequired
		}
	}
	if store.recoverEndpointRoutes(ctx) != nil || store.recoverPFLifecycle(ctx) != nil {
		return ErrRecoveryRequired
	}
	return nil
}

func admittedInterfaceNameAbsent(name string) bool {
	interfaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range interfaces {
		if iface.Name == name {
			return false
		}
	}
	return true
}

func TestRootPFRuleProtectedAdmittedCrashReuse(t *testing.T) {
	admittedLifetimeReuse(t, false)
}

func TestRootPFRuleEphemeralAdmittedCrashReuse(t *testing.T) {
	admittedLifetimeReuse(t, true)
}

func admittedLifetimeReuse(t *testing.T, ephemeral bool) {
	t.Helper()
	requirePFRuleCI(t)
	outer, _ := endpointOwnedLink(t)
	directory := ownedReferenceTestDirectory(t)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRootPFRuleProtectedAdmittedCrashChild$", "-test.v", "-test.timeout=140s")
	child.Env = append(os.Environ(), "LEGACYWG_ADMITTED_DIR="+directory, "LEGACYWG_ADMITTED_OUTER="+outer.Name)
	if ephemeral {
		child.Env = append(child.Env, "LEGACYWG_EPHEMERAL_ADMITTED=1")
	}
	output, err := child.StdoutPipe()
	if err != nil || child.Start() != nil {
		t.Fatal("admitted lifetime child did not start")
	}
	defer func() { _ = child.Process.Kill() }()
	scanner := bufio.NewScanner(output)
	scanner.Buffer(make([]byte, 512), 4096)
	reached := false
	positive := false
	for lines := 0; lines < 32 && scanner.Scan(); lines++ {
		if scanner.Text() == "EPHEMERAL_LIVE_POSITIVE_CONTROLS" {
			positive = true
		}
		if scanner.Text() == "OWNED_PROTECTION_ADMITTED" {
			reached = true
			break
		}
	}
	if !reached || child.Process.Kill() != nil {
		_ = child.Wait()
		t.Fatal("actual admitted-owner checkpoint not reached")
	}
	_ = child.Wait()
	if ephemeral && !t.Run("live_permission_positive_controls", func(t *testing.T) {
		if !positive {
			t.Fatal("live ephemeral permission was not exercised before kill")
		}
	}) {
		return
	}
	status, ok := child.ProcessState.Sys().(syscall.WaitStatus)
	if !t.Run("actual_sigkill", func(t *testing.T) {
		if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
			t.Fatal("admitted owner actual SIGKILL not confirmed")
		}
	}) {
		return
	}
	store := realBootStore(t, directory)
	defer store.Close()
	pf, err := store.readPF(pfJournalFile)
	journal, journalErr := store.read(journalFile)
	if err != nil || pf == nil || pf.PID != child.Process.Pid || pf.Phase != PFActive || pf.RulesSHA256 == pfDigest(stagedPFRule) ||
		journalErr != nil || journal == nil || journal.PID != child.Process.Pid {
		t.Fatal("admitted owner did not leave the expected live policy and vanished TUN")
	}
	cleaned := false
	defer func() {
		if !cleaned {
			cleanup, stop := context.WithTimeout(context.Background(), 40*time.Second)
			defer stop()
			if admittedLifetimeCleanup(t, cleanup, store, *pf) != nil {
				t.Error("controlled admitted lifetime cleanup retained evidence")
				return
			}
		}
		// A live replacement can reuse BOTH old name and index. Its later
		// closure, not tuple equality, permits retiring this child's metadata.
		deadline := time.Now().Add(3 * time.Second)
		for !admittedInterfaceNameAbsent(journal.Interface) && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
		}
		if !admittedInterfaceNameAbsent(journal.Interface) || store.reconcile() != nil {
			t.Error("admitted lifetime metadata retained after replacement closure")
		}
	}()
	deadline := time.Now().Add(3 * time.Second)
	for !admittedInterfaceNameAbsent(journal.Interface) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	oldNameAbsent := admittedInterfaceNameAbsent(journal.Interface)
	if !oldNameAbsent {
		t.Fatal("original tunnel name did not disappear after actual owner death")
	}
	replacement, err := tun.CreateTUN(journal.Interface, 1280)
	if err != nil {
		t.Fatal("controlled same-name TUN replacement failed")
	}
	defer replacement.Close()
	iface := admittedLifetimeSetup(t, replacement)
	if ephemeral && !t.Run("replacement_has_no_skip", func(t *testing.T) {
		fd, err := openPFReferences(ctx)
		if err != nil {
			t.Fatal("replacement PF interface descriptor unavailable")
		}
		defer unix.Close(fd)
		observed, err := fixtureReadPFInterface(ctx, fd, iface.Name)
		if err != nil || observed != (fixturePFInterface{0, 0, 1}) {
			t.Fatalf("replacement inherited skip or PF references: observation=%+v error=%v", observed, err)
		}
	}) {
		return
	}
	if !t.Run("replacement_instance_after_absence", func(t *testing.T) {
		if !oldNameAbsent || iface.Name != journal.Interface {
			t.Fatalf("replacement identity refused: old_name_absent=%t same_name=%t same_index=%t", oldNameAbsent, iface.Name == journal.Interface, iface.Index == journal.InterfaceIndex)
		}
		measurement := "index_changed"
		if iface.Index == journal.InterfaceIndex {
			measurement = "index_reused"
		}
		t.Run(measurement, func(t *testing.T) {})
	}) {
		return
	}
	endpointFixedCommand(t, "/sbin/route", "-n", "add", "-inet", "-host", pfPacketServer4, "-interface", iface.Name)
	endpointFixedCommand(t, "/sbin/route", "-n", "add", "-inet6", "-host", pfPacketServer6, "-interface", iface.Name)
	if !t.Run("dead_owner_policy_retained", func(t *testing.T) {
		policy, err := readPFPolicy(ctx, pf.Anchor, true)
		reference, refErr := selectPFReference(*pf, fixturePFReferences(t, ctx))
		if err != nil || !policy.matches(*pf) || policy.rules != pf.RulesSHA256 || refErr != nil || reference == nil {
			t.Fatal("admitted policy/reference was not retained after owner death and interface replacement")
		}
	}) {
		return
	}
	peer, stack, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(pfPacketServer4), netip.MustParseAddr(pfPacketServer6)}, nil, 1280)
	if err != nil {
		t.Fatal("replacement isolated peer unavailable")
	}
	done := make(chan struct{}, 2)
	capture := &pfPacketObservation{counts: make(map[pfPacketKey]int)}
	go pfPacketBridge(replacement, peer, capture, done)
	go pfPacketBridge(peer, replacement, nil, done)
	var datagrams []net.PacketConn
	var listeners []net.Listener
	defer func() {
		for _, connection := range datagrams {
			_ = connection.Close()
		}
		for _, listener := range listeners {
			_ = listener.Close()
		}
		_ = replacement.Close()
		_ = peer.Close()
		for i := 0; i < 2; i++ {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("replacement bridge did not join")
			}
		}
	}()
	for _, address := range []string{pfPacketServer4, pfPacketServer6} {
		endpoint := netip.AddrPortFrom(netip.MustParseAddr(address), 45121)
		udp, err := stack.ListenUDPAddrPort(endpoint)
		if err != nil {
			t.Fatal("replacement UDP responder unavailable")
		}
		datagrams = append(datagrams, udp)
		go pfServeUDPEcho(udp, false)
		tcp, err := stack.ListenTCPAddrPort(endpoint)
		if err != nil {
			t.Fatal("replacement TCP responder unavailable")
		}
		listeners = append(listeners, tcp)
		go pfServeTCPEcho(tcp, false)
	}
	ordinary := make(map[int]*pfNonrootPacketSession)
	for _, family := range []int{4, 6} {
		ordinary[family] = pfStartNonrootPacketSession(t, ctx, iface, capture, family)
	}
	var inherited [6]bool
	for i, family := range []int{4, 6} {
		source, destination := "198.18.99.129", pfPacketServer4
		if family == 6 {
			source, destination = "fd00:198:18:99::129", pfPacketServer6
		}
		for j, protocol := range []int{17, 6} {
			key := pfPacketKey{family, protocol, 45121}
			before := capture.count(key)
			reply := pfEncryptedEcho(ctx, iface, family, protocol, 45121, source, destination, 650*time.Millisecond)
			time.Sleep(100 * time.Millisecond)
			inherited[2*i+j] = reply || capture.count(key) != before
		}
		session := ordinary[family]
		before := capture.count(pfPacketKey{family, 17, 45121})
		if _, err := io.WriteString(session.input, "PROBE\n"); err != nil {
			t.Fatal("ordinary replacement probe failed")
		}
		response := session.message(t, ctx)
		if response != "NONROOT_PACKET_REPLY" && response != "NONROOT_PACKET_NO_REPLY" {
			t.Fatal("ordinary replacement response refused")
		}
		time.Sleep(100 * time.Millisecond)
		inherited[4+i] = response == "NONROOT_PACKET_REPLY" || capture.count(pfPacketKey{family, 17, 45121}) != before
	}
	// Retire only this fixture's known stale admission under durable deny intent.
	// Production has no such dead-owner facade; do not promote fixture authority.
	next, err := pf.BeginRuleUpdate(pfDigest(stagedPFRule))
	if err != nil || store.commitOwnedPF(next) != nil || forceFixturePFPolicy(ctx, store, next, pf.RulesSHA256, pfPolicy{}) != nil || store.resolvePFPolicy(ctx) != nil {
		t.Fatal("controlled stale permission retirement failed")
	}
	t.Run("verified_deny_blocks_replacement", func(t *testing.T) {
		for _, family := range []int{4, 6} {
			ordinary[family].probe(t, ctx, false)
		}
	})
	if admittedLifetimeCleanup(t, ctx, store, *pf) != nil {
		t.Fatal("admitted owner explicit fixture recovery failed")
	}
	cleaned = true
	if !t.Run("restored_baseline_positive_controls", func(t *testing.T) {
		for _, family := range []int{4, 6} {
			ordinary[family].probe(t, ctx, true)
			source, destination := "198.18.99.129", pfPacketServer4
			if family == 6 {
				source, destination = "fd00:198:18:99::129", pfPacketServer6
			}
			for _, protocol := range []int{17, 6} {
				if !pfEncryptedEcho(ctx, iface, family, protocol, 45121, source, destination, time.Second) {
					t.Fatal("replacement baseline positive control failed")
				}
			}
		}
	}) {
		return
	}
	baseline, err := readDisabledPF(ctx, pf.Anchor)
	if err != nil || !baseline.matches(*pf) || baseline.rules != pfDigest("") || len(fixturePFReferences(t, ctx)) != 0 {
		t.Fatal("admitted lifetime final PF baseline differs")
	}
	t.Run("no_inherited_tunnel_permission", func(t *testing.T) {
		if inherited != [6]bool{} {
			t.Fatalf("admitted permission survived SIGKILL/name replacement: root4udp=%t root4tcp=%t root6udp=%t root6tcp=%t ordinary4udp=%t ordinary6udp=%t", inherited[0], inherited[1], inherited[2], inherited[3], inherited[4], inherited[5])
		}
	})
}
