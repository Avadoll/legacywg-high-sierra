package recoverycore

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	networkcore "legacywg/NetworkCore"
)

func endpointOwnedLink(t *testing.T) (*net.Interface, []networkcore.ScopedHost) {
	t.Helper()
	link, err := tun.CreateTUN("utun", 1420)
	if err != nil {
		t.Fatal("endpoint fixture interface creation failed")
	}
	t.Cleanup(func() {
		if link.Close() != nil {
			t.Error("endpoint fixture interface cleanup failed")
		}
	})
	name, err := link.Name()
	if err != nil || !utunName.MatchString(name) {
		t.Fatal("endpoint fixture identity failed")
	}
	for _, args := range [][]string{{name, "inet", "198.18.111.129", "198.18.111.129", "netmask", "255.255.255.255", "alias"}, {name, "inet6", "fd00:198:18:111::129", "prefixlen", "128", "alias"}, {name, "up"}} {
		endpointFixedCommand(t, "/sbin/ifconfig", args...)
	}
	endpointFixedCommand(t, "/sbin/route", "-n", "add", "-inet", "-net", "198.18.111.0/24", "-interface", name)
	endpointFixedCommand(t, "/sbin/route", "-n", "add", "-inet6", "-net", "fd00:198:18:111::/64", "-interface", name)
	iface, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatal("endpoint fixture index failed")
	}
	return iface, endpointFixtureHosts(t, iface.Name)
}

func endpointFixedCommand(t *testing.T, program string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, program, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}
	if cmd.Run() != nil {
		t.Fatal("fixed endpoint topology operation failed")
	}
}

func endpointFixtureHosts(t *testing.T, name string) []networkcore.ScopedHost {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	iface, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatal("endpoint fixture interface disappeared")
	}
	var hosts []networkcore.ScopedHost
	for _, text := range []string{"198.18.111.130", "fd00:198:18:111::130"} {
		dst := netip.MustParseAddr(text)
		path, err := networkcore.EndpointRoute(ctx, dst)
		if err != nil || path.InterfaceName != name || path.InterfaceIndex != iface.Index {
			t.Fatal("endpoint fixture baseline route failed")
		}
		hosts = append(hosts, networkcore.ScopedHost{Destination: dst, Path: path})
	}
	return hosts
}

func TestRootPFRuleOwnedEndpointLifecycle(t *testing.T) {
	requirePFRuleCI(t)
	_, hosts := endpointOwnedLink(t)
	f := newPFTransportFixture(t) // Cleanup routes before removing its PF guard.
	t.Cleanup(func() {
		f.store.checkpoint = nil
		if f.bind != nil && !f.bind.detached {
			_ = f.bind.Close()
			_ = f.bind.detach()
		}
		if f.store.recoverEndpointRoutes(context.Background()) != nil {
			t.Error("endpoint ownership cleanup refused")
		}
	})
	if f.store.installEndpointRoutes(f.ctx, hosts) != nil {
		t.Fatal("journal-bound dual-family host installation failed")
	}
	for _, host := range hosts {
		snapshot, err := networkcore.ScopedRoute(f.ctx, host.Destination, host.Path.InterfaceIndex)
		if err != nil || !host.Matches(snapshot) {
			t.Fatal("installed exact host differs")
		}
	}
	if f.store.recoverPFLifecycle(f.ctx) == nil || f.store.Finish() == nil {
		t.Fatal("ordinary cleanup lifted guard with route residue")
	}
	var escapes []pfUDPEscape
	for _, host := range hosts {
		source := netip.MustParseAddr("198.18.111.129")
		if host.Destination.Is6() {
			source = netip.MustParseAddr("fd00:198:18:111::129")
		}
		escapes = append(escapes, pfUDPEscape{path: pfInterface{host.Path.InterfaceName, host.Path.InterfaceIndex}, source: source, endpoint: netip.AddrPortFrom(host.Destination, 45121), sourcePort: 1})
	}
	var err error
	f.bind, err = newPFScopedGuardBind(f.ctx, f.store, pfPolicy{escapes: escapes})
	if err != nil {
		t.Fatal("owned routes not admitted by scoped guard")
	}
	if _, _, err = f.bind.Open(0); err != nil {
		t.Fatal("owned routes not admitted by native socket open")
	}
	if f.store.recoverEndpointRoutes(f.ctx) == nil {
		t.Fatal("attached sockets permitted route removal")
	}
	if f.bind.Close() != nil || f.bind.detach() != nil {
		t.Fatal("owned-route transport shutdown failed")
	}
	if f.store.recoverEndpointRoutes(f.ctx) != nil || f.store.endpointResidue() {
		t.Fatal("owned routes not removed under deny-only")
	}
	for _, host := range hosts {
		after, err := networkcore.EndpointRoute(f.ctx, host.Destination)
		if err != nil || after != host.Path {
			t.Fatal("owned host cleanup changed baseline route")
		}
	}
	// A pre-existing exact scoped host is never overwritten or claimed.
	if networkcore.ChangeScopedHost(f.ctx, hosts[0], true) != nil {
		t.Fatal("foreign-route fixture insertion failed")
	}
	if f.store.installEndpointRoutes(f.ctx, hosts) == nil || f.store.endpointResidue() {
		t.Fatal("pre-existing host was claimed or mutated")
	}
	observed, err := networkcore.ScopedRoute(f.ctx, hosts[0].Destination, hosts[0].Path.InterfaceIndex)
	if err != nil || !hosts[0].Matches(observed) || networkcore.ChangeScopedHost(f.ctx, hosts[0], false) != nil {
		t.Fatal("pre-existing host preservation failed")
	}
}

func TestRootPFRuleOwnedEndpointCrashChild(t *testing.T) {
	directory, stage, name := os.Getenv("LEGACYWG_ENDPOINT_DIR"), os.Getenv("LEGACYWG_ENDPOINT_STAGE"), os.Getenv("LEGACYWG_ENDPOINT_IFACE")
	if directory == "" || stage == "" || name == "" {
		t.Skip("separate endpoint crash child")
	}
	requirePFRuleCI(t)
	store := realBootStore(t, directory)
	defer store.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 55*time.Second)
	defer cancel()
	if store.stageDisabledPFAnchor(ctx) != nil || store.activatePFAnchor(ctx) != nil {
		t.Fatal("endpoint crash guard activation failed")
	}
	hosts := endpointFixtureHosts(t, name)[:1]
	store.checkpoint = func(point string) {
		if point == stage {
			fmt.Println("OWNED_ENDPOINT_CHECKPOINT")
			select {}
		}
	}
	if store.installEndpointRoutes(ctx, hosts) != nil {
		t.Fatal("endpoint crash installation failed before checkpoint")
	}
	if store.recoverEndpointRoutes(ctx) != nil {
		t.Fatal("endpoint crash removal failed before checkpoint")
	}
	t.Fatal("endpoint crash checkpoint not reached")
}

func TestRootPFRuleOwnedEndpointCrashRecovery(t *testing.T) {
	requirePFRuleCI(t)
	iface, hosts := endpointOwnedLink(t)
	for _, stage := range []string{"endpoint_plan_committed", "endpoint_add_intent_committed", "endpoint_added_kernel", "endpoint_installed_committed", "endpoint_deleted_kernel"} {
		t.Run(stage, func(t *testing.T) {
			path := ownedReferenceTestDirectory(t)
			ctx, cancel := context.WithTimeout(context.Background(), 65*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRootPFRuleOwnedEndpointCrashChild$", "-test.v")
			child.Env = append(os.Environ(), "LEGACYWG_ENDPOINT_DIR="+path, "LEGACYWG_ENDPOINT_STAGE="+stage, "LEGACYWG_ENDPOINT_IFACE="+iface.Name)
			pipe, err := child.StdoutPipe()
			if err != nil || child.Start() != nil {
				t.Fatal("endpoint crash child did not start")
			}
			defer func() { _ = child.Process.Kill() }()
			scanner := bufio.NewScanner(pipe)
			reached := false
			for scanner.Scan() {
				if scanner.Text() == "OWNED_ENDPOINT_CHECKPOINT" {
					reached = true
					break
				}
			}
			if !reached || child.Process.Kill() != nil {
				_ = child.Wait()
				t.Fatal("endpoint crash checkpoint not reached")
			}
			_ = child.Wait()
			status, ok := child.ProcessState.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatal("endpoint child did not actually die from SIGKILL")
			}
			store := realBootStore(t, path)
			defer store.Close()
			record, err := store.readEndpointRoutes(endpointJournalFile)
			if err != nil || record == nil || record.PID != child.Process.Pid || len(record.Routes) != 1 {
				t.Fatal("endpoint crash durable identity missing")
			}
			if store.recoverPFLifecycle(ctx) == nil {
				t.Fatal("crashed endpoint owner allowed PF release")
			}
			if stage == "endpoint_added_kernel" {
				before, err := networkcore.ScopedRoute(ctx, hosts[0].Destination, hosts[0].Path.InterfaceIndex)
				if err != nil || !hosts[0].Matches(before) || store.recoverEndpointRoutes(ctx) == nil {
					t.Fatal("uncertain addition was claimed by tuple equality")
				}
				after, err := networkcore.ScopedRoute(ctx, hosts[0].Destination, hosts[0].Path.InterfaceIndex)
				retained, readErr := store.readEndpointRoutes(endpointJournalFile)
				if err != nil || after != before || readErr != nil || retained == nil || retained.Routes[0].Phase != endpointAddIntent {
					t.Fatal("uncertain addition was changed during refusal")
				}
				// Test-only authority: the parent owns this interface and observed
				// its child reach the post-ack checkpoint. Production lacks this
				// evidence and never performs this forced uncertain cleanup.
				if networkcore.ChangeScopedHost(ctx, hosts[0], false) != nil {
					t.Fatal("controlled uncertain fixture cleanup failed")
				}
			}
			if store.recoverEndpointRoutes(ctx) != nil || store.endpointResidue() {
				t.Fatal("endpoint crash recovery failed")
			}
			if store.recoverEndpointRoutes(ctx) != nil {
				t.Fatal("endpoint recovery not idempotent")
			}
			pf, err := store.readPF(pfJournalFile)
			if err != nil || pf == nil || store.recoverPFLifecycle(ctx) != nil || store.pfResidue() || len(fixturePFReferences(t, ctx)) != 0 {
				t.Fatal("endpoint crash PF baseline restoration failed")
			}
			baseline, err := readDisabledPF(ctx, pf.Anchor)
			if err != nil || !baseline.matches(*pf) || baseline.rules != pfDigest("") {
				t.Fatal("endpoint crash foreign PF baseline changed")
			}
			after, err := networkcore.EndpointRoute(ctx, hosts[0].Destination)
			if err != nil || after != hosts[0].Path {
				t.Fatal("endpoint crash route baseline changed")
			}
		})
	}
}
