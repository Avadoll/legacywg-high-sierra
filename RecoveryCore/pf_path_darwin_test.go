package recoverycore

import (
	"context"
	"net"
	"net/netip"
	"os/exec"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

type pfScopedFixture struct {
	*pfTransportFixture
	iface  *net.Interface
	policy pfPolicy
}

func newPFScopedFixture(t *testing.T) *pfScopedFixture {
	t.Helper()
	f := &pfScopedFixture{pfTransportFixture: newPFTransportFixture(t)}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	f.ctx = ctx
	t.Cleanup(cancel)
	link, err := tun.CreateTUN("utun", 1420)
	if err != nil {
		t.Fatal("scoped fixture interface creation failed")
	}
	t.Cleanup(func() {
		// Quiesce before deleting the owned interface; whole-PF cleanup is
		// already registered by the underlying fixture and runs afterwards.
		if f.bind != nil && !f.bind.detached {
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			if f.bind.Close() != nil && f.bind.reconcile(ctx) != nil {
				t.Error("scoped fixture retained ambiguous ownership")
				return
			}
			if f.bind.detach() != nil {
				t.Error("scoped fixture monitor join failed")
				return
			}
		}
		if link.Close() != nil {
			t.Error("scoped fixture interface cleanup failed")
		}
	})
	name, err := link.Name()
	if err != nil || !utunName.MatchString(name) {
		t.Fatal("scoped fixture interface identity failed")
	}
	f.command(t, "/sbin/ifconfig", name, "inet", "198.18.101.129", "198.18.101.129", "netmask", "255.255.255.255", "alias")
	f.command(t, "/sbin/ifconfig", name, "up")
	f.iface, err = net.InterfaceByName(name)
	if err != nil {
		t.Fatal("scoped fixture interface index failed")
	}
	f.command(t, "/sbin/route", "-n", "add", "-inet", "-host", "198.18.101.130", "-interface", name)
	f.route(t, "add")
	f.policy = pfPolicy{escapes: []pfUDPEscape{{path: pfInterface{name, f.iface.Index}, source: netip.MustParseAddr("198.18.101.129"), endpoint: netip.MustParseAddrPort("198.18.101.130:45121"), sourcePort: 1}}}
	f.attachScoped(t)
	return f
}

func (f *pfScopedFixture) command(t *testing.T, program string, args ...string) {
	t.Helper()
	cmd := exec.CommandContext(f.ctx, program, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}
	if cmd.Run() != nil {
		t.Fatal("fixed scoped fixture operation failed")
	}
}

func (f *pfScopedFixture) route(t *testing.T, operation string) {
	t.Helper()
	f.command(t, "/sbin/route", "-n", operation, "-inet", "-host", "198.18.101.130", "-interface", f.iface.Name, "-ifscope", f.iface.Name)
}

func (f *pfScopedFixture) attachScoped(t *testing.T) {
	t.Helper()
	bind, err := newPFScopedGuardBind(f.ctx, f.store, f.policy)
	if err != nil {
		t.Fatal("scoped fixture admission failed")
	}
	f.bind = bind
}

func pfAwaitScopedRevocation(t *testing.T, bind *pfGuardBind) {
	t.Helper()
	select {
	case <-bind.scoped.done:
	case <-time.After(25 * time.Second):
		t.Fatal("scoped automatic revocation did not finish")
	}
	if !bind.scoped.lost.Load() || bind.scoped.err != nil || bind.current.Load() != nil || bind.retained {
		t.Fatal("scoped automatic revocation left a live or ambiguous lease")
	}
}

func TestRootPFRuleScopedGuardLossAfterConfirmedAdmission(t *testing.T) {
	f := newPFScopedFixture(t)
	var port uint16
	f.bind.openSocket = func(path pfInterface, source netip.Addr, requested uint16) (pfDatagram, error) {
		socket, err := openPFDatagram(path, source, requested)
		if err == nil {
			port = uint16(socket.LocalAddr().(*net.UDPAddr).Port)
		}
		return socket, err
	}
	loaded := false
	f.store.checkpoint = func(point string) {
		if point == "pf_rule_update_confirmation_committed" {
			f.store.checkpoint = nil
			loaded = true
			f.route(t, "delete")
		}
	}
	callbacks, exposedPort, err := f.bind.Open(0)
	if err == nil || callbacks != nil || exposedPort != 0 || !loaded || port == 0 {
		t.Fatal("post-confirmation route loss exposed a usable socket lifetime")
	}
	pfAwaitScopedRevocation(t, f.bind)
	pfTransportDenyOnly(t, f.ctx, f.store, f.initial)
	pfTransportPortFree(t, f.bind.paths, port)
	f.route(t, "add")
	if _, _, err := f.bind.Open(port); err == nil {
		t.Fatal("route restoration revived a lost admission")
	}
	if f.bind.detach() != nil {
		t.Fatal("lost monitor detachment failed")
	}
	f.attachScoped(t)
	if _, _, err := f.bind.Open(port); err != nil || f.bind.Close() != nil {
		t.Fatal("fresh scoped lifetime refused the restored route")
	}
	if f.bind.detach() != nil {
		t.Fatal("healthy idle monitor did not join")
	}
}

func TestRootPFRuleScopedGuardLossDuringSocketOpen(t *testing.T) {
	f := newPFScopedFixture(t)
	opened := make(chan uint16, 1)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	f.bind.openSocket = func(path pfInterface, source netip.Addr, requested uint16) (pfDatagram, error) {
		socket, err := openPFDatagram(path, source, requested)
		if err != nil {
			return nil, err
		}
		opened <- uint16(socket.LocalAddr().(*net.UDPAddr).Port)
		<-release
		return socket, nil
	}
	type result struct {
		err    error
		usable bool
	}
	finished := make(chan result, 1)
	go func() { callbacks, port, err := f.bind.Open(0); finished <- result{err, callbacks != nil || port != 0} }()
	var port uint16
	select {
	case port = <-opened:
	case <-time.After(4 * time.Second):
		t.Fatal("scoped native socket was not opened")
	}
	f.route(t, "delete")
	select {
	case <-f.bind.scoped.loss:
	case <-time.After(4 * time.Second):
		t.Fatal("scoped loss was not latched during socket creation")
	}
	unblock()
	select {
	case outcome := <-finished:
		if outcome.err == nil || outcome.usable {
			t.Fatal("lost partial socket became usable")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("partial socket admission did not exit")
	}
	pfAwaitScopedRevocation(t, f.bind)
	record := pfTransportDenyOnly(t, f.ctx, f.store, f.initial)
	if record.Generation != f.initial.Generation {
		t.Fatal("unadmitted socket changed the PF generation")
	}
	pfTransportPortFree(t, f.bind.paths, port)
	f.route(t, "add")
	if _, _, err := f.bind.Open(port); err == nil {
		t.Fatal("restored partial admission reopened")
	}
	if f.bind.detach() != nil {
		t.Fatal("partial admission monitor did not join")
	}
}
