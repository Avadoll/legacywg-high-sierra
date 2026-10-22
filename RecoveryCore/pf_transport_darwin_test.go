package recoverycore

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"
	"weak"

	"golang.zx2c4.com/wireguard/conn"
)

// Each fixture owns a real enabled PF anchor and real loopback UDP sockets.
// Cleanup must retire the transport before whole-guard recovery or Store.Close:
// losing either the port or the journal lock while an escape remains is unsafe.
type pfTransportFixture struct {
	store   *Store
	bind    *pfGuardBind
	ctx     context.Context
	initial PFRecord
	path    string
}

func newPFTransportFixture(t *testing.T) *pfTransportFixture {
	t.Helper()
	requirePFRuleCI(t)
	fixture := &pfTransportFixture{path: ownedReferenceTestDirectory(t)}
	fixture.store = realBootStore(t, fixture.path)
	ctx, cancel := context.WithTimeout(context.Background(), 65*time.Second)
	fixture.ctx = ctx
	t.Cleanup(func() {
		cancel()
		fixture.store.checkpoint = nil
		cleanup, stop := context.WithTimeout(context.Background(), 25*time.Second)
		defer stop()
		if fixture.bind != nil && !fixture.bind.detached {
			if fixture.bind.Close() != nil && fixture.bind.reconcile(cleanup) != nil {
				t.Error("transport cleanup retained ambiguous socket and PF evidence")
				return
			}
			if fixture.bind.detach() != nil {
				t.Error("transport cleanup could not release its store pin")
				return
			}
		}
		if fixture.store.pfResidue() && fixture.store.recoverPFLifecycle(cleanup) != nil {
			t.Error("transport cleanup retained owned PF evidence")
			return
		}
		fixture.store.Close()
	})
	if fixture.store.stageDisabledPFAnchor(ctx) != nil || fixture.store.activatePFAnchor(ctx) != nil {
		t.Fatal("transport guard activation failed")
	}
	record, err := fixture.store.readPF(pfJournalFile)
	if err != nil || record == nil || record.Phase != PFActive {
		t.Fatal("transport initial guard identity unavailable")
	}
	fixture.initial = *record
	return fixture
}

func (fixture *pfTransportFixture) attach(t *testing.T, ctx context.Context) *pfGuardBind {
	t.Helper()
	bind, err := newPFGuardBind(ctx, fixture.store, fixturePFUDPPolicy(t))
	if err != nil || bind == nil {
		t.Fatal("transport could not acquire the active deny-only guard")
	}
	fixture.bind = bind
	return bind
}

func pfTransportPortOwned(t *testing.T, paths []pfUDPEscape, port uint16) {
	t.Helper()
	if port == 0 {
		t.Fatal("transport did not reserve an actual port")
	}
	for _, path := range paths {
		other, err := openPFDatagram(path.path, path.source, port)
		if err == nil || other != nil {
			if other != nil {
				_ = other.Close()
			}
			t.Fatal("transport surrendered an admitted source port")
		}
	}
}

func pfTransportPortFree(t *testing.T, paths []pfUDPEscape, port uint16) {
	t.Helper()
	for _, path := range paths {
		other, err := openPFDatagram(path.path, path.source, port)
		if err != nil || other == nil {
			t.Fatal("revoked transport source port remained unavailable")
		}
		if other.Close() != nil {
			t.Fatal("port availability probe cleanup failed")
		}
	}
}

func pfTransportDenyOnly(t *testing.T, ctx context.Context, store *Store, initial PFRecord) PFRecord {
	t.Helper()
	record, err := store.readPF(pfJournalFile)
	actual, nativeErr := readPFPolicy(ctx, initial.Anchor, true)
	if err != nil || record == nil || record.Phase != PFActive || record.NextRulesSHA256 != "" || record.RulesSHA256 != initial.RulesSHA256 || record.ID != initial.ID || record.Reference != initial.Reference || nativeErr != nil || !actual.matches(initial) || actual.rules != initial.RulesSHA256 {
		t.Fatal("transport did not preserve an enabled, confirmed deny-only guard")
	}
	return *record
}

func pfTransportOldReceiveClosed(t *testing.T, receive conn.ReceiveFunc) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		_, err := receive([][]byte{make([]byte, 64)}, make([]int, 1), make([]conn.Endpoint, 1))
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal("retired receive callback did not report closed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("retired receive callback blocked after socket generation changed")
	}
}

// Inspect the actual live policy immediately before releasing each native fd.
// This checks the externally significant ordering, including both families,
// rather than merely examining controller bookkeeping after Close returns.
type pfTransportObservedSocket struct {
	pfDatagram
	beforeClose func()
}

func (socket *pfTransportObservedSocket) Close() error {
	socket.beforeClose()
	return socket.pfDatagram.Close()
}

func TestRootPFRuleGuardTransportCloseReopenAndStorePin(t *testing.T) {
	fixture := newPFTransportFixture(t)
	bind := fixture.attach(t, fixture.ctx)
	closedSockets := 0
	bind.openSocket = func(path pfInterface, source netip.Addr, port uint16) (pfDatagram, error) {
		socket, err := openPFDatagram(path, source, port)
		if err != nil {
			return nil, err
		}
		return &pfTransportObservedSocket{socket, func() {
			pfTransportDenyOnly(t, fixture.ctx, fixture.store, fixture.initial)
			closedSockets++
		}}, nil
	}
	receivers, port, err := bind.Open(0)
	if err != nil || len(receivers) != 2 || port == 0 {
		t.Fatal("dual-family guarded socket admission failed")
	}
	pfTransportPortOwned(t, bind.paths, port)
	active, err := fixture.store.readPF(pfJournalFile)
	if err != nil || active == nil || active.Phase != PFActive || active.RulesSHA256 == fixture.initial.RulesSHA256 {
		t.Fatal("actual socket policy did not replace deny-only")
	}
	fixture.store.Close()
	if fixture.store.closed {
		t.Fatal("Store.Close abandoned an attached transport")
	}
	if duplicate, err := directoryStore(t, fixture.path); err == nil {
		duplicate.Close()
		t.Fatal("attached transport lost its exclusive journal lock")
	}
	if fixture.store.updatePFPolicy(fixture.ctx, pfPolicy{}) == nil || fixture.store.resolvePFPolicy(fixture.ctx) == nil || fixture.store.recoverPFLifecycle(fixture.ctx) == nil || bind.detach() == nil {
		t.Fatal("ordinary PF control bypassed the live transport pin")
	}
	unchanged, err := fixture.store.readPF(pfJournalFile)
	if err != nil || unchanged == nil || *unchanged != *active {
		t.Fatal("refused competing control changed the transport journal")
	}
	if _, _, err := bind.Open(0); !errors.Is(err, conn.ErrBindAlreadyOpen) {
		t.Fatal("already-open transport admitted another socket generation")
	}
	// A native receive is pending when Close retires the lease. Deadlines must
	// wake it without releasing the fd before the PF revocation is confirmed.
	waiting := make(chan error, 1)
	go func() {
		_, err := receivers[0]([][]byte{make([]byte, 64)}, make([]int, 1), make([]conn.Endpoint, 1))
		waiting <- err
	}()
	select {
	case <-waiting:
		t.Fatal("empty native receive was not pending")
	case <-time.After(30 * time.Millisecond):
	}
	if bind.Close() != nil {
		t.Fatal("automatic transport close failed")
	}
	select {
	case err := <-waiting:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal("retired native receive returned a live result")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("transport close did not interrupt native receive")
	}
	pfTransportDenyOnly(t, fixture.ctx, fixture.store, fixture.initial)
	if closedSockets != 2 {
		t.Fatal("automatic close did not retire both native sockets")
	}
	fixture.store.Close()
	if fixture.store.closed || fixture.store.recoverPFLifecycle(fixture.ctx) == nil || fixture.store.updatePFPolicy(fixture.ctx, pfPolicy{}) == nil {
		t.Fatal("closed but attached transport lost its store pin")
	}
	pfTransportPortFree(t, bind.paths, port)
	if bind.Send([][]byte{{1}}, &conn.StdNetEndpoint{AddrPort: bind.policy.escapes[0].endpoint}) != net.ErrClosed {
		t.Fatal("closed transport accepted a packet")
	}
	next, reopenedPort, err := bind.Open(port)
	if err != nil || len(next) != 2 || reopenedPort != port {
		t.Fatal("transport could not admit a fresh socket generation")
	}
	for _, receive := range receivers {
		pfTransportOldReceiveClosed(t, receive)
	}
	pfTransportPortOwned(t, bind.paths, port)
	if bind.Close() != nil || bind.detach() != nil {
		t.Fatal("reopened transport could not close and detach")
	}
	if _, _, err := bind.Open(port); err == nil {
		t.Fatal("detached transport reopened sockets")
	}
	fresh := fixture.attach(t, fixture.ctx)
	if _, freshPort, err := fresh.Open(port); err != nil || freshPort != port {
		t.Fatal("fresh transport could not acquire the released guard and port")
	}
	for _, receive := range next {
		pfTransportOldReceiveClosed(t, receive)
	}
	if fresh.Close() != nil {
		t.Fatal("fresh transport cleanup failed")
	}
	pfTransportDenyOnly(t, fixture.ctx, fixture.store, fixture.initial)
}

func TestRootPFRuleGuardTransportCanceledAdmissionRetainsPorts(t *testing.T) {
	fixture := newPFTransportFixture(t)
	admission, cancel := context.WithCancel(fixture.ctx)
	defer cancel()
	bind := fixture.attach(t, admission)
	loaded := false
	fixture.store.checkpoint = func(point string) {
		if point == "pf_rule_update_loaded_kernel" {
			loaded = true
			cancel()
		}
	}
	if receivers, port, err := bind.Open(0); err == nil || receivers != nil || port != 0 || !loaded {
		t.Fatal("canceled post-load admission exposed usable callbacks")
	}
	fixture.store.checkpoint = nil
	lease := bind.current.Load()
	if lease == nil {
		t.Fatal("failed post-load admission lost its socket lease")
	}
	pfTransportPortOwned(t, bind.paths, lease.port)
	pending, err := fixture.store.readPF(pfJournalFile)
	actual, nativeErr := readPFPolicy(fixture.ctx, fixture.initial.Anchor, true)
	if err != nil || pending == nil || pending.Phase != PFRuleUpdateIntent || pending.NextRulesSHA256 == "" || nativeErr != nil || actual.rules != pending.NextRulesSHA256 {
		t.Fatal("canceled loaded policy lost its unresolved durable intent")
	}
	if bind.Close() == nil || bind.detach() == nil || fixture.store.recoverPFLifecycle(fixture.ctx) == nil || fixture.store.resolvePFPolicy(fixture.ctx) == nil {
		t.Fatal("unresolved admission surrendered transport ownership")
	}
	fixture.store.Close()
	if fixture.store.closed {
		t.Fatal("Store.Close abandoned ambiguous transport ports")
	}
	if err := bind.Send([][]byte{{1}}, &conn.StdNetEndpoint{AddrPort: bind.policy.escapes[0].endpoint}); !errors.Is(err, net.ErrClosed) {
		t.Fatal("unconfirmed admission could transmit")
	}
	pfTransportPortOwned(t, bind.paths, lease.port)
	if bind.reconcile(fixture.ctx) != nil {
		t.Fatal("explicit transport reconciliation failed")
	}
	confirmed := pfTransportDenyOnly(t, fixture.ctx, fixture.store, fixture.initial)
	if confirmed.Generation != fixture.initial.Generation+2 {
		t.Fatal("reconciliation did not confirm then revoke the loaded generation")
	}
	pfTransportPortFree(t, bind.paths, lease.port)
	if _, _, err := bind.Open(lease.port); err == nil {
		t.Fatal("canceled admission context authorized a new socket")
	}
	if bind.detach() != nil {
		t.Fatal("reconciled transport could not detach")
	}
	fresh := fixture.attach(t, fixture.ctx)
	if _, _, err := fresh.Open(lease.port); err != nil {
		t.Fatal("fresh admission after explicit reconciliation failed")
	}
	if fresh.Close() != nil {
		t.Fatal("fresh reconciled transport close failed")
	}
}

func TestRootPFRuleGuardTransportThirdHashRetainsPorts(t *testing.T) {
	fixture := newPFTransportFixture(t)
	bind := fixture.attach(t, fixture.ctx)
	receivers, port, err := bind.Open(0)
	if err != nil || len(receivers) != 2 {
		t.Fatal("third-hash transport admission failed")
	}
	active, err := fixture.store.readPF(pfJournalFile)
	if err != nil || active == nil {
		t.Fatal("third-hash active identity missing")
	}
	third := pfPolicy{loopback: true}
	_, thirdRules, err := fixture.store.preparePFPolicy(fixture.ctx, *active, third)
	if err != nil {
		t.Fatal("controlled third policy unavailable")
	}
	thirdHash := pfDigest(thirdRules)
	if forceFixturePFPolicy(fixture.ctx, fixture.store, *active, active.RulesSHA256, third) != nil {
		t.Fatal("test-only third policy replacement failed")
	}
	// If an assertion below fails, restore only this known test-injected policy,
	// before the shared finalizer attempts transport reconciliation.
	restored := false
	defer func() {
		if restored {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		policy, _ := bind.policy.frozen()
		for i := range policy.escapes {
			policy.escapes[i].sourcePort = port
		}
		if forceFixturePFPolicy(ctx, fixture.store, *active, thirdHash, policy) != nil {
			t.Error("controlled third policy could not be restored; evidence retained")
		}
	}()
	if bind.Close() == nil || bind.reconcile(fixture.ctx) == nil {
		t.Fatal("unknown live policy permitted transport revocation")
	}
	pfTransportPortOwned(t, bind.paths, port)
	for _, receive := range receivers {
		pfTransportOldReceiveClosed(t, receive)
	}
	after, err := fixture.store.readPF(pfJournalFile)
	actual, nativeErr := readPFPolicy(fixture.ctx, active.Anchor, true)
	if err != nil || after == nil || *after != *active || nativeErr != nil || actual.rules != thirdHash {
		t.Fatal("third policy refusal mutated journal or overwritten unknown rules")
	}
	policy, _ := bind.policy.frozen()
	for i := range policy.escapes {
		policy.escapes[i].sourcePort = port
	}
	if forceFixturePFPolicy(fixture.ctx, fixture.store, *active, thirdHash, policy) != nil {
		t.Fatal("controlled active policy restoration failed")
	}
	restored = true
	if bind.reconcile(fixture.ctx) != nil {
		t.Fatal("transport could not reconcile after exact known policy restoration")
	}
	pfTransportDenyOnly(t, fixture.ctx, fixture.store, fixture.initial)
	pfTransportPortFree(t, bind.paths, port)
}

// The cleanup captures only a weak pointer. All construction locals disappear
// on return, so the controller's explicit global pin must keep the descriptors
// alive even when its caller forgets the failed Open result entirely.
func pfTransportWeakRetainedFixture(t *testing.T) (weak.Pointer[pfGuardBind], []pfUDPEscape, uint16, PFRecord) {
	t.Helper()
	store := realBootStore(t, ownedReferenceTestDirectory(t))
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if store.stageDisabledPFAnchor(ctx) != nil || store.activatePFAnchor(ctx) != nil {
		store.Close()
		t.Fatal("GC retention fixture activation failed")
	}
	initial, err := store.readPF(pfJournalFile)
	if err != nil || initial == nil {
		store.Close()
		t.Fatal("GC retention initial identity missing")
	}
	admission, stop := context.WithCancel(ctx)
	defer stop()
	bind, err := newPFGuardBind(admission, store, fixturePFUDPPolicy(t))
	if err != nil {
		store.Close()
		t.Fatal("GC retention guard attachment failed")
	}
	handle := weak.Make(bind)
	t.Cleanup(func() {
		live := handle.Value()
		if live == nil {
			t.Error("retained transport became unreachable before explicit cleanup")
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		live.store.checkpoint = nil
		if live.Close() != nil && live.reconcile(ctx) != nil {
			t.Error("GC retention explicit reconciliation failed")
			return
		}
		if live.detach() != nil {
			t.Error("GC retention detach failed")
			return
		}
		if live.store.recoverPFLifecycle(ctx) != nil {
			t.Error("GC retention owned recovery failed")
			return
		}
		live.store.Close()
	})
	loaded := false
	store.checkpoint = func(point string) {
		if point == "pf_rule_update_loaded_kernel" {
			loaded = true
			stop()
		}
	}
	_, _, openErr := bind.Open(0)
	store.checkpoint = nil
	lease := bind.current.Load()
	if openErr == nil || !loaded || lease == nil {
		t.Fatal("GC retention did not produce a post-load retained socket")
	}
	return handle, append([]pfUDPEscape(nil), bind.paths...), lease.port, *initial
}

func TestRootPFRuleGuardTransportGarbageCollectionRetainsPorts(t *testing.T) {
	requirePFRuleCI(t)
	handle, paths, port, initial := pfTransportWeakRetainedFixture(t)
	// A Store/Bind cycle alone is collectible. No test variable or finalizer
	// closure holds either object strongly until after these collections.
	runtime.GC()
	runtime.GC()
	live := handle.Value()
	if live == nil {
		t.Fatal("GC collected an unresolved transport and its live socket leases")
	}
	pfTransportPortOwned(t, paths, port)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if live.reconcile(ctx) != nil {
		t.Fatal("GC-retained transport could not reconcile explicitly")
	}
	pfTransportDenyOnly(t, ctx, live.store, initial)
	pfTransportPortFree(t, paths, port)
	// Leave detach and whole-guard cleanup to the weak-pointer-only finalizer.
	runtime.KeepAlive(live)
}

// This models an otherwise unbounded syscall while respecting the write
// deadline installed by the transport. The real native port tests above prove
// descriptor retention; this fixture separately exercises the device RLock
// shutdown ordering that prevents Close from being called until Send returns.
type pfTransportStalledDatagram struct {
	mutex    sync.Mutex
	deadline time.Time
	started  chan struct{}
	once     sync.Once
}

func (socket *pfTransportStalledDatagram) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 45120}
}
func (socket *pfTransportStalledDatagram) Close() error { return nil }
func (socket *pfTransportStalledDatagram) SetDeadline(deadline time.Time) error {
	return socket.SetWriteDeadline(deadline)
}
func (socket *pfTransportStalledDatagram) SetWriteDeadline(deadline time.Time) error {
	socket.mutex.Lock()
	socket.deadline = deadline
	socket.mutex.Unlock()
	return nil
}
func (socket *pfTransportStalledDatagram) ReadFromUDPAddrPort([]byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, net.ErrClosed
}
func (socket *pfTransportStalledDatagram) WriteMsgUDPAddrPort([]byte, []byte, netip.AddrPort) (int, int, error) {
	socket.mutex.Lock()
	deadline := socket.deadline
	socket.mutex.Unlock()
	socket.once.Do(func() { close(socket.started) })
	if deadline.IsZero() {
		return 0, 0, errors.New("write deadline missing")
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	<-timer.C
	return 0, 0, os.ErrDeadlineExceeded
}

func TestRootPFRuleGuardTransportBoundedWriteShutdown(t *testing.T) {
	socket := &pfTransportStalledDatagram{started: make(chan struct{})}
	writers := make(chan struct{}, 1)
	writers <- struct{}{}
	lease := &pfGuardLease{done: make(chan struct{}), port: 45120, sockets: []pfGuardSocket{{socket, netip.MustParseAddr("127.0.0.1"), writers}}}
	lease.admitted.Store(true)
	bind := &pfGuardBind{policy: pfPolicy{escapes: []pfUDPEscape{{endpoint: netip.MustParseAddrPort("127.0.0.2:53")}}}}
	bind.current.Store(lease)
	endpoint := &conn.StdNetEndpoint{AddrPort: netip.MustParseAddrPort("127.0.0.2:53")}
	var deviceNet sync.RWMutex
	done := make(chan error, 2)
	entered := make(chan struct{}, 2)
	send := func() {
		deviceNet.RLock()
		defer deviceNet.RUnlock()
		entered <- struct{}{}
		done <- bind.Send([][]byte{{1}}, endpoint)
	}
	go send()
	<-entered
	select {
	case <-socket.started:
	case <-time.After(2 * time.Second):
		t.Fatal("guarded send never entered bounded socket write")
	}
	go send()
	<-entered
	shutdown := make(chan struct{})
	go func() { deviceNet.Lock(); defer deviceNet.Unlock(); _ = lease.retire(); close(shutdown) }()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for completed := 0; completed < 2; completed++ {
		select {
		case err := <-done:
			if !errors.Is(err, os.ErrDeadlineExceeded) && !errors.Is(err, net.ErrClosed) {
				t.Fatal("stalled send did not honor finite shutdown deadline")
			}
		case <-deadline.C:
			t.Fatal("send held the device network lock beyond bounded shutdown")
		}
	}
	select {
	case <-shutdown:
	case <-time.After(time.Second):
		t.Fatal("device shutdown could not acquire its network lock")
	}
	if !errors.Is(bind.Send([][]byte{{1}}, endpoint), net.ErrClosed) {
		t.Fatal("retired stalled transport accepted a send")
	}
}
