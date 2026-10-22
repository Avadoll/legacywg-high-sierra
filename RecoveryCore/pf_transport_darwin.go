package recoverycore

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// Private guard transport. No installed request constructs one yet: physical
// scoped path/route lifetime and full protected session admission remain gates.
// Official WireGuard device/crypto are unchanged. Numeric endpoint updates need
// a new explicit admission; this transport does not open a roaming exception.
type pfGuardBind struct {
	op         sync.Mutex
	current    atomic.Pointer[pfGuardLease]
	store      *Store
	identity   PFRecord
	admission  context.Context
	policy     pfPolicy
	paths      []pfUDPEscape // One source/interface per family, no wildcard socket.
	generation uint64
	retained   bool
	detached   bool
	detaching  bool
	scoped     *pfScopedAdmission
	openSocket func(pfInterface, netip.Addr, uint16) (pfDatagram, error)
}

type pfGuardSocket struct {
	fd      pfDatagram
	source  netip.Addr
	writers chan struct{}
}

type pfGuardLease struct {
	control    sync.Mutex // Retirement and write deadlines only, never blocking I/O.
	retired    atomic.Bool
	admitted   atomic.Bool
	done       chan struct{}
	port       uint16
	generation uint64
	sockets    []pfGuardSocket // Immutable after publication, including after close.
}

var _ conn.Bind = (*pfGuardBind)(nil)

// Store↔Bind references alone form a collectible cycle. Keep a process root
// until explicit detachment so UDPConn finalizers cannot release retained
// ports while an unconfirmed exception may remain in the kernel. The fixed
// production store flock limits ownership; this private map is not a user API.
var pfPinnedTransports sync.Map

func newPFGuardBind(ctx context.Context, store *Store, template pfPolicy) (*pfGuardBind, error) {
	if ctx == nil || ctx.Err() != nil || store == nil || len(template.escapes) == 0 {
		return nil, ErrRecoveryRequired
	}
	policy, err := template.frozen()
	if err != nil || policy.loopback {
		return nil, ErrRecoveryRequired
	}
	bind := &pfGuardBind{store: store, admission: ctx, policy: policy, openSocket: openPFDatagram}
	for _, escape := range policy.escapes {
		found := false
		for _, path := range bind.paths {
			if path.source.Is4() == escape.source.Is4() {
				if path.path != escape.path || path.source != escape.source {
					return nil, ErrRecoveryRequired
				}
				found = true
			}
		}
		if !found {
			bind.paths = append(bind.paths, escape)
		}
	}
	store.mutex.Lock()
	defer store.mutex.Unlock()
	record, err := store.readPF(pfJournalFile)
	if err != nil || record == nil || store.pfTransport != nil || record.Phase != PFActive || record.PID != os.Getpid() || record.RulesSHA256 != pfDigest(stagedPFRule) {
		return nil, ErrRecoveryRequired
	}
	// A verified no-op proves the live guard and reference, not just its journal.
	if store.updatePFPolicyLocked(ctx, pfPolicy{}, nil) != nil {
		return nil, ErrRecoveryRequired
	}
	bind.identity = *record
	store.pfTransport = bind
	pfPinnedTransports.Store(bind, struct{}{})
	return bind, nil
}

func (bind *pfGuardBind) BatchSize() int { return 1 }
func (bind *pfGuardBind) SetMark(mark uint32) error {
	if mark != 0 {
		return ErrRecoveryRequired
	}
	return nil
}
func (bind *pfGuardBind) ParseEndpoint(text string) (conn.Endpoint, error) {
	endpoint, err := netip.ParseAddrPort(text)
	if err != nil || !pfNumericAddress(endpoint.Addr()) || endpoint.Port() == 0 {
		return nil, ErrRecoveryRequired
	}
	return &conn.StdNetEndpoint{AddrPort: endpoint}, nil
}

func (bind *pfGuardBind) Open(requested uint16) ([]conn.ReceiveFunc, uint16, error) {
	bind.op.Lock()
	defer bind.op.Unlock()
	if bind.detached || bind.detaching || bind.retained || bind.admission.Err() != nil || bind.generation == ^uint64(0) || (bind.scoped != nil && bind.scoped.lost.Load()) {
		return nil, 0, ErrRecoveryRequired
	}
	if bind.current.Load() != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	if bind.verifyScoped(bind.admission) != nil {
		return nil, 0, ErrRecoveryRequired
	}
	lease := &pfGuardLease{done: make(chan struct{}), generation: bind.generation + 1}
	for _, path := range bind.paths {
		port := requested
		if lease.port != 0 {
			port = lease.port
		}
		socket, err := bind.openSocket(path.path, path.source, port)
		if err != nil {
			bind.abandonUnadmitted(lease)
			return nil, 0, ErrRecoveryRequired
		}
		writers := make(chan struct{}, 1)
		writers <- struct{}{}
		lease.sockets = append(lease.sockets, pfGuardSocket{socket, path.source, writers})
		local, ok := socket.LocalAddr().(*net.UDPAddr)
		if !ok || local.Port < 1 || local.Port > 65535 || !local.IP.Equal(net.IP(path.source.AsSlice())) || (port != 0 && int(port) != local.Port) {
			bind.abandonUnadmitted(lease)
			return nil, 0, ErrRecoveryRequired
		}
		lease.port = uint16(local.Port)
	}
	if bind.verifyScoped(bind.admission) != nil {
		bind.abandonUnadmitted(lease)
		return nil, 0, ErrRecoveryRequired
	}
	bind.generation = lease.generation
	// Retain ownership BEFORE any effectful PF update. Failed confirmation can
	// mean the new exception is already in the kernel.
	bind.current.Store(lease)
	policy, _ := bind.policy.frozen()
	for i := range policy.escapes {
		policy.escapes[i].sourcePort = lease.port
	}
	if bind.changePolicy(bind.admission, policy, false) != nil || bind.admission.Err() != nil {
		bind.retained = true
		lease.retire()
		return nil, 0, ErrRecoveryRequired
	}
	if bind.verifyScoped(bind.admission) != nil {
		// Admission is confirmed, so the loss monitor can now perform ordinary
		// deny-only revocation. An ambiguous update above needs reconciliation.
		return nil, 0, ErrRecoveryRequired
	}
	lease.control.Lock()
	if lease.retired.Load() || (bind.scoped != nil && bind.scoped.lost.Load()) {
		lease.control.Unlock()
		return nil, 0, ErrRecoveryRequired
	}
	lease.admitted.Store(true)
	lease.control.Unlock()
	fns := make([]conn.ReceiveFunc, 0, len(lease.sockets))
	for _, socket := range lease.sockets {
		fns = append(fns, pfGuardReceive(lease, socket.fd))
	}
	return fns, lease.port, nil
}

func (bind *pfGuardBind) abandonUnadmitted(lease *pfGuardLease) {
	// No PF mutation was attempted; these partial sockets may be released.
	lease.retire()
	if closePFGuardSockets(lease) != nil {
		bind.current.Store(lease)
		bind.retained = true
	}
}

func (lease *pfGuardLease) retire() error {
	lease.control.Lock()
	defer lease.control.Unlock()
	if !lease.retired.Swap(true) {
		close(lease.done)
	}
	var result error
	for _, socket := range lease.sockets {
		result = errors.Join(result, socket.fd.SetDeadline(time.Now()))
	}
	return result
}

func closePFGuardSockets(lease *pfGuardLease) error {
	var result error
	for _, socket := range lease.sockets {
		if err := socket.fd.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			result = errors.Join(result, err)
		}
	}
	return result
}

func (bind *pfGuardBind) Close() error {
	bind.op.Lock()
	defer bind.op.Unlock()
	if bind.retained {
		return ErrRecoveryRequired
	}
	lease := bind.current.Load()
	if lease == nil {
		return nil
	}
	// Independent of a canceled connection attempt. In-flight PF ioctl calls
	// remain soft-bounded: context cancellation cannot forcibly abort a syscall.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	interrupted := lease.retire()
	if bind.changePolicy(ctx, pfPolicy{}, false) != nil {
		bind.retained = true
		return ErrRecoveryRequired
	}
	// Even a deadline failure must not skip deny-only or closing after its proof.
	if closePFGuardSockets(lease) != nil {
		bind.retained = true
		return ErrRecoveryRequired
	}
	bind.current.Store(nil)
	return interrupted
}

// Explicit reconciliation keeps the guard enabled. It never calls whole-guard
// recovery or restores ordinary networking, and it never revives old callbacks.
func (bind *pfGuardBind) reconcile(ctx context.Context) error {
	bind.op.Lock()
	defer bind.op.Unlock()
	lease := bind.current.Load()
	if bind.detached || !bind.retained || lease == nil || !lease.retired.Load() {
		return ErrRecoveryRequired
	}
	lease.retire()
	if bind.changePolicy(ctx, pfPolicy{}, true) != nil || closePFGuardSockets(lease) != nil {
		return ErrRecoveryRequired
	}
	bind.current.Store(nil)
	bind.retained = false
	return nil
}

func (bind *pfGuardBind) detach() error {
	bind.op.Lock()
	if bind.detached || bind.current.Load() != nil || bind.retained {
		bind.op.Unlock()
		return ErrRecoveryRequired
	}
	// The monitor may be entering Close. Refuse further Open operations, then
	// join it without holding op; joining under that mutex would deadlock.
	bind.detaching = true
	bind.op.Unlock()
	if bind.scoped != nil && bind.scoped.stop() != nil {
		return ErrRecoveryRequired
	}
	bind.op.Lock()
	defer bind.op.Unlock()
	bind.store.mutex.Lock()
	defer bind.store.mutex.Unlock()
	if bind.detached || bind.store.closed || bind.store.pfTransport != bind {
		return ErrRecoveryRequired
	}
	bind.store.pfTransport = nil
	bind.detached = true
	pfPinnedTransports.Delete(bind)
	return nil
}

func (bind *pfGuardBind) changePolicy(ctx context.Context, policy pfPolicy, resolve bool) error {
	store := bind.store
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if ctx == nil || ctx.Err() != nil || store.closed || store.pfTransport != bind {
		return ErrRecoveryRequired
	}
	record, err := store.readPF(pfJournalFile)
	if err != nil || record == nil || record.Version != bind.identity.Version || record.ID != bind.identity.ID || record.Boot != bind.identity.Boot || record.PID != bind.identity.PID || record.Anchor != bind.identity.Anchor || record.Reference != bind.identity.Reference || record.ReferenceAfter != bind.identity.ReferenceAfter || record.ReferenceBefore != bind.identity.ReferenceBefore || record.RootSHA256 != bind.identity.RootSHA256 || record.RecursiveSHA256 != bind.identity.RecursiveSHA256 || record.NATSHA256 != bind.identity.NATSHA256 {
		return ErrRecoveryRequired
	}
	if resolve && record.Phase == PFRuleUpdateIntent {
		if store.resolvePFPolicyLocked(ctx) != nil {
			return ErrRecoveryRequired
		}
	}
	return store.updatePFPolicyLocked(ctx, policy, bind)
}

func pfGuardReceive(lease *pfGuardLease, socket pfDatagram) conn.ReceiveFunc {
	return func(buffers [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
		if lease.retired.Load() || !lease.admitted.Load() {
			return 0, net.ErrClosed
		}
		if len(buffers) != 1 || len(sizes) < 1 || len(endpoints) < 1 {
			return 0, ErrRecoveryRequired
		}
		n, remote, err := socket.ReadFromUDPAddrPort(buffers[0])
		if lease.retired.Load() {
			return 0, net.ErrClosed
		}
		if err != nil {
			return 0, err
		}
		if !pfNumericAddress(remote.Addr()) || remote.Port() == 0 {
			return 0, ErrRecoveryRequired
		}
		sizes[0] = n
		endpoints[0] = &conn.StdNetEndpoint{AddrPort: remote}
		return 1, nil
	}
}

func (bind *pfGuardBind) Send(buffers [][]byte, endpoint conn.Endpoint) error {
	lease := bind.current.Load()
	if lease == nil || lease.retired.Load() || !lease.admitted.Load() {
		return net.ErrClosed
	}
	remote, ok := endpoint.(*conn.StdNetEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	if len(buffers) != 1 || len(buffers[0]) > 65507 {
		return ErrRecoveryRequired
	}
	admitted := false
	for _, escape := range bind.policy.escapes {
		if escape.endpoint == remote.AddrPort {
			admitted = true
			break
		}
	}
	if !admitted {
		return ErrRecoveryRequired
	}
	for _, socket := range lease.sockets {
		if socket.source.Is4() != remote.AddrPort.Addr().Is4() {
			continue
		}
		// Official Peer.Send holds device.net.RLock. A finite write AND queue
		// wait prevent shutdown from waiting forever before it can call Close.
		timer := time.NewTimer(time.Second)
		defer timer.Stop()
		select {
		case <-lease.done:
			return net.ErrClosed
		case <-timer.C:
			return os.ErrDeadlineExceeded
		case <-socket.writers:
		}
		defer func() { socket.writers <- struct{}{} }()
		lease.control.Lock()
		if lease.retired.Load() {
			lease.control.Unlock()
			return net.ErrClosed
		}
		err := socket.fd.SetWriteDeadline(time.Now().Add(time.Second))
		lease.control.Unlock()
		if err != nil {
			return err
		}
		n, _, err := socket.fd.WriteMsgUDPAddrPort(buffers[0], nil, remote.AddrPort)
		if lease.retired.Load() {
			return net.ErrClosed
		}
		if err != nil {
			return err
		}
		if n != len(buffers[0]) {
			return io.ErrShortWrite
		}
		return nil
	}
	return ErrRecoveryRequired
}
