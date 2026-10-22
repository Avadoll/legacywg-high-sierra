package recoverycore

// Test-only orchestration around the unchanged official engine. It does not
// implement installed ownership, journal intent or the scoped monitor's loss
// callback, and must not be used as a product transport.
import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun"
)

type pfFixtureTUNLease struct {
	tun.Device
	file *os.File
}

func (lease *pfFixtureTUNLease) File() *os.File { return lease.file }
func (lease *pfFixtureTUNLease) Close() error   { return lease.file.Close() }
func (lease *pfFixtureTUNLease) Name() (string, error) {
	raw, err := lease.file.SyscallConn()
	if err != nil {
		return "", err
	}
	var name string
	var queryErr error
	if err := raw.Control(func(fd uintptr) { name, queryErr = unix.GetsockoptString(int(fd), 2, 2) }); err != nil {
		return "", err
	}
	return name, queryErr
}

type pfFixturePermissionBind struct {
	conn.Bind
	mutex   sync.Mutex
	lease   *pfFixtureTUNLease
	enabled bool
	closed  bool
}

func fixturePermissionBind(t *testing.T, bind *pfGuardBind, link tun.Device) *pfFixturePermissionBind {
	t.Helper()
	name, err := link.Name()
	if err != nil || link.File() == nil {
		t.Fatal("encrypted permission own TUN unavailable")
	}
	raw, err := link.File().SyscallConn()
	if err != nil {
		t.Fatal("encrypted permission own file unavailable")
	}
	fd := -1
	var duplicateErr error
	if raw.Control(func(value uintptr) { fd, duplicateErr = unix.FcntlInt(value, unix.F_DUPFD_CLOEXEC, 0) }) != nil || duplicateErr != nil || fd < 0 {
		t.Fatal("encrypted permission lease duplication failed")
	}
	lease := &pfFixtureTUNLease{Device: link, file: os.NewFile(uintptr(fd), "owned-tun-lease")}
	actual, err := lease.Name()
	if err != nil || actual != name {
		_ = lease.Close()
		t.Fatal("encrypted permission lease identity differs")
	}
	bind.op.Lock()
	bind.policy.tunnel = nil // Never create a name-pinning TUN rule.
	bind.op.Unlock()
	return &pfFixturePermissionBind{Bind: bind, lease: lease}
}

func (bind *pfFixturePermissionBind) change(enabled bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	fd, err := openPFReferences(ctx)
	if err != nil {
		return ErrRecoveryRequired
	}
	defer unix.Close(fd)
	if fixtureChangeOwnSkip(ctx, fd, bind.lease, enabled) != nil {
		return ErrRecoveryRequired
	}
	bind.enabled = enabled
	return nil
}

func (bind *pfFixturePermissionBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	bind.mutex.Lock()
	defer bind.mutex.Unlock()
	if bind.closed || bind.enabled {
		return nil, 0, ErrRecoveryRequired
	}
	functions, actual, err := bind.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	if bind.change(true) != nil {
		_ = bind.Bind.Close() // Guarded core retains ports if deny is ambiguous.
		return nil, 0, ErrRecoveryRequired
	}
	return functions, actual, nil
}

func (bind *pfFixturePermissionBind) Close() error {
	bind.mutex.Lock()
	defer bind.mutex.Unlock()
	if bind.closed {
		return nil
	}
	if bind.enabled && bind.change(false) != nil {
		return ErrRecoveryRequired // Keep lease/ports on uncertain permission.
	}
	return bind.Bind.Close()
}

func (bind *pfFixturePermissionBind) release() error {
	if bind.Close() != nil {
		return ErrRecoveryRequired
	}
	bind.mutex.Lock()
	defer bind.mutex.Unlock()
	if bind.closed {
		return nil
	}
	if bind.enabled || bind.lease.Close() != nil {
		return ErrRecoveryRequired
	}
	bind.closed = true
	return nil
}

func TestRootPFRuleEphemeralEncryptedPackets(t *testing.T) {
	requirePFRuleCI(t)
	if os.Getenv("LEGACYWG_PF_ENCRYPTED_PACKET_TESTS") != "1" {
		t.Skip("explicit test-only ephemeral encrypted lifecycle")
	}
	for _, family := range []int{4, 6} {
		t.Run(outerFamilyName(family), func(t *testing.T) { pfEncryptedPacketFamilyWithPermission(t, family, true, true, true, true, true) })
	}
}

func outerFamilyName(family int) string {
	if family == 4 {
		return "outer4"
	}
	return "outer6"
}
