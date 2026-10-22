package recoverycore

// Developer-only projection. No installed code can change interface flags.
// ABI is compiler-compared from pinned legacy/modern Apple headers before CI.
import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

const (
	fixturePFGetInterfaces = uintptr(0xc0284457)
	fixturePFSetSkip       = uintptr(0xc0284459)
	fixturePFClearSkip     = uintptr(0xc028445a)
	fixturePFSkip          = uint32(0x100)
)

type fixturePFInterface struct{ flags, states, rules uint32 }

func fixturePFInterfaceIoctl(ctx context.Context, fd int, operation uintptr, data []byte) error {
	if ctx.Err() != nil || fd < 0 || runtime.GOARCH != "amd64" || len(data) != 40 ||
		(operation != fixturePFGetInterfaces && operation != fixturePFSetSkip && operation != fixturePFClearSkip) {
		return ErrRecoveryRequired
	}
	_, _, errno := syscall.Syscall(unix.SYS_IOCTL, uintptr(fd), operation, uintptr(unsafe.Pointer(&data[0])))
	runtime.KeepAlive(data)
	if errno != 0 {
		return errno
	}
	return nil
}

func fixtureReadPFInterface(ctx context.Context, fd int, name string) (fixturePFInterface, error) {
	if !utunName.MatchString(name) || len(name) >= 16 {
		return fixturePFInterface{}, ErrRecoveryRequired
	}
	header := make([]byte, 40)
	copy(header, name)
	binary.LittleEndian.PutUint32(header[24:], 168)
	if fixturePFInterfaceIoctl(ctx, fd, fixturePFGetInterfaces, header) != nil || binary.LittleEndian.Uint32(header[28:]) != 1 {
		return fixturePFInterface{}, ErrRecoveryRequired
	}
	data, err := unix.Mmap(-1, 0, 168, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
	if err != nil {
		return fixturePFInterface{}, ErrRecoveryRequired
	}
	defer unix.Munmap(data)
	binary.LittleEndian.PutUint32(header[28:], 1)
	binary.LittleEndian.PutUint64(header[16:], uint64(uintptr(unsafe.Pointer(&data[0]))))
	if fixturePFInterfaceIoctl(ctx, fd, fixturePFGetInterfaces, header) != nil || binary.LittleEndian.Uint32(header[28:]) != 1 || unix.ByteSliceToString(data[:16]) != name {
		return fixturePFInterface{}, ErrRecoveryRequired
	}
	return fixturePFInterface{binary.LittleEndian.Uint32(data[152:]), binary.LittleEndian.Uint32(data[156:]), binary.LittleEndian.Uint32(data[160:])}, nil
}

// Require the actual fresh device, not an arbitrary interface name. The test
// keeps its descriptor open across verification/mutation; no index-only lease.
func fixtureChangeOwnSkip(ctx context.Context, fd int, link tun.Device, enable bool) error {
	name, err := link.Name()
	if err != nil || link.File() == nil {
		return ErrRecoveryRequired
	}
	raw, err := link.File().SyscallConn()
	if err != nil {
		return ErrRecoveryRequired
	}
	var descriptorName string
	var descriptorErr error
	if raw.Control(func(value uintptr) {
		descriptorName, descriptorErr = unix.GetsockoptString(int(value), 2, 2)
	}) != nil || descriptorErr != nil || descriptorName != name {
		return ErrRecoveryRequired
	}
	iface, err := net.InterfaceByName(name)
	if err != nil || iface.Index < 1 {
		return ErrRecoveryRequired
	}
	before, err := fixtureReadPFInterface(ctx, fd, name)
	expected, next, operation := uint32(0), fixturePFSkip, fixturePFSetSkip
	if !enable {
		expected, next, operation = fixturePFSkip, 0, fixturePFClearSkip
	}
	// Getter takes one temporary RULE reference before copying; one means
	// zero actual rule references. Flags alone must not pin the kif instance.
	if err != nil || before != (fixturePFInterface{expected, 0, 1}) {
		return ErrRecoveryRequired
	}
	stillName, err := link.Name()
	still, lookupErr := net.InterfaceByName(name)
	if err != nil || stillName != name || lookupErr != nil || still.Index != iface.Index {
		return ErrRecoveryRequired
	}
	header := make([]byte, 40)
	copy(header, name)
	binary.LittleEndian.PutUint32(header[36:], fixturePFSkip)
	if fixturePFInterfaceIoctl(ctx, fd, operation, header) != nil {
		return ErrRecoveryRequired
	}
	after, err := fixtureReadPFInterface(ctx, fd, name)
	if err != nil || after != (fixturePFInterface{next, 0, 1}) {
		return ErrRecoveryRequired
	}
	return nil
}

func TestRootPFRuleOwnInterfaceFlagWire(t *testing.T) {
	requirePFRuleCI(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	anchor := "com.apple/legacywg-0123456789abcdef0123456789abcdef"
	baseline, err := readDisabledPF(ctx, anchor)
	if err != nil || baseline.rules != pfDigest("") || len(fixturePFReferences(t, ctx)) != 0 {
		t.Fatal("interface flag wire requires unchanged disabled empty-state PF baseline")
	}
	fd, err := openPFReferences(ctx)
	if err != nil {
		t.Fatal("interface flag wire PF descriptor unavailable")
	}
	defer unix.Close(fd)
	link, err := tun.CreateTUN("utun", 1280)
	if err != nil {
		t.Fatal("interface flag wire own tunnel unavailable")
	}
	defer link.Close()
	name, err := link.Name()
	iface, lookupErr := net.InterfaceByName(name)
	if err != nil || lookupErr != nil || !utunName.MatchString(name) {
		t.Fatal("interface flag wire identity unavailable")
	}
	if !t.Run("fresh_zero_references", func(t *testing.T) {
		observed, err := fixtureReadPFInterface(ctx, fd, name)
		if err != nil || observed != (fixturePFInterface{0, 0, 1}) {
			t.Fatalf("fresh interface flags/reference projection refused: observation=%+v error=%v", observed, err)
		}
	}) {
		return
	}
	if !t.Run("set_clear_verified", func(t *testing.T) {
		if fixtureChangeOwnSkip(ctx, fd, link, true) != nil || fixtureChangeOwnSkip(ctx, fd, link, true) == nil || fixtureChangeOwnSkip(ctx, fd, link, false) != nil {
			t.Fatal("exact owned interface set/clear verification failed")
		}
	}) {
		return
	}
	if fixtureChangeOwnSkip(ctx, fd, link, true) != nil || link.Close() != nil {
		t.Fatal("flagged own tunnel closure failed")
	}
	deadline := time.Now().Add(3 * time.Second)
	for !admittedInterfaceNameAbsent(name) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !admittedInterfaceNameAbsent(name) {
		t.Fatal("flagged original interface did not disappear")
	}
	replacement, err := tun.CreateTUN(name, 1280)
	if err != nil {
		t.Fatal("flag wire same-name replacement unavailable")
	}
	defer replacement.Close()
	if !t.Run("replacement_has_no_skip", func(t *testing.T) {
		observed, err := fixtureReadPFInterface(ctx, fd, name)
		if err != nil || observed != (fixturePFInterface{0, 0, 1}) {
			t.Fatalf("flag inherited across verified interface disappearance: observation=%+v error=%v", observed, err)
		}
		current, err := net.InterfaceByName(name)
		if err != nil {
			t.Fatal("replacement interface identity disappeared")
		}
		measurement := "index_changed"
		if current.Index == iface.Index {
			measurement = "index_reused"
		}
		t.Run(measurement, func(t *testing.T) {})
	}) {
		return
	}
	t.Run("disabled_policy_baseline_unchanged", func(t *testing.T) {
		after, err := readDisabledPF(ctx, anchor)
		if err != nil || after != baseline || len(fixturePFReferences(t, ctx)) != 0 {
			t.Fatal("interface flag wire altered PF policy/reference baseline")
		}
	})
}

func TestRootPFRuleOwnInterfaceReferencedRefused(t *testing.T) {
	for cycle := 0; cycle < 3; cycle++ {
		t.Run(fmt.Sprintf("cycle%d", cycle), fixtureReferencedInterfaceRefusal)
	}
}

func fixtureReferencedInterfaceRefusal(t *testing.T) {
	t.Helper()
	requirePFRuleCI(t)
	_, hosts := endpointOwnedLink(t)
	f := newProtectedFixture(t)
	var err error
	f.owner, err = f.store.PrepareProtectedTransport(f.ctx, protectedFixtureEndpoints(hosts))
	if err != nil || f.owner == nil {
		t.Fatal("referenced interface fixture preparation failed")
	}
	bind, err := f.owner.Bind()
	if err != nil {
		t.Fatal("referenced interface fixture Bind unavailable")
	}
	if _, _, err := bind.Open(0); err != nil {
		t.Fatal("referenced interface fixture admission failed")
	}
	fd, err := openPFReferences(f.ctx)
	if err != nil {
		t.Fatal("referenced interface fixture PF descriptor unavailable")
	}
	defer unix.Close(fd)
	name, err := f.tunnel.Name()
	if err != nil {
		t.Fatal("referenced interface fixture identity unavailable")
	}
	before, err := fixtureReadPFInterface(f.ctx, fd, name)
	if err != nil || before.flags != 0 || before.states != 0 || before.rules < 2 {
		t.Fatal("live tunnel rule did not retain the expected PF interface reference")
	}
	record, err := f.store.readPF(pfJournalFile)
	if err != nil || record == nil {
		t.Fatal("referenced interface fixture journal unavailable")
	}
	if fixtureChangeOwnSkip(f.ctx, fd, f.tunnel, true) == nil {
		t.Fatal("ephemeral permission accepted a rule-pinned interface")
	}
	after, err := fixtureReadPFInterface(f.ctx, fd, name)
	policy, policyErr := readPFPolicy(f.ctx, record.Anchor, true)
	if err != nil || after != before || policyErr != nil || !policy.matches(*record) || policy.rules != record.RulesSHA256 {
		t.Fatal("referenced permission refusal modified flags or policy")
	}
	// Preserve immediate sequential cleanup, without subtest scheduling between
	// steps: a prior compound call failed once. Identify the stage if it recurs.
	if f.owner.Stop(f.ctx) != nil {
		t.Fatal("referenced permission fixture stop did not confirm deny")
	}
	if f.tunnel.Close() != nil {
		t.Fatal("referenced permission fixture native tunnel close failed")
	}
	if f.owner.Disconnect(f.ctx) != nil {
		t.Fatalf("referenced permission fixture disconnect refused: tunnel_absent=%t endpoint_residue=%t pf_residue=%t", admittedInterfaceNameAbsent(name), f.store.endpointResidue(), f.store.pfResidue())
	}
}

func TestRootPFRuleOwnInterfaceLeaseWire(t *testing.T) {
	requirePFRuleCI(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	anchor := "com.apple/legacywg-0123456789abcdef0123456789abcdef"
	baseline, err := readDisabledPF(ctx, anchor)
	if err != nil || baseline.rules != pfDigest("") || len(fixturePFReferences(t, ctx)) != 0 {
		t.Fatal("interface lease wire requires disabled empty-state baseline")
	}
	pf, err := openPFReferences(ctx)
	if err != nil {
		t.Fatal("interface lease PF descriptor unavailable")
	}
	defer unix.Close(pf)
	link, err := tun.CreateTUN("utun", 1280)
	if err != nil {
		t.Fatal("interface lease own tunnel unavailable")
	}
	defer link.Close()
	name, err := link.Name()
	iface, lookupErr := net.InterfaceByName(name)
	if err != nil || lookupErr != nil || link.File() == nil {
		t.Fatal("interface lease own identity unavailable")
	}
	lease := -1
	raw, err := link.File().SyscallConn()
	if err != nil {
		t.Fatal("interface lease file unavailable")
	}
	var duplicateErr error
	if raw.Control(func(fd uintptr) {
		lease, duplicateErr = unix.FcntlInt(fd, unix.F_DUPFD_CLOEXEC, 0)
	}) != nil || duplicateErr != nil || lease < 0 {
		t.Fatal("interface lease atomic close-on-exec duplication failed")
	}
	defer func() {
		if lease >= 0 {
			_ = unix.Close(lease)
		}
	}()
	leaseIdentity := func() bool {
		actual, err := unix.GetsockoptString(lease, 2, 2) // official Darwin TUN name query
		current, lookupErr := net.InterfaceByName(name)
		flags, flagErr := unix.FcntlInt(uintptr(lease), unix.F_GETFD, 0)
		return err == nil && actual == name && lookupErr == nil && current.Index == iface.Index && flagErr == nil && flags&unix.FD_CLOEXEC != 0
	}
	if !leaseIdentity() || fixtureChangeOwnSkip(ctx, pf, link, true) != nil || link.Close() != nil {
		t.Fatal("interface lease preparation or engine-side closure failed")
	}
	if !t.Run("retained_after_device_close", func(t *testing.T) {
		observed, err := fixtureReadPFInterface(ctx, pf, name)
		if !leaseIdentity() || err != nil || observed != (fixturePFInterface{fixturePFSkip, 0, 1}) {
			t.Fatal("native duplicate failed to retain original flagged interface")
		}
	}) {
		return
	}
	if !t.Run("clear_before_last_descriptor_close", func(t *testing.T) {
		if !leaseIdentity() {
			t.Fatal("retained descriptor identity changed")
		}
		header := make([]byte, 40)
		copy(header, name)
		binary.LittleEndian.PutUint32(header[36:], fixturePFSkip)
		if fixturePFInterfaceIoctl(ctx, pf, fixturePFClearSkip, header) != nil {
			t.Fatal("leased interface clear failed")
		}
		observed, err := fixtureReadPFInterface(ctx, pf, name)
		if err != nil || observed != (fixturePFInterface{0, 0, 1}) || !leaseIdentity() {
			t.Fatal("leased interface clear was not verified before release")
		}
	}) {
		return
	}
	if unix.Close(lease) != nil {
		t.Fatal("interface lease final descriptor release failed")
	}
	lease = -1
	deadline := time.Now().Add(3 * time.Second)
	for !admittedInterfaceNameAbsent(name) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !t.Run("last_close_removes_interface", func(t *testing.T) {
		if !admittedInterfaceNameAbsent(name) {
			t.Fatal("interface remained after final descriptor closed")
		}
	}) {
		return
	}
	t.Run("disabled_policy_baseline_unchanged", func(t *testing.T) {
		after, err := readDisabledPF(ctx, anchor)
		if err != nil || after != baseline || len(fixturePFReferences(t, ctx)) != 0 {
			t.Fatal("interface lease wire altered PF policy/reference baseline")
		}
	})
}
