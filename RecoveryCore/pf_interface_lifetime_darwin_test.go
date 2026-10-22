package recoverycore

// Developer-only projection. No installed code can change interface flags.
// ABI is compiler-compared from pinned legacy/modern Apple headers before CI.
import (
	"context"
	"encoding/binary"
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
		if fixtureChangeOwnSkip(ctx, fd, link, true) != nil || fixtureChangeOwnSkip(ctx, fd, link, false) != nil {
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
