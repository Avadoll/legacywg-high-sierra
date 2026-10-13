package recoverycore

import (
	"context"
	"encoding/binary"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Unsupported private Darwin PF ABI, Intel LP64 only. No global start/stop,
// ruleset, state-kill or arbitrary ioctl is exposed by this fixed projection.
// These identifiers/layouts also match the developer C probe, but actual
// High Sierra operation remains a separate gate. Separate metadata reads and
// STOPREF are NOT an atomic compare-and-release API.
const pfGetReferences = uintptr(0xc0104405)
const pfStartReference = uintptr(0x40084408)
const pfStopReference = uintptr(0xc0104409)

func openPFReferences(ctx context.Context) (int, error) {
	if ctx.Err() != nil || runtime.GOARCH != "amd64" || unsafe.Sizeof(uintptr(0)) != 8 || os.Geteuid() != 0 {
		return -1, ErrRecoveryRequired
	}
	fd, err := unix.Open("/dev/pf", unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, ErrRecoveryRequired
	}
	var status unix.Stat_t
	if unix.Fstat(fd, &status) != nil || status.Uid != 0 || status.Mode&unix.S_IFMT != unix.S_IFCHR {
		unix.Close(fd)
		return -1, ErrRecoveryRequired
	}
	return fd, nil
}

func pfReferenceIoctl(ctx context.Context, fd int, operation uintptr, data []byte) error {
	if ctx.Err() != nil || fd < 0 || runtime.GOARCH != "amd64" || (operation != pfGetReferences && operation != pfStartReference && operation != pfStopReference) || (operation == pfStartReference && len(data) != 8) || (operation != pfStartReference && len(data) != 16) {
		return ErrRecoveryRequired
	}
	_, _, errno := syscall.Syscall(unix.SYS_IOCTL, uintptr(fd), operation, uintptr(unsafe.Pointer(&data[0])))
	runtime.KeepAlive(data)
	if errno != 0 {
		return errno
	}
	return nil
}

func readPFReferences(ctx context.Context, fd int) ([]pfReference, error) {
	header := make([]byte, 16)
	if err := pfReferenceIoctl(ctx, fd, pfGetReferences, header); err != nil {
		if err == unix.ENOENT {
			return []pfReference{}, nil
		}
		return nil, ErrRecoveryRequired
	}
	count := int32(binary.LittleEndian.Uint32(header[:4]))
	if count <= 0 || count > maxPFReferences*pfReferenceEntryBytes || count%pfReferenceEntryBytes != 0 {
		return nil, ErrRecoveryRequired
	}
	// Kernel buffer is mmap memory, not a retained Go pointer in a uintptr.
	// Capacity is fixed and bounded even if the reference list changes.
	data, err := unix.Mmap(-1, 0, maxPFReferences*pfReferenceEntryBytes, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
	if err != nil {
		return nil, ErrRecoveryRequired
	}
	defer unix.Munmap(data)
	binary.LittleEndian.PutUint64(header[8:], uint64(uintptr(unsafe.Pointer(&data[0]))))
	if pfReferenceIoctl(ctx, fd, pfGetReferences, header) != nil || int32(binary.LittleEndian.Uint32(header[:4])) != count {
		return nil, ErrRecoveryRequired
	}
	// The second size check catches ordinary additions/removals during copying;
	// a later full observation is still needed before any owned release.
	check := make([]byte, 16)
	if pfReferenceIoctl(ctx, fd, pfGetReferences, check) != nil || int32(binary.LittleEndian.Uint32(check[:4])) != count {
		return nil, ErrRecoveryRequired
	}
	return decodePFReferences(data[:int(count)])
}

func currentPFReferenceName() bool {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", os.Getpid())
	if err != nil || info.Proc.P_pid != int32(os.Getpid()) {
		return false
	}
	return unix.ByteSliceToString(info.Proc.P_comm[:]) == pfReferenceOwnerName
}

func acquirePFReference(ctx context.Context, fd int) (uint64, error) {
	if !currentPFReferenceName() {
		return 0, ErrRecoveryRequired
	}
	value := make([]byte, 8)
	if pfReferenceIoctl(ctx, fd, pfStartReference, value) != nil || binary.LittleEndian.Uint64(value) == 0 {
		return 0, ErrRecoveryRequired
	}
	return binary.LittleEndian.Uint64(value), nil
}

// Only the lifecycle coordinator passes a token already matched to its exact
// durable record and two full metadata observations. This scalar kernel call
// itself cannot check PID/name/epoch and offers no adversarial ABA guarantee.
func releasePFReference(ctx context.Context, fd int, reference pfReference) (uint64, error) {
	if reference.token == 0 || reference.pid <= 0 || reference.name != pfReferenceOwnerName || reference.epoch <= 0 {
		return 0, ErrRecoveryRequired
	}
	value := make([]byte, 16)
	binary.LittleEndian.PutUint64(value, reference.token)
	if pfReferenceIoctl(ctx, fd, pfStopReference, value) != nil {
		return 0, ErrRecoveryRequired
	}
	return binary.LittleEndian.Uint64(value[8:]), nil
}
