package recoverycore

import (
	"context"
	"encoding/binary"
	"net"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const pfGetInterfaces = uintptr(0xc0284457)

// Read-only, fixed DIOCIGETIFACES. No interface flag setter/clearer is linked
// into production; a protected own-TUN capability remains a separate change.
func pfInterfaceRead(ctx context.Context, fd int, header []byte) error {
	if ctx == nil || ctx.Err() != nil || fd < 0 || runtime.GOARCH != "amd64" || len(header) != 40 {
		return ErrRecoveryRequired
	}
	_, _, errno := syscall.Syscall(unix.SYS_IOCTL, uintptr(fd), pfGetInterfaces, uintptr(unsafe.Pointer(&header[0])))
	runtime.KeepAlive(header)
	if errno != 0 {
		return ErrRecoveryRequired
	}
	return nil
}

func readPFInterfaces(ctx context.Context) ([]pfInterfaceObservation, error) {
	fd, err := openPFReferences(ctx)
	if err != nil {
		return nil, ErrRecoveryRequired
	}
	defer unix.Close(fd)
	header := make([]byte, 40) // Empty filter enumerates ALL kif entries.
	binary.LittleEndian.PutUint32(header[24:], pfInterfaceEntryBytes)
	if pfInterfaceRead(ctx, fd, header) != nil {
		return nil, ErrRecoveryRequired
	}
	count := int32(binary.LittleEndian.Uint32(header[28:]))
	if count < 1 || count > maxPFInterfaces {
		return nil, ErrRecoveryRequired
	}
	data, err := unix.Mmap(-1, 0, maxPFInterfaces*pfInterfaceEntryBytes, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
	if err != nil {
		return nil, ErrRecoveryRequired
	}
	defer unix.Munmap(data)
	binary.LittleEndian.PutUint64(header[16:], uint64(uintptr(unsafe.Pointer(&data[0]))))
	binary.LittleEndian.PutUint32(header[28:], maxPFInterfaces)
	if pfInterfaceRead(ctx, fd, header) != nil || int32(binary.LittleEndian.Uint32(header[28:])) != count {
		return nil, ErrRecoveryRequired
	}
	check := make([]byte, 40)
	binary.LittleEndian.PutUint32(check[24:], pfInterfaceEntryBytes)
	if pfInterfaceRead(ctx, fd, check) != nil || int32(binary.LittleEndian.Uint32(check[28:])) != count || ctx.Err() != nil {
		return nil, ErrRecoveryRequired
	}
	return decodePFInterfaces(data[:int(count)*pfInterfaceEntryBytes])
}

// A deny rule is not proof of filtering when any interface is skipped. Even
// a foreign loopback skip is refused; this routine never changes foreign flags.
// Enumeration/count checks are observations, not an atomic privileged-writer
// guarantee or an interface-incarnation capability.
func requireUnskippedPFInterfaces(ctx context.Context) error {
	entries, err := readPFInterfaces(ctx)
	if err != nil {
		return ErrRecoveryRequired
	}
	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		if entry.flags != 0 {
			return ErrRecoveryRequired
		}
		seen[entry.name] = true
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) == 0 || len(interfaces) > maxPFInterfaces {
		return ErrRecoveryRequired
	}
	for _, iface := range interfaces {
		if !seen[iface.Name] {
			return ErrRecoveryRequired
		}
	}
	return nil
}
