package recoverycore

import (
	"net"
	"net/netip"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// The controller retains this socket until its PF exception has been revoked.
// SetDeadline stops pending I/O without relinquishing the admitted local port.
// Only unconnected UDP is exposed, matching the official Darwin bind's API.
type pfDatagram interface {
	ReadFromUDPAddrPort([]byte) (int, netip.AddrPort, error)
	WriteMsgUDPAddrPort([]byte, []byte, netip.AddrPort) (int, int, error)
	SetDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	Close() error
	LocalAddr() net.Addr
}

func validatePFDatagramSource(path pfInterface, source netip.Addr) error {
	if !pfInterfaceName.MatchString(path.name) || path.index < 1 || path.index > 2147483647 || !pfNumericAddress(source) {
		return ErrRecoveryRequired
	}
	iface, err := net.InterfaceByName(path.name)
	if err != nil || iface.Index != path.index || iface.Flags&net.FlagUp == 0 {
		return ErrRecoveryRequired
	}
	byIndex, err := net.InterfaceByIndex(path.index)
	if err != nil || byIndex.Name != path.name || byIndex.Flags&net.FlagUp == 0 {
		return ErrRecoveryRequired
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return ErrRecoveryRequired
	}
	for _, address := range addresses {
		var ip net.IP
		switch value := address.(type) {
		case *net.IPNet:
			ip = value.IP
		case *net.IPAddr:
			ip = value.IP
		}
		if actual, ok := netip.AddrFromSlice(ip); ok && actual.Unmap() == source {
			return nil
		}
	}
	return ErrRecoveryRequired
}

// No destination is resolved or connected here. A zero requested port asks the
// kernel to reserve a port on the live socket; the controller must read that
// actual port before admitting its PF rule. Path checks bracket creation but
// are not atomic interface-generation or future route-lifetime guarantees.
func openPFDatagram(path pfInterface, source netip.Addr, port uint16) (pfDatagram, error) {
	if os.Geteuid() != 0 || validatePFDatagramSource(path, source) != nil {
		return nil, ErrRecoveryRequired
	}
	network, level, option := "udp4", unix.IPPROTO_IP, unix.IP_BOUND_IF
	if source.Is6() {
		network, level, option = "udp6", unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
	}
	udp, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(source, port)))
	if err != nil {
		return nil, err
	}
	accepted := false
	defer func() {
		if !accepted {
			_ = udp.Close()
		}
	}()
	raw, err := udp.SyscallConn()
	if err != nil {
		return nil, ErrRecoveryRequired
	}
	var socketErr error
	boundIndex := 0
	err = raw.Control(func(fd uintptr) {
		socketErr = unix.SetsockoptInt(int(fd), level, option, path.index)
		if socketErr == nil {
			boundIndex, socketErr = unix.GetsockoptInt(int(fd), level, option)
		}
	})
	if err != nil || socketErr != nil || boundIndex != path.index {
		return nil, ErrRecoveryRequired
	}
	local, ok := udp.LocalAddr().(*net.UDPAddr)
	if !ok || local.AddrPort().Addr().Unmap() != source || local.Port < 1 || local.Port > 65535 || local.Zone != "" || (port != 0 && local.Port != int(port)) || validatePFDatagramSource(path, source) != nil || udp.SetDeadline(time.Time{}) != nil {
		return nil, ErrRecoveryRequired
	}
	accepted = true
	return udp, nil
}
