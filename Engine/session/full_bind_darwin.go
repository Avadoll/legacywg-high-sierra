package session

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	networkcore "legacywg/NetworkCore"
)

var errFullPath = errors.New("full tunnel endpoint path unavailable")

// One peer, one numeric endpoint address for this connection. A fresh Connect
// is required for IP roaming. This adapter never changes vendor/crypto code,
// installs a host route, or falls back to an unscoped UDP socket.
type fullBind struct {
	mutex    sync.Mutex
	remote   netip.Addr
	path     networkcore.Path
	scoped   networkcore.ScopedPath
	loopback bool
	socket   *fullSocket
	ended    atomic.Bool
}

type fullSocket struct {
	udp    *net.UDPConn
	closed atomic.Bool
}

var _ conn.Bind = (*fullBind)(nil)

func prepareFullBind(ctx context.Context, endpoints []netip.AddrPort) (*fullBind, error) {
	if len(endpoints) != 1 || !endpoints[0].IsValid() {
		return nil, errFullPath
	}
	address := endpoints[0].Addr()
	before, err := networkcore.EndpointRoute(ctx, address)
	if err != nil {
		return nil, errFullPath
	}
	bind := &fullBind{remote: address, path: before, loopback: address.IsLoopback()}
	if !bind.loopback {
		bind.scoped, err = networkcore.SocketRoute(ctx, address, before.InterfaceIndex)
		if err != nil || bind.scoped.Path != before {
			return nil, errFullPath
		}
	}
	if bind.verify(ctx) != nil {
		return nil, errFullPath
	}
	return bind, nil
}

func (bind *fullBind) verify(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || bind.ended.Load() {
		return errFullPath
	}
	iface, err := net.InterfaceByName(bind.path.InterfaceName)
	if err != nil || iface.Index != bind.path.InterfaceIndex || iface.Flags&net.FlagUp == 0 {
		return errFullPath
	}
	if bind.loopback {
		path, err := networkcore.EndpointRoute(ctx, bind.remote)
		if err != nil || path != bind.path {
			return errFullPath
		}
	} else {
		path, err := networkcore.SocketRoute(ctx, bind.remote, bind.path.InterfaceIndex)
		if err != nil || path != bind.scoped {
			return errFullPath
		}
	}
	return ctx.Err()
}

func (*fullBind) BatchSize() int { return 1 }
func (*fullBind) SetMark(mark uint32) error {
	if mark != 0 {
		return errFullPath
	}
	return nil
}
func (bind *fullBind) ParseEndpoint(text string) (conn.Endpoint, error) {
	address, err := netip.ParseAddrPort(text)
	if err != nil || address.Port() == 0 || address.Addr() != bind.remote {
		return nil, errFullPath
	}
	return &conn.StdNetEndpoint{AddrPort: address}, nil
}

func (bind *fullBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	bind.mutex.Lock()
	defer bind.mutex.Unlock()
	if bind.socket != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if bind.verify(ctx) != nil {
		return nil, 0, errFullPath
	}
	family, level, option, address := "udp4", unix.IPPROTO_IP, unix.IP_BOUND_IF, "0.0.0.0"
	if bind.remote.Is6() {
		family, level, option, address = "udp6", unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, "::"
	}
	config := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var failure error
		err := raw.Control(func(fd uintptr) {
			failure = unix.SetsockoptInt(int(fd), level, option, bind.path.InterfaceIndex)
			if failure == nil {
				actual, err := unix.GetsockoptInt(int(fd), level, option)
				if err != nil || actual != bind.path.InterfaceIndex {
					failure = errFullPath
				}
			}
		})
		if err != nil {
			return err
		}
		return failure
	}}
	packet, err := config.ListenPacket(ctx, family, net.JoinHostPort(address, strconv.Itoa(int(port))))
	if err != nil {
		return nil, 0, errFullPath
	}
	udp, ok := packet.(*net.UDPConn)
	if !ok || bind.verify(ctx) != nil {
		packet.Close()
		return nil, 0, errFullPath
	}
	lease := &fullSocket{udp: udp}
	bind.socket = lease
	receive := func(buffers [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
		if len(buffers) != 1 || len(sizes) < 1 || len(endpoints) < 1 {
			return 0, errFullPath
		}
		for {
			n, remote, err := udp.ReadFromUDPAddrPort(buffers[0])
			if lease.closed.Load() {
				return 0, net.ErrClosed
			}
			if err != nil {
				return 0, err
			}
			// Unknown source addresses never become a new unverified route.
			if remote.Addr() != bind.remote {
				continue
			}
			sizes[0] = n
			endpoints[0] = &conn.StdNetEndpoint{AddrPort: remote}
			return 1, nil
		}
	}
	return []conn.ReceiveFunc{receive}, uint16(udp.LocalAddr().(*net.UDPAddr).Port), nil
}

func (bind *fullBind) Close() error {
	bind.mutex.Lock()
	lease := bind.socket
	bind.socket = nil
	if lease != nil {
		lease.closed.Store(true)
	}
	bind.mutex.Unlock()
	if lease == nil {
		return nil
	}
	return lease.udp.Close()
}

func (bind *fullBind) Send(buffers [][]byte, endpoint conn.Endpoint) error {
	remote, ok := endpoint.(*conn.StdNetEndpoint)
	if !ok || remote.AddrPort.Addr() != bind.remote || remote.AddrPort.Port() == 0 || len(buffers) > 1 || bind.ended.Load() {
		return errFullPath
	}
	bind.mutex.Lock()
	lease := bind.socket
	bind.mutex.Unlock()
	if lease == nil || lease.closed.Load() {
		return net.ErrClosed
	}
	for _, buffer := range buffers {
		n, err := lease.udp.WriteToUDPAddrPort(buffer, remote.AddrPort)
		if err != nil {
			return err
		}
		if n != len(buffer) {
			return errFullPath
		}
	}
	return nil
}

func (bind *fullBind) stop() error {
	bind.ended.Store(true)
	return bind.Close()
}
