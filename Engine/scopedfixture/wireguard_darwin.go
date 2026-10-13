// Experimental packet transport and encrypted fixture, never linked into the
// product. Official device/crypto/tun/endpoint implementations stay unchanged.
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	configcore "legacywg/ConfigCore"
)

type packetLease struct {
	socket net.PacketConn
	closed atomic.Bool
}
type packetBind struct {
	mutex   sync.Mutex
	lease   *packetLease
	factory func(uint16) (net.PacketConn, error)
	opens   atomic.Int64
}

var _ conn.Bind = (*packetBind)(nil)

func (bind *packetBind) BatchSize() int { return 1 }
func (bind *packetBind) SetMark(mark uint32) error {
	if mark != 0 {
		return errors.New("experimental transport does not implement marks")
	}
	return nil
}
func (bind *packetBind) ParseEndpoint(text string) (conn.Endpoint, error) {
	address, err := netip.ParseAddrPort(text)
	if err != nil || address.Addr().Zone() != "" || address.Addr().Is4In6() || address.Addr().IsUnspecified() || address.Addr().IsMulticast() || address.Port() == 0 {
		return nil, errors.New("experimental endpoint refused")
	}
	return &conn.StdNetEndpoint{AddrPort: address}, nil
}
func (bind *packetBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	bind.mutex.Lock()
	defer bind.mutex.Unlock()
	if bind.lease != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	socket, err := bind.factory(port)
	if err != nil {
		return nil, 0, err
	}
	local, ok := socket.LocalAddr().(*net.UDPAddr)
	if !ok || local.Port < 1 || local.Port > 65535 {
		socket.Close()
		return nil, 0, errors.New("experimental socket port unavailable")
	}
	lease := &packetLease{socket: socket}
	bind.lease = lease
	bind.opens.Add(1)
	receive := func(buffers [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
		if len(buffers) != 1 || len(sizes) < 1 || len(endpoints) < 1 {
			return 0, errors.New("experimental receive batch refused")
		}
		size, remote, err := lease.socket.ReadFrom(buffers[0])
		if lease.closed.Load() {
			return 0, net.ErrClosed
		}
		if err != nil {
			return 0, err
		}
		udp, ok := remote.(*net.UDPAddr)
		if !ok {
			return 0, errors.New("experimental remote address unavailable")
		}
		address, ok := netip.AddrFromSlice(udp.IP)
		if !ok || udp.Zone != "" || udp.Port < 1 || udp.Port > 65535 {
			return 0, errors.New("experimental remote address refused")
		}
		sizes[0] = size
		endpoints[0] = &conn.StdNetEndpoint{AddrPort: netip.AddrPortFrom(address.Unmap(), uint16(udp.Port))}
		return 1, nil
	}
	return []conn.ReceiveFunc{receive}, uint16(local.Port), nil
}
func (bind *packetBind) Close() error {
	bind.mutex.Lock()
	lease := bind.lease
	bind.lease = nil
	if lease != nil {
		lease.closed.Store(true)
	}
	bind.mutex.Unlock()
	if lease == nil {
		return nil
	}
	return lease.socket.Close()
}
func (bind *packetBind) Send(buffers [][]byte, endpoint conn.Endpoint) error {
	remote, ok := endpoint.(*conn.StdNetEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	if len(buffers) > 1 {
		return errors.New("experimental send batch refused")
	}
	bind.mutex.Lock()
	lease := bind.lease
	bind.mutex.Unlock()
	if lease == nil || lease.closed.Load() {
		return net.ErrClosed
	}
	for _, buffer := range buffers {
		count, err := lease.socket.WriteTo(buffer, net.UDPAddrFromAddrPort(remote.AddrPort))
		if err != nil {
			return err
		}
		if count != len(buffer) {
			return errors.New("experimental partial datagram")
		}
	}
	return nil
}

func leaseProof(factory func(uint16) (net.PacketConn, error)) error {
	bind := &packetBind{factory: factory}
	defer bind.Close()
	functions, _, err := bind.Open(0)
	if err != nil {
		return err
	}
	if bind.Close() != nil {
		return errors.New("experimental close failed")
	}
	readOld := func() bool {
		_, err := functions[0]([][]byte{make([]byte, 65535)}, make([]int, 1), make([]conn.Endpoint, 1))
		return errors.Is(err, net.ErrClosed)
	}
	if !readOld() {
		return errors.New("old receive callback did not close")
	}
	if _, _, err = bind.Open(0); err != nil {
		return err
	}
	if !readOld() {
		return errors.New("old receive callback revived after reopen")
	}
	return nil
}

func ephemeralKeys() (string, string, error) {
	var private [32]byte
	if _, err := rand.Read(private[:]); err != nil {
		return "", "", errors.New("ephemeral test key generation failed")
	}
	defer clear(private[:])
	public, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		return "", "", errors.New("official test public key derivation failed")
	}
	return base64.StdEncoding.EncodeToString(private[:]), base64.StdEncoding.EncodeToString(public), nil
}
func configure(engine *device.Device, profile string, endpoints []netip.AddrPort) error {
	config, err := configcore.Parse([]byte(profile))
	if err != nil {
		return errors.New("encrypted fixture profile refused")
	}
	defer config.Destroy()
	var buffer bytes.Buffer
	if config.WriteUAPI(&buffer, endpoints) != nil {
		return errors.New("encrypted fixture UAPI creation failed")
	}
	err = engine.IpcSet(buffer.String())
	clear(buffer.Bytes())
	if err != nil {
		return errors.New("official encrypted fixture UAPI failed")
	}
	return nil
}

type encryptedFixture struct {
	client, server *device.Device
	transport      *packetBind
	socket         net.Conn
	remote         netip.Addr
	serial         int
}

func (fixture *encryptedFixture) close() {
	fixture.socket.Close()
	fixture.client.Close()
	fixture.server.Close()
}

func startEncrypted(outerStack *netstack.Net, local, remote netip.Addr, before kernelPath) (*encryptedFixture, error) {
	factory := admittedFactory(local, remote, before)
	if err := leaseProof(factory); err != nil {
		return nil, err
	}
	clientIP, serverIP := netip.MustParseAddr("198.18.88.1"), netip.MustParseAddr("198.18.88.2")
	if remote.Is6() {
		clientIP, serverIP = netip.MustParseAddr("2001:db8:88::1"), netip.MustParseAddr("2001:db8:88::2")
	}
	clientTun, clientStack, err := netstack.CreateNetTUN([]netip.Addr{clientIP}, nil, 1420)
	if err != nil {
		return nil, errors.New("encrypted client stack failed")
	}
	serverTun, serverStack, err := netstack.CreateNetTUN([]netip.Addr{serverIP}, nil, 1420)
	if err != nil {
		clientTun.Close()
		return nil, errors.New("encrypted server stack failed")
	}
	clientBind := &packetBind{factory: factory}
	serverBind := &packetBind{factory: func(port uint16) (net.PacketConn, error) {
		if port != 54324 {
			return nil, errors.New("fixture server port refused")
		}
		return outerStack.ListenUDPAddrPort(netip.AddrPortFrom(remote, port))
	}}
	client := device.NewDevice(clientTun, clientBind, device.NewLogger(device.LogLevelSilent, ""))
	server := device.NewDevice(serverTun, serverBind, device.NewLogger(device.LogLevelSilent, ""))
	fail := func() (*encryptedFixture, error) {
		client.Close()
		server.Close()
		return nil, errors.New("official encrypted fixture start failed")
	}
	cp, cu, err := ephemeralKeys()
	if err != nil {
		return fail()
	}
	sp, su, err := ephemeralKeys()
	if err != nil {
		return fail()
	}
	bits := clientIP.BitLen()
	serverProfile := fmt.Sprintf("[Interface]\nPrivateKey=%s\nAddress=%s/%d\nListenPort=54324\n[Peer]\nPublicKey=%s\nAllowedIPs=%s/%d\n", sp, serverIP, bits, cu, clientIP, bits)
	clientProfile := fmt.Sprintf("[Interface]\nPrivateKey=%s\nAddress=%s/%d\n[Peer]\nPublicKey=%s\nEndpoint=%s\nAllowedIPs=%s/%d\n", cp, clientIP, bits, su, net.JoinHostPort(remote.String(), "54324"), serverIP, bits)
	if configure(server, serverProfile, []netip.AddrPort{{}}) != nil || configure(client, clientProfile, []netip.AddrPort{netip.AddrPortFrom(remote, 54324)}) != nil || server.Up() != nil || client.Up() != nil {
		return fail()
	}
	echo, err := serverStack.ListenUDPAddrPort(netip.AddrPortFrom(serverIP, 54325))
	if err != nil {
		return fail()
	}
	go func() {
		defer echo.Close()
		buffer := make([]byte, 512)
		for {
			size, from, err := echo.ReadFrom(buffer)
			if err != nil {
				return
			}
			if _, err = echo.WriteTo(buffer[:size], from); err != nil {
				return
			}
		}
	}()
	packet, err := clientStack.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(serverIP, 54325))
	if err != nil {
		return fail()
	}
	return &encryptedFixture{client: client, server: server, transport: clientBind, socket: packet, remote: serverIP}, nil
}
func (fixture *encryptedFixture) roundTrip() bool {
	fixture.serial++
	payload := []byte(fmt.Sprintf("LegacyWG scoped encrypted payload %d", fixture.serial))
	fixture.socket.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	if _, err := fixture.socket.Write(payload); err != nil {
		return false
	}
	buffer := make([]byte, 512)
	size, err := fixture.socket.Read(buffer)
	return err == nil && bytes.Equal(buffer[:size], payload)
}
func officialStats(engine *device.Device) bool {
	text, err := engine.IpcGet()
	if err != nil {
		return false
	}
	totals := map[string]uint64{}
	for _, line := range strings.Split(text, "\n") {
		field, value, ok := strings.Cut(line, "=")
		if ok && (field == "last_handshake_time_sec" || field == "rx_bytes" || field == "tx_bytes") {
			number, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return false
			}
			totals[field] += number
		}
	}
	return totals["last_handshake_time_sec"] > 0 && totals["rx_bytes"] > 0 && totals["tx_bytes"] > 0
}
