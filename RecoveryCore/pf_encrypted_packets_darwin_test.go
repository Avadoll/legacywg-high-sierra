package recoverycore

// Disposable CI topology only. The client uses the unchanged official Darwin
// StdNetBind and native inner utun; the isolated peer uses a netstack transport.
// No installed request, physical interface or default route uses this fixture.
import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type pfObservedTUN struct {
	tun.Device
	capture *pfPacketObservation
}

// The upstream isolated netstack closes channels and must be closed once.
// Both partial setup cleanup and Device.Close share this fixture-owned wrapper.
type pfOnceTUN struct {
	tun.Device
	once       sync.Once
	closeError error
}

func (link *pfOnceTUN) Close() error {
	link.once.Do(func() { link.closeError = link.Device.Close() })
	return link.closeError
}

func (observed *pfObservedTUN) Read(buffers [][]byte, sizes []int, offset int) (int, error) {
	n, err := observed.Device.Read(buffers, sizes, offset)
	for i := 0; i < n; i++ {
		if sizes[i] > 0 && sizes[i] <= len(buffers[i])-offset {
			observed.capture.observe(buffers[i][offset : offset+sizes[i]])
		}
	}
	return n, err
}

// Minimal single-family peer adapter. Only public conn.Bind interfaces are
// implemented; authentication, encryption and endpoint learning remain upstream.
type pfPeerPacketBind struct {
	mu      sync.Mutex
	stack   *netstack.Net
	address netip.Addr
	socket  net.PacketConn
}

func (*pfPeerPacketBind) BatchSize() int { return 1 }
func (*pfPeerPacketBind) SetMark(mark uint32) error {
	if mark != 0 {
		return errors.New("fixture mark refused")
	}
	return nil
}
func (*pfPeerPacketBind) ParseEndpoint(text string) (conn.Endpoint, error) {
	address, err := netip.ParseAddrPort(text)
	if err != nil || address.Port() == 0 || address.Addr().Is4In6() || address.Addr().Zone() != "" {
		return nil, errors.New("fixture endpoint refused")
	}
	return &conn.StdNetEndpoint{AddrPort: address}, nil
}
func (bind *pfPeerPacketBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	bind.mu.Lock()
	defer bind.mu.Unlock()
	if bind.socket != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	if port != 45121 {
		return nil, 0, errors.New("fixture peer port refused")
	}
	socket, err := bind.stack.ListenUDPAddrPort(netip.AddrPortFrom(bind.address, port))
	if err != nil {
		return nil, 0, err
	}
	bind.socket = socket
	receive := func(buffers [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
		if len(buffers) != 1 || len(sizes) < 1 || len(endpoints) < 1 {
			return 0, errors.New("fixture receive batch refused")
		}
		n, remote, err := socket.ReadFrom(buffers[0])
		if err != nil {
			return 0, err
		}
		address, ok := remote.(*net.UDPAddr)
		if !ok {
			return 0, errors.New("fixture source refused")
		}
		ip, ok := netip.AddrFromSlice(address.IP)
		if !ok || address.Zone != "" || address.Port < 1 || address.Port > 65535 {
			return 0, errors.New("fixture source refused")
		}
		sizes[0] = n
		endpoints[0] = &conn.StdNetEndpoint{AddrPort: netip.AddrPortFrom(ip.Unmap(), uint16(address.Port))}
		return 1, nil
	}
	return []conn.ReceiveFunc{receive}, port, nil
}
func (bind *pfPeerPacketBind) Close() error {
	bind.mu.Lock()
	socket := bind.socket
	bind.socket = nil
	bind.mu.Unlock()
	if socket == nil {
		return nil
	}
	return socket.Close()
}
func (bind *pfPeerPacketBind) Send(buffers [][]byte, endpoint conn.Endpoint) error {
	remote, ok := endpoint.(*conn.StdNetEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	bind.mu.Lock()
	socket := bind.socket
	bind.mu.Unlock()
	if socket == nil {
		return net.ErrClosed
	}
	for _, buffer := range buffers {
		n, err := socket.WriteTo(buffer, net.UDPAddrFromAddrPort(remote.AddrPort))
		if err != nil {
			return err
		}
		if n != len(buffer) {
			return io.ErrShortWrite
		}
	}
	return nil
}

func pfEphemeralKey(t *testing.T) (string, string) {
	t.Helper()
	var private [32]byte
	if _, err := rand.Read(private[:]); err != nil {
		t.Fatal("fixture ephemeral entropy unavailable")
	}
	defer clear(private[:])
	public, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal("fixture public key derivation failed")
	}
	return hex.EncodeToString(private[:]), hex.EncodeToString(public)
}

func pfEncryptedEcho(ctx context.Context, iface *net.Interface, family, protocol, port int, source, address string, timeout time.Duration) bool {
	network := "udp4"
	if family == 6 {
		network = "udp6"
	}
	if protocol == 6 {
		network = "tcp4"
		if family == 6 {
			network = "tcp6"
		}
	}
	bind := func(raw syscall.RawConn) error {
		var result error
		err := raw.Control(func(fd uintptr) {
			level, option := unix.IPPROTO_IP, unix.IP_BOUND_IF
			if family == 6 {
				level, option = unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
			}
			result = unix.SetsockoptInt(int(fd), level, option, iface.Index)
		})
		if err != nil {
			return err
		}
		return result
	}
	var connection net.Conn
	var err error
	if protocol == 6 {
		dialer := net.Dialer{Timeout: timeout, LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}, Control: func(_, _ string, raw syscall.RawConn) error { return bind(raw) }}
		connection, err = dialer.DialContext(ctx, network, net.JoinHostPort(address, fmtPort(port)))
	} else {
		udp, listenErr := net.ListenUDP(network, &net.UDPAddr{IP: net.ParseIP(source)})
		err = listenErr
		if err == nil {
			raw, rawErr := udp.SyscallConn()
			err = rawErr
			if err == nil {
				err = bind(raw)
			}
			if err != nil {
				udp.Close()
			} else {
				connection = &pfFixtureUDPConnection{udp, &net.UDPAddr{IP: net.ParseIP(address), Port: port}}
			}
		}
	}
	if err != nil {
		return false
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(timeout))
	query := bytes.Repeat([]byte{0x47}, 32)
	if port == 53 {
		query = pfDNSQuery()
	}
	frame := func(data []byte) []byte {
		if port == 53 && protocol == 6 {
			var prefix [2]byte
			binary.BigEndian.PutUint16(prefix[:], uint16(len(data)))
			return append(prefix[:], data...)
		}
		return data
	}
	if _, err = connection.Write(frame(query)); err != nil {
		return false
	}
	want := frame(pfFixtureResponse(query, port == 53))
	got := make([]byte, len(want))
	_, err = io.ReadFull(connection, got)
	return err == nil && bytes.Equal(got, want)
}

func TestRootPFRuleEncryptedPackets(t *testing.T) {
	requirePFRuleCI(t)
	if os.Getenv("LEGACYWG_PF_ENCRYPTED_PACKET_TESTS") != "1" {
		t.Skip("explicit disposable encrypted packet test")
	}
	for _, outerFamily := range []int{4, 6} {
		t.Run(fmt.Sprintf("outer%d", outerFamily), func(t *testing.T) { pfEncryptedPacketFamily(t, outerFamily) })
	}
}

func pfEncryptedPacketFamily(t *testing.T, outerFamily int) {
	store := realBootStore(t, ownedReferenceTestDirectory(t))
	defer store.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	if store.begin() != nil {
		t.Fatal("encrypted interface intent failed")
	}
	outer, err := tun.CreateTUN("utun", 1420)
	if err != nil {
		t.Fatal("encrypted outer interface failed")
	}
	defer outer.Close()
	outerPeer, outerStack, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(pfPacketServer4), netip.MustParseAddr(pfPacketServer6)}, nil, 1420)
	if err != nil {
		t.Fatal("encrypted outer stack failed")
	}
	outerCapture := &pfPacketObservation{counts: make(map[pfPacketKey]int)}
	done := make(chan struct{}, 2)
	go pfPacketBridge(outer, outerPeer, outerCapture, done)
	go pfPacketBridge(outerPeer, outer, nil, done)
	defer func() {
		outer.Close()
		outerPeer.Close()
		for i := 0; i < 2; i++ {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("encrypted outer bridge close failed")
			}
		}
	}()
	inner, err := tun.CreateTUN("utun", 1280)
	if err != nil {
		t.Fatal("encrypted inner interface failed")
	}
	defer inner.Close()
	innerCapture := &pfPacketObservation{counts: make(map[pfPacketKey]int), server4: net.ParseIP("198.18.100.130").To4(), server6: net.ParseIP("fd00:198:18:100::130").To16()}
	serverTUN, serverStack, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("198.18.100.130"), netip.MustParseAddr("fd00:198:18:100::130")}, nil, 1280)
	if err != nil {
		t.Fatal("encrypted inner peer failed")
	}
	serverTUN = &pfOnceTUN{Device: serverTUN}
	defer serverTUN.Close()
	var listeners []net.Listener
	var datagrams []net.PacketConn
	var client, peer *device.Device
	defer func() {
		for _, l := range listeners {
			l.Close()
		}
		for _, d := range datagrams {
			d.Close()
		}
	}()
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 25*time.Second)
		defer stop()
		failed := store.pfResidue() && store.recoverPFLifecycle(cleanup) != nil
		if client != nil {
			client.Close()
		}
		if peer != nil {
			peer.Close()
		}
		inner.Close()
		if failed {
			t.Error("encrypted PF cleanup ownership retained")
			return
		}
		if store.Finish() != nil {
			t.Error("encrypted journal cleanup failed")
		}
	}()
	command := func(program string, args ...string) {
		op := exec.CommandContext(ctx, program, args...)
		op.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}
		if op.Run() != nil {
			t.Fatal("fixed encrypted topology operation failed")
		}
	}
	setup := func(link tun.Device, four, six string) *net.Interface {
		name, err := link.Name()
		if err != nil || !utunName.MatchString(name) {
			t.Fatal("encrypted topology identity failed")
		}
		command("/sbin/ifconfig", name, "inet", four, four, "netmask", "255.255.255.255", "alias")
		command("/sbin/ifconfig", name, "inet6", six, "prefixlen", "128", "alias")
		command("/sbin/ifconfig", name, "up")
		iface, err := net.InterfaceByName(name)
		if err != nil {
			t.Fatal("encrypted topology index failed")
		}
		return iface
	}
	outerIface := setup(outer, "198.18.99.129", "fd00:198:18:99::129")
	innerIface := setup(inner, "198.18.100.129", "fd00:198:18:100::129")
	if store.MarkInterface(innerIface.Name, innerIface.Index) != nil {
		t.Fatal("encrypted inner journal identity failed")
	}
	for _, route := range []struct{ family, address, name string }{{"-inet", pfPacketServer4, outerIface.Name}, {"-inet6", pfPacketServer6, outerIface.Name}, {"-inet", "198.18.100.130", innerIface.Name}, {"-inet6", "fd00:198:18:100::130", innerIface.Name}} {
		command("/sbin/route", "-n", "add", route.family, "-host", route.address, "-interface", route.name)
	}
	remote, source := pfPacketServer4, "198.18.99.129"
	if outerFamily == 6 {
		remote, source = pfPacketServer6, "fd00:198:18:99::129"
	}
	client = device.NewDevice(&pfObservedTUN{inner, innerCapture}, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))
	peer = device.NewDevice(serverTUN, &pfPeerPacketBind{stack: outerStack, address: netip.MustParseAddr(remote)}, device.NewLogger(device.LogLevelSilent, ""))
	cp, cu := pfEphemeralKey(t)
	sp, su := pfEphemeralKey(t)
	if peer.IpcSet("private_key="+sp+"\nlisten_port=45121\npublic_key="+cu+"\nallowed_ip=198.18.100.129/32\nallowed_ip=fd00:198:18:100::129/128\n") != nil ||
		client.IpcSet("private_key="+cp+"\npublic_key="+su+"\nendpoint="+net.JoinHostPort(remote, "45121")+"\nallowed_ip=198.18.100.130/32\nallowed_ip=fd00:198:18:100::130/128\n") != nil || peer.Up() != nil || client.Up() != nil {
		t.Fatal("official encrypted device configuration failed")
	}
	cp, sp = "", "" // No key/configuration is printed or exported.
	for _, address := range []string{"198.18.100.130", "fd00:198:18:100::130"} {
		for _, port := range []uint16{45121, 53} {
			endpoint := netip.AddrPortFrom(netip.MustParseAddr(address), port)
			udp, err := serverStack.ListenUDPAddrPort(endpoint)
			if err != nil {
				t.Fatal("encrypted UDP listener failed")
			}
			datagrams = append(datagrams, udp)
			go pfServeUDPEcho(udp, port == 53)
			tcp, err := serverStack.ListenTCPAddrPort(endpoint)
			if err != nil {
				t.Fatal("encrypted TCP listener failed")
			}
			listeners = append(listeners, tcp)
			go pfServeTCPEcho(tcp, port == 53)
		}
	}
	phase := func(label string, innerAllowed, outerAllowed, allowed bool) {
		t.Helper()
		for _, family := range []int{4, 6} {
			for _, protocol := range []int{17, 6} {
				for _, port := range []int{45121, 53} {
					source, address := "198.18.100.129", "198.18.100.130"
					if family == 6 {
						source, address = "fd00:198:18:100::129", "fd00:198:18:100::130"
					}
					key := pfPacketKey{family, protocol, port}
					outerKey := pfPacketKey{outerFamily, 17, 45121}
					beforeInner, beforeOuter := innerCapture.count(key), outerCapture.count(outerKey)
					timeout := 650 * time.Millisecond
					if allowed {
						timeout = 4 * time.Second
					}
					succeeded := pfEncryptedEcho(ctx, innerIface, family, protocol, port, source, address, timeout)
					time.Sleep(100 * time.Millisecond)
					innerDelta, outerDelta := innerCapture.count(key)-beforeInner, outerCapture.count(outerKey)-beforeOuter
					if succeeded != allowed || (!innerAllowed && innerDelta != 0) || (!outerAllowed && outerDelta != 0) || (allowed && (innerDelta < 1 || outerDelta < 1)) {
						t.Fatalf("encrypted phase %s family=%d protocol=%d dns=%t failed", label, family, protocol, port == 53)
					}
				}
			}
		}
	}
	phase("baseline", true, true, true)
	if store.stageDisabledPFAnchor(ctx) != nil || store.activatePFAnchor(ctx) != nil {
		t.Fatal("encrypted durable guard activation failed")
	}
	phase("deny", false, false, false)
	tunnel := &pfInterface{innerIface.Name, innerIface.Index}
	escape := pfUDPEscape{pfInterface{outerIface.Name, outerIface.Index}, netip.MustParseAddr(source), netip.AddrPortFrom(netip.MustParseAddr(remote), 45121)}
	if store.updatePFPolicy(ctx, pfPolicy{tunnel: tunnel}) != nil {
		t.Fatal("encrypted tunnel-only policy failed")
	}
	phase("tunnel-only", true, false, false)
	if store.updatePFPolicy(ctx, pfPolicy{escapes: []pfUDPEscape{escape}}) != nil {
		t.Fatal("encrypted outer-only policy failed")
	}
	phase("outer-only", false, true, false)
	if store.updatePFPolicy(ctx, pfPolicy{tunnel: tunnel, escapes: []pfUDPEscape{escape}}) != nil {
		t.Fatal("encrypted complete policy failed")
	}
	phase("protected", true, true, true)
	if store.updatePFPolicy(ctx, pfPolicy{tunnel: tunnel}) != nil {
		t.Fatal("encrypted outer removal failed")
	}
	phase("outer-removed", true, false, false)
	if store.updatePFPolicy(ctx, pfPolicy{tunnel: tunnel, escapes: []pfUDPEscape{escape}}) != nil {
		t.Fatal("encrypted outer restore failed")
	}
	phase("outer-restored", true, true, true)
	if store.updatePFPolicy(ctx, pfPolicy{escapes: []pfUDPEscape{escape}}) != nil {
		t.Fatal("encrypted inner removal failed")
	}
	phase("inner-removed", false, true, false)
	record, err := store.readPF(pfJournalFile)
	if err != nil || record == nil {
		t.Fatal("encrypted PF intent missing")
	}
	if store.recoverPFLifecycle(ctx) != nil || store.pfResidue() || len(fixturePFReferences(t, ctx)) != 0 {
		t.Fatal("encrypted PF recovery failed")
	}
	after, err := readDisabledPF(ctx, record.Anchor)
	if err != nil || !after.matches(*record) || after.rules != pfDigest("") {
		t.Fatal("encrypted PF baseline differs")
	}
	phase("recovered", true, true, true)
}
