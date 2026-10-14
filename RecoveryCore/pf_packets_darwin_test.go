package recoverycore

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
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

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func TestRootPFRulePacketGuardCrashChild(t *testing.T) {
	path := os.Getenv("LEGACYWG_PACKET_CRASH_DIR")
	if path == "" {
		t.Skip("explicit packet guard crash child")
	}
	requirePFRuleCI(t)
	store := realBootStore(t, path)
	defer store.Close()
	ctx, stop := context.WithTimeout(context.Background(), 30*time.Second)
	defer stop()
	if store.stageDisabledPFAnchor(ctx) != nil || store.activatePFAnchor(ctx) != nil {
		t.Fatal("packet crash child guard activation failed")
	}
	fmt.Println("OWNED_PACKET_GUARD_ACTIVE")
	select {}
}

const pfPacketServer4 = "198.18.99.130"
const pfPacketServer6 = "fd00:198:18:99::130"

type pfPacketKey struct{ family, protocol, port int }
type pfPacketObservation struct {
	sync.Mutex
	counts map[pfPacketKey]int
}

// Match the unconnected WriteMsgUDP API used by official StdNetBind on Darwin.
// Connected UDP Write is a separate observed runtime/kernel compatibility issue.
type pfFixtureUDPConnection struct {
	*net.UDPConn
	destination *net.UDPAddr
}

func (connection *pfFixtureUDPConnection) Write(data []byte) (int, error) {
	n, _, err := connection.WriteMsgUDP(data, nil, connection.destination)
	return n, err
}

func (connection *pfFixtureUDPConnection) Read(data []byte) (int, error) {
	n, address, err := connection.ReadFromUDP(data)
	if err == nil && (!address.IP.Equal(connection.destination.IP) || address.Port != connection.destination.Port) {
		return 0, io.ErrUnexpectedEOF
	}
	return n, err
}

func (connection *pfFixtureUDPConnection) RemoteAddr() net.Addr { return connection.destination }

func (capture *pfPacketObservation) observe(packet []byte) {
	var family, protocol, offset int
	if len(packet) >= 20 && packet[0]>>4 == 4 {
		family, protocol, offset = 4, int(packet[9]), int(packet[0]&15)*4
		if offset < 20 || !bytes.Equal(packet[16:20], net.ParseIP(pfPacketServer4).To4()) {
			return
		}
	} else if len(packet) >= 40 && packet[0]>>4 == 6 {
		family, protocol, offset = 6, int(packet[6]), 40
		if !bytes.Equal(packet[24:40], net.ParseIP(pfPacketServer6).To16()) {
			return
		}
	} else {
		return
	}
	if (protocol != 6 && protocol != 17) || len(packet) < offset+4 {
		return
	}
	port := int(binary.BigEndian.Uint16(packet[offset+2 : offset+4]))
	if port != 45121 && port != 45122 && port != 53 {
		return
	}
	capture.Lock()
	capture.counts[pfPacketKey{family, protocol, port}]++
	capture.Unlock()
}

func (capture *pfPacketObservation) count(key pfPacketKey) int {
	capture.Lock()
	defer capture.Unlock()
	return capture.counts[key]
}

func pfPacketBridge(source, destination tun.Device, capture *pfPacketObservation, done chan<- struct{}) {
	defer func() { done <- struct{}{} }()
	buffer := make([]byte, 65536)
	for {
		sizes := []int{0}
		n, err := source.Read([][]byte{buffer}, sizes, 4)
		if err != nil || n != 1 || sizes[0] < 1 || sizes[0] > len(buffer)-4 {
			return
		}
		if capture != nil {
			capture.observe(buffer[4 : 4+sizes[0]])
		}
		if _, err := destination.Write([][]byte{buffer[:4+sizes[0]]}, 4); err != nil {
			return
		}
	}
}

func pfDNSQuery() []byte {
	return []byte{0x47, 0x57, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 5, 'g', 'u', 'a', 'r', 'd', 7, 'i', 'n', 'v', 'a', 'l', 'i', 'd', 0, 0, 1, 0, 1}
}

func pfFixtureResponse(query []byte, dns bool) []byte {
	response := append([]byte(nil), query...)
	if dns && len(response) >= 12 {
		response[2] |= 128
	}
	return response
}

func pfServeUDPEcho(connection net.PacketConn, dns bool) {
	defer connection.Close()
	buffer := make([]byte, 512)
	for {
		n, address, err := connection.ReadFrom(buffer)
		if err != nil {
			return
		}
		if n > 256 || (dns && !bytes.Equal(buffer[:n], pfDNSQuery())) {
			continue
		}
		_, _ = connection.WriteTo(pfFixtureResponse(buffer[:n], dns), address)
	}
}

func pfServeTCPEcho(listener net.Listener, dns bool) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
			size := 32
			if dns {
				var prefix [2]byte
				if _, err := io.ReadFull(connection, prefix[:]); err != nil {
					return
				}
				size = int(binary.BigEndian.Uint16(prefix[:]))
				if size < 12 || size > 256 {
					return
				}
			}
			query := make([]byte, size)
			if _, err := io.ReadFull(connection, query); err != nil {
				return
			}
			if dns && !bytes.Equal(query, pfDNSQuery()) {
				return
			}
			response := pfFixtureResponse(query, dns)
			if dns {
				var prefix [2]byte
				binary.BigEndian.PutUint16(prefix[:], uint16(len(response)))
				response = append(prefix[:], response...)
			}
			_, _ = connection.Write(response)
		}()
	}
}

// Native kernel packets on one journal-owned utun and pinned netstack peer.
// This does not exercise encryption, physical NICs, OS resolver or full routes.
func TestRootPFRuleNativePackets(t *testing.T) {
	requirePFRuleCI(t)
	if os.Getenv("LEGACYWG_PF_PACKET_TESTS") != "1" {
		t.Skip("explicit disposable packet test")
	}
	store := realBootStore(t, ownedReferenceTestDirectory(t))
	defer store.Close()
	ctx, stop := context.WithTimeout(context.Background(), 150*time.Second)
	defer stop()
	if store.begin() != nil {
		t.Fatal("packet fixture interface intent unavailable")
	}
	native, err := tun.CreateTUN("utun", 1280)
	if err != nil {
		t.Fatal("packet fixture utun unavailable")
	}
	virtual, stack, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(pfPacketServer4), netip.MustParseAddr(pfPacketServer6)}, nil, 1280)
	if err != nil {
		native.Close()
		t.Fatal("pinned packet fixture stack unavailable")
	}
	var listeners []net.Listener
	var datagrams []net.PacketConn
	done := make(chan struct{}, 2)
	capture := &pfPacketObservation{counts: make(map[pfPacketKey]int)}
	go pfPacketBridge(native, virtual, capture, done)
	go pfPacketBridge(virtual, native, nil, done)
	defer func() {
		for _, listener := range listeners {
			listener.Close()
		}
		for _, connection := range datagrams {
			connection.Close()
		}
		native.Close()
		virtual.Close()
		for i := 0; i < 2; i++ {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("packet bridge did not close")
			}
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		if store.pfResidue() && store.recoverPFLifecycle(cleanup) != nil {
			t.Error("packet PF ownership retained after cleanup refusal")
			return
		}
		if store.Finish() != nil {
			t.Error("packet interface journal cleanup failed")
		}
	}()
	name, err := native.Name()
	if err != nil || !utunName.MatchString(name) {
		t.Fatal("packet fixture name unavailable")
	}
	command := func(program string, args ...string) {
		op := exec.CommandContext(ctx, program, args...)
		op.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}
		if op.Run() != nil {
			t.Fatal("fixed owned packet topology operation failed")
		}
	}
	command("/sbin/ifconfig", name, "inet", "198.18.99.129", "198.18.99.129", "netmask", "255.255.255.255", "alias")
	command("/sbin/ifconfig", name, "inet6", "fd00:198:18:99::129", "prefixlen", "128", "alias")
	command("/sbin/ifconfig", name, "up")
	iface, err := net.InterfaceByName(name)
	if err != nil || store.MarkInterface(name, iface.Index) != nil {
		t.Fatal("packet utun identity journal failed")
	}
	command("/sbin/route", "-n", "add", "-inet", "-host", pfPacketServer4, "-interface", name)
	command("/sbin/route", "-n", "add", "-inet6", "-host", pfPacketServer6, "-interface", name)
	for _, address := range []string{pfPacketServer4, pfPacketServer6} {
		for _, port := range []uint16{45121, 45122, 53} {
			endpoint := netip.AddrPortFrom(netip.MustParseAddr(address), port)
			udp, err := stack.ListenUDPAddrPort(endpoint)
			if err != nil {
				t.Fatal("owned UDP/DNS fixture listener failed")
			}
			datagrams = append(datagrams, udp)
			go pfServeUDPEcho(udp, port == 53)
			tcp, err := stack.ListenTCPAddrPort(endpoint)
			if err != nil {
				t.Fatal("owned TCP/DNS fixture listener failed")
			}
			listeners = append(listeners, tcp)
			go pfServeTCPEcho(tcp, port == 53)
		}
	}
	probe := func(family, protocol, port int, allowed bool) {
		t.Helper()
		address, source, network := pfPacketServer4, "198.18.99.129", "udp4"
		if family == 6 {
			address, source, network = pfPacketServer6, "fd00:198:18:99::129", "udp6"
		}
		if protocol == 6 {
			network = "tcp4"
			if family == 6 {
				network = "tcp6"
			}
		}
		key := pfPacketKey{family, protocol, port}
		prior := capture.count(key)
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
			dialer := net.Dialer{Timeout: 650 * time.Millisecond, LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}, Control: func(_, _ string, raw syscall.RawConn) error { return bind(raw) }}
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
		succeeded := false
		if err == nil {
			_ = connection.SetDeadline(time.Now().Add(650 * time.Millisecond))
			query := bytes.Repeat([]byte{0x47}, 32)
			if port == 53 {
				query = pfDNSQuery()
			}
			wire := query
			if port == 53 && protocol == 6 {
				var prefix [2]byte
				binary.BigEndian.PutUint16(prefix[:], uint16(len(query)))
				wire = append(prefix[:], query...)
			}
			if _, err = connection.Write(wire); err == nil {
				want := pfFixtureResponse(query, port == 53)
				if port == 53 && protocol == 6 {
					var prefix [2]byte
					binary.BigEndian.PutUint16(prefix[:], uint16(len(want)))
					want = append(prefix[:], want...)
				}
				got := make([]byte, len(want))
				_, err = io.ReadFull(connection, got)
				succeeded = err == nil && bytes.Equal(got, want)
			}
			connection.Close()
		}
		time.Sleep(100 * time.Millisecond)
		observed := capture.count(key) - prior
		if allowed && (!succeeded || observed < 1) {
			t.Fatalf("allowed kernel packet/response missing: family=%d protocol=%d dns=%t", family, protocol, port == 53)
		}
		if !allowed && (succeeded || observed != 0) {
			t.Fatalf("blocked packet reached owned peer: family=%d protocol=%d dns=%t", family, protocol, port == 53)
		}
	}
	for _, family := range []int{4, 6} {
		for _, protocol := range []int{6, 17} {
			for _, port := range []int{45121, 45122, 53} {
				probe(family, protocol, port, true)
			}
		}
	}
	if store.stageDisabledPFAnchor(ctx) != nil || store.activatePFAnchor(ctx) != nil {
		t.Fatal("durable packet guard activation failed")
	}
	for _, family := range []int{4, 6} {
		for _, protocol := range []int{6, 17} {
			for _, port := range []int{45121, 53} {
				probe(family, protocol, port, false)
			}
		}
	}
	escapes := pfPolicy{}
	for _, family := range []int{4, 6} {
		source, address := "198.18.99.129", pfPacketServer4
		if family == 6 {
			source, address = "fd00:198:18:99::129", pfPacketServer6
		}
		for _, port := range []uint16{45121, 53} {
			escapes.escapes = append(escapes.escapes, pfUDPEscape{pfInterface{name, iface.Index}, netip.MustParseAddr(source), netip.AddrPortFrom(netip.MustParseAddr(address), port)})
		}
	}
	if store.updatePFPolicy(ctx, escapes) != nil {
		t.Fatal("numeric packet exception generation failed")
	}
	for _, family := range []int{4, 6} {
		probe(family, 17, 45121, true)
		probe(family, 17, 53, true)
		probe(family, 17, 45122, false)
		probe(family, 6, 45121, false)
		probe(family, 6, 53, false)
	}
	if store.updatePFPolicy(ctx, pfPolicy{tunnel: &pfInterface{name, iface.Index}}) != nil {
		t.Fatal("journal-owned tunnel packet exception failed")
	}
	for _, family := range []int{4, 6} {
		for _, protocol := range []int{6, 17} {
			for _, port := range []int{45121, 53} {
				probe(family, protocol, port, true)
			}
		}
	}
	if store.updatePFPolicy(ctx, pfPolicy{}) != nil {
		t.Fatal("packet exceptions removal failed")
	}
	for _, family := range []int{4, 6} {
		for _, protocol := range []int{6, 17} {
			for _, port := range []int{45121, 53} {
				probe(family, protocol, port, false)
			}
		}
	}
	record, err := store.readPF(pfJournalFile)
	if err != nil || record == nil {
		t.Fatal("packet guard journal missing")
	}
	if store.recoverPFLifecycle(ctx) != nil || store.pfResidue() || len(fixturePFReferences(t, ctx)) != 0 {
		t.Fatal("packet guard final cleanup failed")
	}
	after, err := readDisabledPF(ctx, record.Anchor)
	if err != nil || !after.matches(*record) || after.rules != pfDigest("") {
		t.Fatal("packet final PF baseline differs")
	}
	// A separate process owns the deny policy while this parent's utun remains
	// alive. Actual process death must retain packet blocking until explicit
	// journal-authorized dead-owner recovery. No client runtime integration.
	crashPath := ownedReferenceTestDirectory(t)
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRootPFRulePacketGuardCrashChild$", "-test.v")
	child.Env = append(os.Environ(), "LEGACYWG_PACKET_CRASH_DIR="+crashPath)
	pipe, err := child.StdoutPipe()
	if err != nil || child.Start() != nil {
		t.Fatal("packet crash child unavailable")
	}
	defer func() { _ = child.Process.Kill() }()
	scanner := bufio.NewScanner(pipe)
	reached := false
	for scanner.Scan() {
		if scanner.Text() == "OWNED_PACKET_GUARD_ACTIVE" {
			reached = true
			break
		}
	}
	if !reached || child.Process.Kill() != nil {
		_ = child.Wait()
		t.Fatal("packet active guard actual SIGKILL not reached")
	}
	_ = child.Wait()
	for _, family := range []int{4, 6} {
		for _, protocol := range []int{6, 17} {
			for _, port := range []int{45121, 53} {
				probe(family, protocol, port, false)
			}
		}
	}
	recovery := realBootStore(t, crashPath)
	defer recovery.Close()
	crashed, err := recovery.readPF(pfJournalFile)
	if err != nil || crashed == nil || crashed.PID != child.Process.Pid || crashed.Phase != PFActive {
		t.Fatal("packet dead owner intent missing")
	}
	if recovery.recoverPFLifecycle(ctx) != nil || recovery.pfResidue() || len(fixturePFReferences(t, ctx)) != 0 {
		t.Fatal("packet dead owner explicit recovery failed")
	}
	for _, family := range []int{4, 6} {
		for _, protocol := range []int{6, 17} {
			for _, port := range []int{45121, 53} {
				probe(family, protocol, port, true)
			}
		}
	}
	after, err = readDisabledPF(ctx, crashed.Anchor)
	if err != nil || !after.matches(*crashed) || after.rules != pfDigest("") {
		t.Fatal("packet crash recovery final baseline differs")
	}
}

func fmtPort(port int) string { return fmt.Sprintf("%d", port) }
