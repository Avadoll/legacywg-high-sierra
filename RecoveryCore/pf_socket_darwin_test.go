package recoverycore

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func pfSocketLoopback(t *testing.T) pfInterface {
	t.Helper()
	iface, err := net.InterfaceByName("lo0")
	if err != nil || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback == 0 {
		t.Fatal("socket loopback fixture unavailable")
	}
	return pfInterface{iface.Name, iface.Index}
}

func pfSocketPort(t *testing.T, socket pfDatagram, source netip.Addr) uint16 {
	t.Helper()
	local, ok := socket.LocalAddr().(*net.UDPAddr)
	if !ok || local.AddrPort().Addr().Unmap() != source || local.Port < 1 || local.Port > 65535 {
		t.Fatal("socket exact local identity unavailable")
	}
	return uint16(local.Port)
}

func pfSocketEcho(t *testing.T, socket pfDatagram, source netip.Addr) {
	t.Helper()
	network := "udp4"
	if source.Is6() {
		network = "udp6"
	}
	peer, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(source, 0)))
	if err != nil {
		t.Fatal("socket echo peer unavailable")
	}
	defer peer.Close()
	deadline := time.Now().Add(2 * time.Second)
	if peer.SetDeadline(deadline) != nil || socket.SetDeadline(deadline) != nil {
		t.Fatal("socket echo deadline failed")
	}
	want := []byte("owned-socket-echo")
	destination := peer.LocalAddr().(*net.UDPAddr).AddrPort()
	if n, oob, err := socket.WriteMsgUDPAddrPort(want, nil, destination); err != nil || n != len(want) || oob != 0 {
		t.Fatal("unconnected socket send failed")
	}
	buffer := make([]byte, 64)
	n, remote, err := peer.ReadFromUDPAddrPort(buffer)
	if err != nil || !bytes.Equal(buffer[:n], want) || remote.Addr().Unmap() != source || remote.Port() != pfSocketPort(t, socket, source) {
		t.Fatal("socket echo source or payload changed")
	}
	if n, oob, err := peer.WriteMsgUDPAddrPort(want, nil, remote); err != nil || n != len(want) || oob != 0 {
		t.Fatal("socket echo reply failed")
	}
	n, remote, err = socket.ReadFromUDPAddrPort(buffer)
	if err != nil || !bytes.Equal(buffer[:n], want) || remote != destination {
		t.Fatal("unconnected socket receive failed")
	}
	if socket.SetDeadline(time.Time{}) != nil {
		t.Fatal("socket deadline reset failed")
	}
}

func TestRootPFRuleSocketPortLease(t *testing.T) {
	requirePFRuleCI(t)
	path := pfSocketLoopback(t)
	for _, text := range []string{"127.0.0.1", "::1"} {
		t.Run(text, func(t *testing.T) {
			source := netip.MustParseAddr(text)
			socket, err := openPFDatagram(path, source, 0)
			if err != nil {
				t.Fatal("owned socket open failed")
			}
			t.Cleanup(func() { _ = socket.Close() })
			port := pfSocketPort(t, socket, source)
			pfSocketEcho(t, socket, source)
			if socket.SetWriteDeadline(time.Now().Add(-time.Second)) != nil {
				t.Fatal("socket write deadline failed")
			}
			n, oob, writeErr := socket.WriteMsgUDPAddrPort([]byte{1}, nil, netip.AddrPortFrom(source, port))
			var writeTimeout net.Error
			if n != 0 || oob != 0 || !errors.As(writeErr, &writeTimeout) || !writeTimeout.Timeout() {
				t.Fatal("expired write deadline did not prevent an unconnected send")
			}
			if other, err := openPFDatagram(path, source, port); err == nil {
				_ = other.Close()
				t.Fatal("write timeout surrendered the reserved source port")
			}
			if socket.SetWriteDeadline(time.Time{}) != nil {
				t.Fatal("socket write deadline reset failed")
			}
			pfSocketEcho(t, socket, source)
			started, result := make(chan struct{}), make(chan error, 1)
			go func() {
				close(started)
				_, _, err := socket.ReadFromUDPAddrPort(make([]byte, 64))
				result <- err
			}()
			<-started
			select {
			case <-result:
				t.Fatal("empty socket receive was not pending")
			case <-time.After(50 * time.Millisecond):
			}
			if socket.SetDeadline(time.Now()) != nil {
				t.Fatal("socket I/O quiescence failed")
			}
			select {
			case err := <-result:
				var timeout net.Error
				if !errors.As(err, &timeout) || !timeout.Timeout() {
					t.Fatal("pending socket receive did not time out")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("pending socket receive was not released")
			}
			if other, err := openPFDatagram(path, source, port); err == nil {
				_ = other.Close()
				t.Fatal("quiesced socket surrendered its reserved source port")
			}
			if socket.SetDeadline(time.Time{}) != nil {
				t.Fatal("socket deadline reset failed")
			}
			pfSocketEcho(t, socket, source)
			if socket.Close() != nil {
				t.Fatal("owned socket close failed")
			}
			if _, _, err := socket.WriteMsgUDPAddrPort([]byte{1}, nil, netip.AddrPortFrom(source, port)); !errors.Is(err, net.ErrClosed) {
				t.Fatal("closed socket accepted a send")
			}
			if _, _, err := socket.ReadFromUDPAddrPort(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
				t.Fatal("closed socket accepted a receive")
			}
			reopened, err := openPFDatagram(path, source, port)
			if err != nil {
				t.Fatal("closed socket source port was not released")
			}
			defer reopened.Close()
			if pfSocketPort(t, reopened, source) != port {
				t.Fatal("reopened socket source port changed")
			}
			pfSocketEcho(t, reopened, source)
		})
	}
}

func TestRootPFRuleSocketDualFamilyAndAdmission(t *testing.T) {
	requirePFRuleCI(t)
	path := pfSocketLoopback(t)
	first, second := netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")
	udp4, err := openPFDatagram(path, first, 0)
	if err != nil {
		t.Fatal("IPv4 socket unavailable")
	}
	defer udp4.Close()
	port := pfSocketPort(t, udp4, first)
	udp6, err := openPFDatagram(path, second, port)
	if err != nil {
		t.Fatal("same-port independent IPv6 socket unavailable")
	}
	defer udp6.Close()
	if pfSocketPort(t, udp6, second) != port {
		t.Fatal("dual-family source port mismatch")
	}
	pfSocketEcho(t, udp4, first)
	pfSocketEcho(t, udp6, second)
	for _, invalid := range []struct {
		path   pfInterface
		source netip.Addr
	}{
		{pfInterface{path.name, path.index + 1}, first},
		{pfInterface{path.name, 0}, first},
		{pfInterface{"../lo0", path.index}, first},
		{path, netip.Addr{}},
		{path, netip.MustParseAddr("0.0.0.0")},
		{path, netip.MustParseAddr("::ffff:127.0.0.1")},
		{path, netip.MustParseAddr("::1%lo0")},
		{path, netip.MustParseAddr("224.0.0.1")},
		{path, netip.MustParseAddr("127.0.0.2")},
	} {
		if socket, err := openPFDatagram(invalid.path, invalid.source, 0); err == nil || socket != nil {
			if socket != nil {
				_ = socket.Close()
			}
			t.Fatal("invalid socket path/source admitted")
		}
	}
	// Refused admissions cannot disturb the two already-owned socket leases.
	pfSocketEcho(t, udp4, first)
	pfSocketEcho(t, udp6, second)
}
