package session

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

func TestRootFullBindScopedSocketLifetime(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("native scoped socket test requires root")
	}
	for _, address := range []string{"127.0.0.1", "::1"} {
		t.Run(address, func(t *testing.T) {
			remote, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(address), 0)))
			if err != nil {
				t.Fatal(err)
			}
			defer remote.Close()
			endpoint := remote.LocalAddr().(*net.UDPAddr).AddrPort()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			bind, err := prepareFullBind(ctx, []netip.AddrPort{endpoint})
			if err != nil {
				t.Fatal(err)
			}
			defer bind.stop()
			receivers, _, err := bind.Open(0)
			if err != nil {
				t.Fatal(err)
			}
			ep, err := bind.ParseEndpoint(endpoint.String())
			if err != nil {
				t.Fatal(err)
			}
			payload := []byte("scoped full transport lifecycle")
			if bind.Send([][]byte{payload}, ep) != nil {
				t.Fatal("scoped send refused")
			}
			remote.SetDeadline(time.Now().Add(time.Second))
			buffer := make([]byte, 256)
			n, source, err := remote.ReadFromUDPAddrPort(buffer)
			if err != nil || !bytes.Equal(buffer[:n], payload) {
				t.Fatal("scoped payload unavailable", err)
			}
			if _, err = remote.WriteToUDPAddrPort(payload, source); err != nil {
				t.Fatal(err)
			}
			sizes := make([]int, 1)
			endpoints := make([]conn.Endpoint, 1)
			n, err = receivers[0]([][]byte{buffer}, sizes, endpoints)
			if err != nil || n != 1 || sizes[0] != len(payload) || !bytes.Equal(buffer[:sizes[0]], payload) {
				t.Fatal("scoped receive unavailable", err)
			}
			if bind.Close() != nil {
				t.Fatal("close refused")
			}
			if _, _, err = bind.Open(0); err != nil {
				t.Fatal("reopen refused", err)
			}
			if _, err = receivers[0]([][]byte{buffer}, sizes, endpoints); !errors.Is(err, net.ErrClosed) {
				t.Fatal("old callback revived")
			}
			if bind.stop() != nil {
				t.Fatal("permanent close refused")
			}
			if _, _, err = bind.Open(0); err == nil {
				t.Fatal("permanent close reopened")
			}
			if _, err = bind.ParseEndpoint("192.0.2.8:12345"); err == nil {
				t.Fatal("unknown endpoint address accepted")
			}
		})
	}
}
