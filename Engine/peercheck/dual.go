package main

import (
	"bytes"
	"errors"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"net"
	"net/netip"
	"time"
)

// Prove IPv4 still traverses the same session while IPv6 is active, rather
// than inferring dual-stack support from two separate family-only sessions.
func extraIPv4Echo(stack *netstack.Net) error {
	address := netip.MustParseAddr("198.18.0.2")
	echo, err := stack.ListenUDPAddrPort(netip.AddrPortFrom(address, 54322))
	if err != nil {
		return errors.New("dual-stack IPv4 server setup failed")
	}
	defer echo.Close()
	echo.SetDeadline(time.Now().Add(5 * time.Second))
	result := make(chan error, 1)
	go func() {
		packet := make([]byte, 256)
		size, remote, failure := echo.ReadFrom(packet)
		if failure == nil {
			_, failure = echo.WriteTo(packet[:size], remote)
		}
		result <- failure
	}()
	client, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IP(address.AsSlice()), Port: 54322})
	if err != nil {
		return errors.New("dual-stack IPv4 client setup failed")
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(5 * time.Second))
	packet := []byte("LegacyWG simultaneous IPv4/IPv6 tunnel proof")
	if _, err = client.Write(packet); err != nil {
		return errors.New("dual-stack IPv4 send failed")
	}
	received := make([]byte, 256)
	size, err := client.Read(received)
	if err != nil || !bytes.Equal(received[:size], packet) {
		return errors.New("dual-stack IPv4 round trip failed")
	}
	if <-result != nil {
		return errors.New("dual-stack IPv4 echo failed")
	}
	return nil
}
