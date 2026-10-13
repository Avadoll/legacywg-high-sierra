package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	configcore "legacywg/ConfigCore"
)

func multiplePeers(client, requirement string) error {
	clientIP := netip.MustParseAddr("198.18.0.1")
	servers := []netip.Addr{netip.MustParseAddr("198.18.0.2"), netip.MustParseAddr("198.18.0.3")}
	before := make(map[netip.Addr]string)
	for _, address := range append([]netip.Addr{clientIP}, servers...) {
		original, err := physicalRoute(address)
		if err != nil {
			return err
		}
		before[address] = original
	}
	private, public, err := keypair()
	if err != nil {
		return err
	}
	profile := fmt.Sprintf("[Interface]\nPrivateKey=%s\nAddress=%s/32\n", private, clientIP)
	for _, address := range servers {
		serverPrivate, serverPublic, err := keypair()
		if err != nil {
			return err
		}
		tunnel, stack, err := netstack.CreateNetTUN([]netip.Addr{address}, nil, 1420)
		if err != nil {
			return errors.New("multi-peer test stack failed")
		}
		server := device.NewDevice(tunnel, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
		defer server.Close()
		config, err := configcore.Parse([]byte(fmt.Sprintf("[Interface]\nPrivateKey=%s\nAddress=%s/32\n[Peer]\nPublicKey=%s\nAllowedIPs=%s/32\n", serverPrivate, address, public, clientIP)))
		if err != nil {
			return errors.New("multi-peer test server config failed")
		}
		var buffer bytes.Buffer
		err = config.WriteUAPI(&buffer, []netip.AddrPort{{}})
		config.Destroy()
		if err == nil {
			err = server.IpcSet(buffer.String())
		}
		clear(buffer.Bytes())
		if err != nil || server.Up() != nil {
			return errors.New("multi-peer official server failed")
		}
		raw, err := server.IpcGet()
		if err != nil {
			return errors.New("multi-peer server port failed")
		}
		port := 0
		for _, line := range strings.Split(raw, "\n") {
			if value, found := strings.CutPrefix(line, "listen_port="); found {
				port, _ = strconv.Atoi(value)
			}
		}
		if port < 1 || port > 65535 {
			return errors.New("multi-peer port unavailable")
		}
		profile += fmt.Sprintf("[Peer]\nPublicKey=%s\nEndpoint=127.0.0.1:%d\nAllowedIPs=%s/32\nPersistentKeepalive=1\n", serverPublic, port, address)
		echo, err := stack.ListenUDPAddrPort(netip.AddrPortFrom(address, 54321))
		if err != nil {
			return errors.New("multi-peer echo listener failed")
		}
		defer echo.Close()
		echo.SetDeadline(time.Now().Add(15 * time.Second))
		go func() {
			buffer := make([]byte, 256)
			size, remote, err := echo.ReadFrom(buffer)
			if err == nil {
				echo.WriteTo(buffer[:size], remote)
			}
		}()
	}
	if _, err := call(client, requirement, "start", profile); err != nil {
		return err
	}
	defer call(client, requirement, "stop", "")
	for index, address := range servers {
		socket, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IP(address.AsSlice()), Port: 54321})
		if err != nil {
			return errors.New("multi-peer native socket failed")
		}
		defer socket.Close()
		socket.SetDeadline(time.Now().Add(10 * time.Second))
		payload := []byte(fmt.Sprintf("LegacyWG independently encrypted peer %d", index+1))
		if _, err := socket.Write(payload); err != nil {
			return errors.New("multi-peer send failed")
		}
		response := make([]byte, 256)
		size, err := socket.Read(response)
		if err != nil || !bytes.Equal(response[:size], payload) {
			return errors.New("multi-peer encrypted round trip failed")
		}
	}
	reply, err := call(client, requirement, "status", "")
	if err != nil {
		return err
	}
	status, ok := reply["status"].(map[string]any)
	if !ok || status["peers"] != float64(2) || status["tunnel_started"] != true {
		return errors.New("multi-peer tunnel status missing")
	}
	peers, ok := status["peer_details"].([]any)
	if !ok || len(peers) != 2 {
		return errors.New("multi-peer details missing")
	}
	for index, value := range peers {
		peer, ok := value.(map[string]any)
		if !ok || peer["index"] != float64(index+1) {
			return errors.New("multi-peer identity order failed")
		}
		for _, field := range []string{"rx_bytes", "tx_bytes", "last_handshake_unix"} {
			number, ok := peer[field].(float64)
			if !ok || number <= 0 {
				return errors.New("multi-peer actual handshake/traffic missing")
			}
		}
		if len(peer) != 4 {
			return errors.New("multi-peer status exposes unexpected metadata")
		}
	}
	iface, _ := status["interface"].(string)
	if _, err := call(client, requirement, "stop", ""); err != nil {
		return err
	}
	if _, err := net.InterfaceByName(iface); err == nil {
		return errors.New("multi-peer interface not cleaned up")
	}
	for address, original := range before {
		restored, err := physicalRoute(address)
		if err != nil || restored != original {
			return errors.New("multi-peer routes not restored")
		}
	}
	return nil
}
