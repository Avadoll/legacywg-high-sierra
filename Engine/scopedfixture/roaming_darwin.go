// Developer-only authenticated roaming proof using unmodified official crypto.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

func ephemeralPublicHex(public string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(public)
	if err != nil || len(data) != 32 {
		return "", errors.New("ephemeral metadata unavailable")
	}
	defer clear(data)
	return hex.EncodeToString(data), nil
}

// Captures at most one bounded encrypted transport datagram per family, only
// while the explicit proof is enabled. No plaintext/key/packet is exported.
func (link *dualOuter) captureTransport(packet []byte) {
	index, header, total := -1, 0, 0
	if len(packet) >= 28 && packet[0]>>4 == 4 && packet[9] == 17 && bytes.Equal(packet[12:16], dualRemote[0].AsSlice()) && bytes.Equal(packet[16:20], dualLocal[0].AsSlice()) {
		index = 0
		header = int(packet[0]&15) * 4
		total = int(binary.BigEndian.Uint16(packet[2:4]))
		if header < 20 || binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
			return
		}
	} else if len(packet) >= 48 && packet[0]>>4 == 6 && packet[6] == 17 && bytes.Equal(packet[8:24], dualRemote[1].AsSlice()) && bytes.Equal(packet[24:40], dualLocal[1].AsSlice()) {
		index = 1
		header = 40
		total = 40 + int(binary.BigEndian.Uint16(packet[4:6]))
	}
	if index < 0 || total > len(packet) || total < header+8 {
		return
	}
	udpLength := int(binary.BigEndian.Uint16(packet[header+4 : header+6]))
	if udpLength < 8 || header+udpLength > total {
		return
	}
	data := packet[header+8 : header+udpLength]
	if len(data) <= device.MinMessageSize || len(data) > 1420 || binary.LittleEndian.Uint32(data[:4]) != device.MessageTransportType {
		return
	}
	copy := append([]byte(nil), data...)
	select {
	case link.captured[index] <- copy:
	default:
		clear(copy)
	}
}

type privatePeerState struct {
	endpoint netip.AddrPort
	rx       uint64
}

func (fixture *simultaneousFixture) privatePeerStates() ([2]privatePeerState, error) {
	failure := errors.New("private ephemeral peer state unavailable")
	var states [2]privatePeerState
	text, err := fixture.client.IpcGet()
	if err != nil || len(text) > 8192 {
		return states, failure
	}
	index := -1
	seen := [2]bool{}
	for _, line := range strings.Split(text, "\n") {
		field, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if field == "public_key" {
			index = -1
			for i, key := range fixture.serverPublicHex {
				if value == key {
					if seen[i] {
						return states, failure
					}
					index = i
					seen[i] = true
					break
				}
			}
			if index < 0 {
				return states, failure
			}
			continue
		}
		if index < 0 {
			continue
		}
		switch field {
		case "endpoint":
			states[index].endpoint, err = netip.ParseAddrPort(value)
		case "rx_bytes":
			states[index].rx, err = strconv.ParseUint(value, 10, 64)
		}
		if err != nil {
			return states, failure
		}
	}
	for i, found := range seen {
		if !found || !states[i].endpoint.IsValid() || states[i].rx == 0 {
			return states, failure
		}
	}
	return states, nil
}

func (bind *dualPacketBind) nativePort() (uint16, bool) {
	bind.mutex.Lock()
	defer bind.mutex.Unlock()
	if !bind.opened {
		return 0, false
	}
	port := 0
	for _, family := range bind.bindings {
		family.mutex.Lock()
		if family.lease == nil {
			family.mutex.Unlock()
			return 0, false
		}
		address, ok := family.lease.socket.LocalAddr().(*net.UDPAddr)
		family.mutex.Unlock()
		if !ok || address.Port < 1 || address.Port > 65535 || (port != 0 && address.Port != port) {
			return 0, false
		}
		port = address.Port
	}
	return uint16(port), true
}

func proveAuthenticatedRoaming(fixture *simultaneousFixture, link *dualOuter, decoy *dualDecoy) error {
	failure := errors.New("authenticated new-address roaming proof failed")
	port, ok := fixture.transport.nativePort()
	if !ok {
		return failure
	}
	opens := fixture.transport.opens.Load()
	for i, remote := range dualRoamed {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		unscoped, err := queryKernelPath(ctx, remote, 0)
		scopedErr := admitPath(ctx, remote, dualLocal[i], link.paths[i])
		cancel()
		if err != nil || unscoped.index != decoy.iface.Index || scopedErr != nil {
			return errors.New("roamed address scoped path not verified")
		}
	}
	link.captureEnabled.Store(true)
	defer link.captureEnabled.Store(false)
	if !fixture.roundTrip(9) {
		return errors.New("fresh ciphertext capture echo failed")
	}
	before, err := fixture.privatePeerStates()
	if err != nil {
		return err
	}
	for i, state := range before {
		if state.endpoint != netip.AddrPortFrom(dualRemote[i], dualPorts[i]) {
			return failure
		}
	}
	for i := range dualRoamed {
		var packet []byte
		select {
		case packet = <-link.captured[i]:
		case <-time.After(time.Second):
			return errors.New("bounded ciphertext capture unavailable")
		}
		// Retain the actual receiver index; change both AEAD nonce/counter and
		// tag. Authentication and replay handling remain the official engine's.
		counter := binary.LittleEndian.Uint64(packet[device.MessageTransportOffsetCounter:device.MessageTransportOffsetContent])
		if counter > 1000 {
			clear(packet)
			return failure
		}
		packet[len(packet)-1] ^= 0x80
		forged, err := link.stack.ListenUDPAddrPort(netip.AddrPortFrom(dualRoamed[i], dualRoamedPorts[i]))
		if err != nil {
			clear(packet)
			return failure
		}
		received := fixture.transport.bindings[i].receives.Load()
		for attempt := 0; attempt < 3; attempt++ {
			binary.LittleEndian.PutUint64(packet[device.MessageTransportOffsetCounter:device.MessageTransportOffsetContent], counter+100+uint64(attempt))
			forged.SetWriteDeadline(time.Now().Add(time.Second))
			count, writeErr := forged.WriteTo(packet, net.UDPAddrFromAddrPort(netip.AddrPortFrom(dualLocal[i], port)))
			if writeErr != nil || count != len(packet) {
				forged.Close()
				clear(packet)
				return failure
			}
		}
		forged.Close()
		clear(packet)
		deadline := time.Now().Add(time.Second)
		for fixture.transport.bindings[i].receives.Load() < received+3 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if fixture.transport.bindings[i].receives.Load() < received+3 {
			return errors.New("tampered packet did not reach native receive callback")
		}
	}
	link.captureEnabled.Store(false)
	time.Sleep(200 * time.Millisecond)
	after, err := fixture.privatePeerStates()
	if err != nil {
		return err
	}
	for i, state := range after {
		if state != before[i] {
			return errors.New("tampered packet altered accepted endpoint or RX counter")
		}
	}
	for i, server := range fixture.servers {
		// Rebind the same official authenticated peer to a new numeric IP/port
		// and send its genuine encrypted keepalive. Only owned fixture peers.
		config := fmt.Sprintf("listen_port=%d\npublic_key=%s\npersistent_keepalive_interval=1\n", dualRoamedPorts[i], fixture.clientPublicHex)
		if server.IpcSet(config) != nil {
			return errors.New("official fixture peer rebinding failed")
		}
	}
	deadline := time.Now().Add(4 * time.Second)
	accepted := false
	for time.Now().Before(deadline) {
		states, err := fixture.privatePeerStates()
		if err == nil && states[0].endpoint == netip.AddrPortFrom(dualRoamed[0], dualRoamedPorts[0]) && states[1].endpoint == netip.AddrPortFrom(dualRoamed[1], dualRoamedPorts[1]) {
			accepted = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !accepted || !fixture.roundTrip(10) || !individualPeerStats(fixture.client, 2) || !individualPeerStats(fixture.servers[0], 1) || !individualPeerStats(fixture.servers[1], 1) {
		return failure
	}
	for i, server := range fixture.servers {
		if server.IpcSet(fmt.Sprintf("public_key=%s\npersistent_keepalive_interval=0\n", fixture.clientPublicHex)) != nil {
			return failure
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		err := admitPath(ctx, dualRoamed[i], dualLocal[i], link.paths[i])
		cancel()
		if err != nil {
			return failure
		}
	}
	afterPort, ok := fixture.transport.nativePort()
	if !ok || afterPort != port || fixture.transport.opens.Load() != opens {
		return errors.New("client sockets changed during peer roaming")
	}
	return nil
}
