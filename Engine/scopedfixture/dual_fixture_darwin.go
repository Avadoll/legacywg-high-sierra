// Developer-only one-client/two-peer native routing fixture.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var dualLocal = [2]netip.Addr{netip.MustParseAddr("198.18.80.1"), netip.MustParseAddr("2001:db8:80::1")}
var dualRemote = [2]netip.Addr{netip.MustParseAddr("198.18.80.2"), netip.MustParseAddr("2001:db8:80::2")}
var dualRoamed = [2]netip.Addr{netip.MustParseAddr("198.18.80.3"), netip.MustParseAddr("2001:db8:80::3")}
var dualPorts = [2]uint16{54324, 54326}
var dualRoamedPorts = [2]uint16{54328, 54329}
var dualDecoyIP = [2]netip.Addr{netip.MustParseAddr("198.18.80.9"), netip.MustParseAddr("2001:db8:80::9")}
var dualPrefix = [2]string{"198.18.80.0/24", "2001:db8:80::/64"}
var dualFamily = [2]string{"-inet", "-inet6"}

func assignDualAddress(name string, address netip.Addr) error {
	var err error
	if address.Is4() {
		_, err = command("/sbin/ifconfig", name, "inet", address.String(), address.String(), "netmask", "255.255.255.255", "alias")
	} else {
		_, err = command("/sbin/ifconfig", name, "inet6", address.String(), "prefixlen", "128", "alias")
	}
	return err
}

type dualOuter struct {
	outer           tun.Device
	inner           tun.Device
	stack           *netstack.Net
	iface           *net.Interface
	paths           [2]kernelPath
	inDone, outDone chan struct{}
	once            sync.Once
	clean           bool
	captureEnabled  atomic.Bool
	captured        [2]chan []byte
}

func (link *dualOuter) close() bool {
	link.once.Do(func() {
		link.clean = link.outer.Close() == nil
		if link.inDone != nil {
			select {
			case <-link.inDone:
			case <-time.After(time.Second):
				link.clean = false
			}
		}
		if link.inner != nil {
			if link.inner.Close() != nil {
				link.clean = false
			}
		}
		if link.outDone != nil {
			select {
			case <-link.outDone:
			case <-time.After(time.Second):
				link.clean = false
			}
		}
		for _, packets := range link.captured {
			for {
				select {
				case packet := <-packets:
					clear(packet)
				default:
					goto drained
				}
			}
		drained:
		}
	})
	return link.clean
}

func createDualOuter() (*dualOuter, error) {
	failure := errors.New("dual outer setup failed")
	outer, err := tun.CreateTUN("utun", 1420)
	if err != nil {
		return nil, failure
	}
	link := &dualOuter{outer: outer, captured: [2]chan []byte{make(chan []byte, 1), make(chan []byte, 1)}}
	fail := func() (*dualOuter, error) { link.close(); return nil, failure }
	name, err := outer.Name()
	if err != nil {
		return fail()
	}
	link.iface, err = net.InterfaceByName(name)
	if err != nil {
		return fail()
	}
	for i := range dualLocal {
		if assignDualAddress(name, dualLocal[i]) != nil {
			return fail()
		}
		if _, err = command("/sbin/route", "-n", "add", dualFamily[i], "-net", dualPrefix[i], "-interface", name); err != nil {
			return fail()
		}
		if _, err = command("/sbin/route", "-n", "add", dualFamily[i], "-net", dualPrefix[i], "-interface", name, "-ifscope", name); err != nil {
			return fail()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		link.paths[i], err = queryKernelPath(ctx, dualRemote[i], link.iface.Index)
		cancel()
		if err != nil || !link.paths[i].scoped || !link.paths[i].direct || link.paths[i].name != name {
			return fail()
		}
	}
	addresses := []netip.Addr{dualRemote[0], dualRemote[1], dualRoamed[0], dualRoamed[1]}
	link.inner, link.stack, err = netstack.CreateNetTUN(addresses, nil, 1420)
	if err != nil {
		return fail()
	}
	link.inDone = make(chan struct{})
	link.outDone = make(chan struct{})
	go func() {
		defer close(link.inDone)
		buffers := [][]byte{make([]byte, 65539)}
		sizes := make([]int, 1)
		for {
			count, err := link.outer.Read(buffers, sizes, 4)
			if err != nil {
				return
			}
			if count == 1 {
				if _, err = link.inner.Write([][]byte{buffers[0][:4+sizes[0]]}, 4); err != nil {
					return
				}
			}
		}
	}()
	go func() {
		defer close(link.outDone)
		buffers := [][]byte{make([]byte, 65539)}
		sizes := make([]int, 1)
		for {
			count, err := link.inner.Read(buffers, sizes, 4)
			if err != nil {
				return
			}
			if count == 1 {
				if link.captureEnabled.Load() {
					link.captureTransport(buffers[0][4 : 4+sizes[0]])
				}
				if _, err = link.outer.Write([][]byte{buffers[0][:4+sizes[0]]}, 4); err != nil {
					return
				}
			}
		}
	}()
	return link, nil
}

type dualDecoy struct {
	outer   tun.Device
	iface   *net.Interface
	packets [2]atomic.Int64
	done    chan struct{}
	once    sync.Once
	clean   bool
}

func (link *dualDecoy) close() bool {
	link.once.Do(func() {
		link.clean = link.outer.Close() == nil
		if link.done != nil {
			select {
			case <-link.done:
			case <-time.After(time.Second):
				link.clean = false
			}
		}
	})
	return link.clean
}
func createDualDecoy() (*dualDecoy, error) {
	failure := errors.New("dual decoy setup failed")
	outer, err := tun.CreateTUN("utun", 1420)
	if err != nil {
		return nil, failure
	}
	link := &dualDecoy{outer: outer}
	fail := func() (*dualDecoy, error) { link.close(); return nil, failure }
	name, err := outer.Name()
	if err != nil {
		return fail()
	}
	for _, address := range dualDecoyIP {
		if assignDualAddress(name, address) != nil {
			return fail()
		}
	}
	link.iface, err = net.InterfaceByName(name)
	if err != nil || link.iface.Flags&net.FlagUp == 0 {
		return fail()
	}
	link.done = make(chan struct{})
	go func() {
		defer close(link.done)
		buffers := [][]byte{make([]byte, 65539)}
		sizes := make([]int, 1)
		for {
			count, err := outer.Read(buffers, sizes, 4)
			if err != nil {
				return
			}
			if count != 1 {
				continue
			}
			packet := buffers[0][4 : 4+sizes[0]]
			if len(packet) >= 20 && packet[0]>>4 == 4 && (bytes.Equal(packet[16:20], dualRemote[0].AsSlice()) || bytes.Equal(packet[16:20], dualRoamed[0].AsSlice())) {
				link.packets[0].Add(1)
			}
			if len(packet) >= 40 && packet[0]>>4 == 6 && (bytes.Equal(packet[24:40], dualRemote[1].AsSlice()) || bytes.Equal(packet[24:40], dualRoamed[1].AsSlice())) {
				link.packets[1].Add(1)
			}
		}
	}()
	for i, remote := range dualRemote {
		host := netip.PrefixFrom(remote, remote.BitLen()).String()
		if _, err = command("/sbin/route", "-n", "add", dualFamily[i], "-net", host, "-interface", name); err != nil {
			return fail()
		}
		host = netip.PrefixFrom(dualRoamed[i], dualRoamed[i].BitLen()).String()
		if _, err = command("/sbin/route", "-n", "add", dualFamily[i], "-net", host, "-interface", name); err != nil {
			return fail()
		}
	}
	return link, nil
}

type simultaneousFixture struct {
	client          *device.Device
	servers         [2]*device.Device
	transport       *dualPacketBind
	observers       [2]*scopedObserver
	sockets         [2]net.Conn
	echoes          [2]net.PacketConn
	clientPublicHex string
	serverPublicHex [2]string
}

func (fixture *simultaneousFixture) close() bool {
	clean := true
	for _, observer := range fixture.observers {
		if observer != nil && !observer.stop() {
			clean = false
		}
	}
	for _, socket := range fixture.sockets {
		if socket != nil {
			socket.Close()
		}
	}
	if fixture.client != nil {
		fixture.client.Close()
	}
	for _, server := range fixture.servers {
		if server != nil {
			server.Close()
		}
	}
	for _, echo := range fixture.echoes {
		if echo != nil {
			echo.Close()
		}
	}
	return clean
}

func startSimultaneous(link *dualOuter) (*simultaneousFixture, error) {
	factories := [2]func(uint16) (net.PacketConn, error){admittedFactory(dualLocal[0], dualRemote[0], link.paths[0]), admittedFactory(dualLocal[1], dualRemote[1], link.paths[1])}
	fixture := &simultaneousFixture{transport: &dualPacketBind{bindings: [2]*packetBind{{factory: factories[0]}, {factory: factories[1]}}}}
	fail := func() (*simultaneousFixture, error) {
		fixture.close()
		return nil, errors.New("simultaneous encrypted setup failed")
	}
	clientIP := [2]netip.Addr{netip.MustParseAddr("198.18.89.1"), netip.MustParseAddr("2001:db8:89::1")}
	serverIP := [2]netip.Addr{netip.MustParseAddr("198.18.89.2"), netip.MustParseAddr("2001:db8:89::2")}
	clientTun, clientStack, err := netstack.CreateNetTUN(clientIP[:], nil, 1420)
	if err != nil {
		return fail()
	}
	fixture.client = device.NewDevice(clientTun, fixture.transport, device.NewLogger(device.LogLevelSilent, ""))
	private, public, err := ephemeralKeys()
	if err != nil {
		return fail()
	}
	fixture.clientPublicHex, err = ephemeralPublicHex(public)
	if err != nil {
		return fail()
	}
	clientProfile := fmt.Sprintf("[Interface]\nPrivateKey=%s\nAddress=%s/32,%s/128\n", private, clientIP[0], clientIP[1])
	ports := dualPorts
	endpoints := make([]netip.AddrPort, 2)
	for i := range serverIP {
		serverTun, serverStack, err := netstack.CreateNetTUN([]netip.Addr{serverIP[i]}, nil, 1420)
		if err != nil {
			return fail()
		}
		index := i
		serverBind := &packetBind{factory: func(port uint16) (net.PacketConn, error) {
			if port != ports[index] && port != dualRoamedPorts[index] {
				return nil, errors.New("dual server port refused")
			}
			address := dualRemote[index]
			if port == dualRoamedPorts[index] {
				address = dualRoamed[index]
			}
			return link.stack.ListenUDPAddrPort(netip.AddrPortFrom(address, port))
		}}
		fixture.servers[i] = device.NewDevice(serverTun, serverBind, device.NewLogger(device.LogLevelSilent, ""))
		serverPrivate, serverPublic, err := ephemeralKeys()
		if err != nil {
			return fail()
		}
		fixture.serverPublicHex[i], err = ephemeralPublicHex(serverPublic)
		if err != nil {
			return fail()
		}
		bits := serverIP[i].BitLen()
		profile := fmt.Sprintf("[Interface]\nPrivateKey=%s\nAddress=%s/%d\nListenPort=%d\n[Peer]\nPublicKey=%s\nAllowedIPs=%s/%d\n", serverPrivate, serverIP[i], bits, ports[i], public, clientIP[i], bits)
		if configure(fixture.servers[i], profile, []netip.AddrPort{{}}) != nil || fixture.servers[i].Up() != nil {
			return fail()
		}
		endpoints[i] = netip.AddrPortFrom(dualRemote[i], ports[i])
		clientProfile += fmt.Sprintf("[Peer]\nPublicKey=%s\nEndpoint=%s\nAllowedIPs=%s/%d\n", serverPublic, endpoints[i], serverIP[i], bits)
		echo, err := serverStack.ListenUDPAddrPort(netip.AddrPortFrom(serverIP[i], 54325))
		if err != nil {
			return fail()
		}
		fixture.echoes[i] = echo
		go func() {
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
		fixture.sockets[i], err = clientStack.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(serverIP[i], 54325))
		if err != nil {
			return fail()
		}
	}
	if configure(fixture.client, clientProfile, endpoints) != nil || fixture.client.Up() != nil {
		return fail()
	}
	for i := range fixture.observers {
		fixture.observers[i] = observeScopedPath(dualLocal[i], dualRemote[i], link.paths[i], fixture.transport.bindings[i], fixture.client)
	}
	return fixture, nil
}

func (fixture *simultaneousFixture) probe(serial int) [2]bool {
	type result struct {
		index  int
		echoed bool
	}
	results := make(chan result, 2)
	for i, socket := range fixture.sockets {
		go func(index int, socket net.Conn) {
			payload := []byte(fmt.Sprintf("LegacyWG simultaneous peer %d payload %d", index, serial))
			socket.SetDeadline(time.Now().Add(1500 * time.Millisecond))
			if _, err := socket.Write(payload); err != nil {
				results <- result{index, false}
				return
			}
			buffer := make([]byte, 512)
			size, err := socket.Read(buffer)
			results <- result{index, err == nil && bytes.Equal(buffer[:size], payload)}
		}(i, socket)
	}
	var echoes [2]bool
	for range 2 {
		value := <-results
		echoes[value.index] = value.echoed
	}
	return echoes
}
func (fixture *simultaneousFixture) roundTrip(serial int) bool {
	echoes := fixture.probe(serial)
	return echoes[0] && echoes[1]
}

// Require each record, not aggregate totals that could hide an idle peer.
func individualPeerStats(engine *device.Device, want int) bool {
	text, err := engine.IpcGet()
	if err != nil {
		return false
	}
	count := 0
	values := map[string]uint64{}
	valid := func() bool {
		return values["last_handshake_time_sec"] > 0 && values["rx_bytes"] > 0 && values["tx_bytes"] > 0
	}
	for _, line := range strings.Split(text, "\n") {
		field, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if field == "public_key" {
			if count > 0 && !valid() {
				return false
			}
			count++
			if count > want {
				return false
			}
			values = map[string]uint64{}
			continue
		}
		if count > 0 && (field == "last_handshake_time_sec" || field == "rx_bytes" || field == "tx_bytes") {
			n, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return false
			}
			values[field] = n
		}
	}
	return count == want && valid()
}

func (bind *dualPacketBind) samePort() bool {
	bind.mutex.Lock()
	defer bind.mutex.Unlock()
	if !bind.opened {
		return false
	}
	port := 0
	for _, family := range bind.bindings {
		family.mutex.Lock()
		if family.lease == nil {
			family.mutex.Unlock()
			return false
		}
		address, ok := family.lease.socket.LocalAddr().(*net.UDPAddr)
		family.mutex.Unlock()
		if !ok || address.Port == 0 || (port != 0 && address.Port != port) {
			return false
		}
		port = address.Port
	}
	return true
}

func (bind *dualPacketBind) allClosed() bool {
	bind.mutex.Lock()
	defer bind.mutex.Unlock()
	if bind.opened {
		return false
	}
	for _, family := range bind.bindings {
		family.mutex.Lock()
		open := family.lease != nil
		family.mutex.Unlock()
		if open {
			return false
		}
	}
	return true
}

func concurrentPathProof(link *dualOuter, decoy *dualDecoy) (uint64, error) {
	before := fixtureOtherQueryReplies.Load()
	for round := 0; round < 16; round++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		gate := make(chan struct{})
		results := make(chan bool, 4)
		for i := 0; i < 4; i++ {
			go func(i int) {
				<-gate
				family := i % 2
				scope := 0
				if i < 2 {
					scope = link.iface.Index
				}
				path, err := queryKernelPath(ctx, dualRemote[family], scope)
				valid := err == nil && path.index == decoy.iface.Index
				if scope != 0 {
					valid = err == nil && path == link.paths[family]
				}
				results <- valid
			}(i)
		}
		close(gate)
		valid := true
		for range 4 {
			if !<-results {
				valid = false
			}
		}
		cancel()
		if !valid {
			return 0, errors.New("concurrent kernel query correlation failed")
		}
	}
	ignored := fixtureOtherQueryReplies.Load() - before
	if ignored == 0 {
		return 0, errors.New("concurrent queries did not observe broadcast cross-replies")
	}
	return ignored, nil
}

func checkSimultaneous() (map[string]any, error) {
	failure := errors.New("simultaneous scoped experiment failed")
	var baseline [4]string
	allRemotes := [4]netip.Addr{dualRemote[0], dualRemote[1], dualRoamed[0], dualRoamed[1]}
	for i, remote := range allRemotes {
		var err error
		baseline[i], err = path(remote)
		if err != nil {
			return nil, err
		}
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, failure
	}
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			return nil, failure
		}
		for _, address := range addresses {
			assigned, err := netip.ParsePrefix(address.String())
			if err != nil {
				continue
			}
			for _, text := range dualPrefix {
				probe := netip.MustParsePrefix(text)
				if assigned.Overlaps(probe) {
					return nil, errors.New("dual benchmark prefix already assigned")
				}
			}
		}
	}
	link, err := createDualOuter()
	if err != nil {
		return nil, err
	}
	defer link.close()
	factories := [2]func(uint16) (net.PacketConn, error){admittedFactory(dualLocal[0], dualRemote[0], link.paths[0]), admittedFactory(dualLocal[1], dualRemote[1], link.paths[1])}
	if dualLeaseProof(factories) != nil {
		return nil, errors.New("dual callback or partial-open rollback proof failed")
	}
	fixture, err := startSimultaneous(link)
	if err != nil {
		return nil, err
	}
	defer fixture.close()
	stats := func() bool {
		return individualPeerStats(fixture.client, 2) && individualPeerStats(fixture.servers[0], 1) && individualPeerStats(fixture.servers[1], 1)
	}
	if !fixture.transport.samePort() || !fixture.roundTrip(1) || !stats() {
		return nil, errors.New("simultaneous baseline or individual stats failed")
	}
	decoy, err := createDualDecoy()
	if err != nil {
		return nil, err
	}
	defer decoy.close()
	for i, remote := range dualRemote {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		unscoped, err := queryKernelPath(ctx, remote, 0)
		admissionErr := admitPath(ctx, remote, dualLocal[i], link.paths[i])
		cancel()
		if err != nil || unscoped.index != decoy.iface.Index || admissionErr != nil {
			return nil, errors.New("dual conflict kernel path distinction failed")
		}
		negative, err := socket(dualLocal[i], 0)
		if err != nil {
			return nil, err
		}
		// The peer endpoint has no plaintext echo server: fresh ordinary UDP
		// must reach the decoy, demonstrating both active competing routes.
		count := decoy.packets[i].Load()
		negative.SetWriteDeadline(time.Now().Add(time.Second))
		_, err = negative.WriteToUDPAddrPort([]byte("LegacyWG dual ordinary negative control"), netip.AddrPortFrom(remote, 54323))
		negative.Close()
		if err != nil {
			return nil, failure
		}
		deadline := time.Now().Add(time.Second)
		for decoy.packets[i].Load() == count && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if decoy.packets[i].Load() == count {
			return nil, errors.New("dual ordinary negative control missed decoy")
		}
	}
	before := [2]int64{decoy.packets[0].Load(), decoy.packets[1].Load()}
	ignoredReplies, err := concurrentPathProof(link, decoy)
	if err != nil {
		return nil, err
	}
	for round := 2; round <= 5; round++ {
		if !fixture.roundTrip(round) {
			return nil, errors.New("simultaneous encrypted conflicting route echo failed")
		}
	}
	if fixture.client.Down() != nil || fixture.client.Up() != nil || fixture.transport.opens.Load() < 2 || !fixture.transport.samePort() || !fixture.roundTrip(6) || !stats() {
		return nil, errors.New("simultaneous actual reopen failed")
	}
	time.Sleep(100 * time.Millisecond)
	if decoy.packets[0].Load() != before[0] || decoy.packets[1].Load() != before[1] {
		return nil, errors.New("simultaneous transport reached decoy")
	}
	if err := proveAuthenticatedRoaming(fixture, link, decoy); err != nil {
		return nil, err
	}
	if decoy.packets[0].Load() != before[0] || decoy.packets[1].Load() != before[1] {
		return nil, errors.New("roamed transport reached decoy")
	}
	if _, err = command("/sbin/route", "-n", "delete", dualFamily[0], "-net", dualPrefix[0], "-interface", link.iface.Name, "-ifscope", link.iface.Name); err != nil {
		return nil, err
	}
	select {
	case <-fixture.observers[0].lost:
	case <-time.After(4 * time.Second):
		return nil, errors.New("dual one-family path loss not observed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	healthy := admitPath(ctx, dualRemote[1], dualLocal[1], link.paths[1])
	cancel()
	lossEchoes := fixture.probe(7)
	if healthy != nil || fixture.observers[0].downFailed.Load() || !fixture.transport.refused() || !fixture.transport.allClosed() || lossEchoes[0] || lossEchoes[1] {
		return nil, errors.New("one-family loss did not close whole client")
	}
	opens := fixture.transport.opens.Load()
	if fixture.client.Up() == nil || fixture.transport.opens.Load() != opens {
		return nil, errors.New("dual lost context reopened")
	}
	if _, err = command("/sbin/route", "-n", "add", dualFamily[0], "-net", dualPrefix[0], "-interface", link.iface.Name, "-ifscope", link.iface.Name); err != nil {
		return nil, err
	}
	if fixture.client.Up() == nil || fixture.transport.opens.Load() != opens {
		return nil, errors.New("dual restored old context revived")
	}
	if !fixture.close() {
		return nil, errors.New("dual observer shutdown failed")
	}
	fixture, err = startSimultaneous(link)
	if err != nil {
		return nil, err
	}
	defer fixture.close()
	if !fixture.transport.samePort() || !fixture.roundTrip(8) || !stats() {
		return nil, errors.New("dual fresh context encrypted recovery failed")
	}
	if decoy.packets[0].Load() != before[0] || decoy.packets[1].Load() != before[1] {
		return nil, errors.New("dual loss or recovery reached decoy")
	}
	if !fixture.close() || !link.close() || !decoy.close() {
		return nil, errors.New("dual topology cleanup failed")
	}
	for i, remote := range allRemotes {
		restored, err := path(remote)
		if err != nil || restored != baseline[i] {
			return nil, errors.New("dual destination baseline not restored")
		}
	}
	return map[string]any{"status": "PASS", "one_client_two_independent_peers": "PASS", "simultaneous_ipv4_ipv6_echo": "PASS", "successful_echoes_per_peer": 9,
		"individual_handshake_rx_tx": "PASS", "shared_native_port": "PASS", "both_unbound_negative_controls": "PASS", "both_conflicting_scoped_paths": "PASS",
		"actual_device_down_up_reopens_both": "PASS", "old_callbacks_closed_after_reopen": "PASS", "second_family_open_failure_closes_first": "PASS",
		"one_family_route_loss_stops_entire_client": "PASS", "other_family_path_still_admissible": "PASS", "old_context_refused_after_restore": "PASS",
		"both_native_sockets_closed_after_loss": "PASS", "both_peers_no_echo_after_loss": "PASS",
		"concurrent_kernel_query_correlation": "PASS", "concurrent_query_count": 64, "other_query_replies_ignored": ignoredReplies,
		"tampered_transport_new_ip_port_does_not_roam": "PASS", "tampered_packets_received_per_family": 3,
		"authenticated_new_ip_port_roaming_both_peers": "PASS", "roamed_endpoints_have_scoped_paths": "PASS",
		"encrypted_echo_after_roaming": "PASS", "client_port_unchanged_during_roaming": "PASS",
		"fresh_context_two_peer_encrypted_recovery": "PASS", "encrypted_decoy_packets_ipv4": 0, "encrypted_decoy_packets_ipv6": 0,
		"observer_shutdown": "PASS", "baseline_destination_routes_restored": "PASS", "physical_nic": "NOT_RUN", "high_sierra": "NOT_RUN", "protection_ready": false}, nil
}
