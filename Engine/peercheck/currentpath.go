// Developer-only actual helper roaming/path-loss fixture, never in the app.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
	configcore "legacywg/ConfigCore"
)

type currentAddresses struct {
	local, old, next, decoy, innerClient, innerServer netip.Addr
	prefix                                            netip.Prefix
	family, udp, mode, label                          string
}

func currentTestAddresses(ipv6 bool) currentAddresses {
	if ipv6 {
		return currentAddresses{netip.MustParseAddr("2001:db8:100::1"), netip.MustParseAddr("2001:db8:100::3"), netip.MustParseAddr("2001:db8:100::4"), netip.MustParseAddr("2001:db8:100::9"), netip.MustParseAddr("2001:db8:81::1"), netip.MustParseAddr("2001:db8:81::2"), netip.MustParsePrefix("2001:db8:100::/64"), "-inet6", "udp6", "--current-path-fixture6", "ipv6"}
	}
	return currentAddresses{netip.MustParseAddr("198.18.100.1"), netip.MustParseAddr("198.18.100.3"), netip.MustParseAddr("198.18.100.4"), netip.MustParseAddr("198.18.100.9"), netip.MustParseAddr("198.18.81.1"), netip.MustParseAddr("198.18.81.2"), netip.MustParsePrefix("198.18.100.0/24"), "-inet", "udp4", "--current-path-fixture", "ipv4"}
}
func currentAssignAddress(name string, address netip.Addr) error {
	if address.Is6() {
		return currentCommand("/sbin/ifconfig", name, "inet6", address.String(), "prefixlen", "128", "alias")
	}
	return currentCommand("/sbin/ifconfig", name, "inet", address.String(), address.String(), "netmask", "255.255.255.255", "alias")
}

type currentLease struct {
	socket net.PacketConn
	closed atomic.Bool
}
type currentServerBind struct {
	addresses currentAddresses
	mutex     sync.Mutex
	lease     *currentLease
	stack     *netstack.Net
}

var _ conn.Bind = (*currentServerBind)(nil)

func (*currentServerBind) BatchSize() int { return 1 }
func (*currentServerBind) SetMark(mark uint32) error {
	if mark != 0 {
		return errors.New("fixture marks refused")
	}
	return nil
}
func (*currentServerBind) ParseEndpoint(text string) (conn.Endpoint, error) {
	address, err := netip.ParseAddrPort(text)
	if err != nil || address.Addr().Zone() != "" || address.Port() == 0 {
		return nil, errors.New("fixture endpoint refused")
	}
	return &conn.StdNetEndpoint{AddrPort: address}, nil
}
func (bind *currentServerBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	bind.mutex.Lock()
	defer bind.mutex.Unlock()
	if bind.lease != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	address := bind.addresses.old
	if port == 54328 {
		address = bind.addresses.next
	} else if port != 54324 {
		return nil, 0, errors.New("fixture listener refused")
	}
	socket, err := bind.stack.ListenUDPAddrPort(netip.AddrPortFrom(address, port))
	if err != nil {
		return nil, 0, errors.New("fixture listener failed")
	}
	lease := &currentLease{socket: socket}
	bind.lease = lease
	receive := func(buffers [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
		if len(buffers) != 1 || len(sizes) < 1 || len(endpoints) < 1 {
			return 0, errors.New("fixture batch refused")
		}
		size, from, err := lease.socket.ReadFrom(buffers[0])
		if lease.closed.Load() {
			return 0, net.ErrClosed
		}
		if err != nil {
			return 0, err
		}
		udp, ok := from.(*net.UDPAddr)
		if !ok || udp.Port < 1 || udp.Port > 65535 {
			return 0, errors.New("fixture UDP metadata failed")
		}
		ip, ok := netip.AddrFromSlice(udp.IP)
		if !ok || udp.Zone != "" {
			return 0, errors.New("fixture UDP address failed")
		}
		sizes[0] = size
		endpoints[0] = &conn.StdNetEndpoint{AddrPort: netip.AddrPortFrom(ip.Unmap(), uint16(udp.Port))}
		return 1, nil
	}
	return []conn.ReceiveFunc{receive}, port, nil
}
func (bind *currentServerBind) Close() error {
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
func (bind *currentServerBind) Send(buffers [][]byte, endpoint conn.Endpoint) error {
	remote, ok := endpoint.(*conn.StdNetEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	if len(buffers) > 1 {
		return errors.New("fixture batch refused")
	}
	bind.mutex.Lock()
	lease := bind.lease
	bind.mutex.Unlock()
	if lease == nil || lease.closed.Load() {
		return net.ErrClosed
	}
	for _, data := range buffers {
		size, err := lease.socket.WriteTo(data, net.UDPAddrFromAddrPort(remote.AddrPort))
		if err != nil {
			return err
		}
		if size != len(data) {
			return errors.New("fixture partial packet")
		}
	}
	return nil
}

func currentCommand(program string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, program, args...)
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}
	if command.Run() != nil {
		return errors.New("controlled current-path operation failed")
	}
	return nil
}

type currentFixture struct {
	addresses                  currentAddresses
	outer, stackTun, decoy     tun.Device
	server                     *device.Device
	echo                       net.PacketConn
	name                       string
	clientHex                  string
	before                     [2]string
	interfaces                 []net.Interface
	inDone, outDone, decoyDone chan struct{}
	roamed                     bool
	closeOnce                  sync.Once
	clean                      bool
}

func (fixture *currentFixture) close() bool {
	fixture.closeOnce.Do(func() { fixture.clean = fixture.closeOwned() })
	return fixture.clean
}

func (fixture *currentFixture) closeOwned() bool {
	clean := true
	if fixture.server != nil {
		fixture.server.Close()
	}
	if fixture.echo != nil {
		fixture.echo.Close()
	}
	if fixture.outer != nil {
		if fixture.outer.Close() != nil {
			clean = false
		}
	}
	if fixture.inDone != nil {
		select {
		case <-fixture.inDone:
		case <-time.After(time.Second):
			clean = false
		}
	}
	if fixture.stackTun != nil {
		fixture.stackTun.Close()
	}
	if fixture.outDone != nil {
		select {
		case <-fixture.outDone:
		case <-time.After(time.Second):
			clean = false
		}
	}
	if fixture.decoy != nil {
		if fixture.decoy.Close() != nil {
			clean = false
		}
	}
	if fixture.decoyDone != nil {
		select {
		case <-fixture.decoyDone:
		case <-time.After(time.Second):
			clean = false
		}
	}
	for i, address := range []netip.Addr{fixture.addresses.old, fixture.addresses.next} {
		after, err := physicalRoute(address)
		if err != nil || after != fixture.before[i] {
			clean = false
		}
	}
	if fixture.interfaces != nil {
		after, err := net.Interfaces()
		if err != nil || len(after) != len(fixture.interfaces) {
			clean = false
		}
		for _, original := range fixture.interfaces {
			found := false
			for _, iface := range after {
				if iface.Index == original.Index && iface.Name == original.Name {
					found = true
				}
			}
			if !found {
				clean = false
			}
		}
	}
	return clean
}
func createCurrentFixture(private, public string, ipv6 bool) (*currentFixture, error) {
	failure := errors.New("current-path fixture setup failed")
	a := currentTestAddresses(ipv6)
	fixture := &currentFixture{addresses: a}
	fail := func() (*currentFixture, error) { fixture.close(); return nil, failure }
	var err error
	for i, address := range []netip.Addr{a.old, a.next} {
		fixture.before[i], err = physicalRoute(address)
		if err != nil {
			return nil, failure
		}
	}
	fixture.interfaces, err = net.Interfaces()
	if err != nil || len(fixture.interfaces) > 1024 {
		return nil, failure
	}
	for _, iface := range fixture.interfaces {
		addresses, err := iface.Addrs()
		if err != nil || len(addresses) > 256 {
			return nil, failure
		}
		for _, value := range addresses {
			prefix, err := netip.ParsePrefix(value.String())
			if err == nil && prefix.Overlaps(a.prefix) {
				return nil, errors.New("current-path benchmark prefix already assigned")
			}
		}
	}
	fixture.outer, err = tun.CreateTUN("utun", 1420)
	if err != nil {
		return fail()
	}
	fixture.name, err = fixture.outer.Name()
	if err != nil {
		return fail()
	}
	if currentAssignAddress(fixture.name, a.local) != nil {
		return fail()
	}
	if currentCommand("/sbin/route", "-n", "add", a.family, "-net", a.prefix.String(), "-interface", fixture.name) != nil {
		return fail()
	}
	var stack *netstack.Net
	fixture.stackTun, stack, err = netstack.CreateNetTUN([]netip.Addr{a.old, a.next}, nil, 1420)
	if err != nil {
		return fail()
	}
	fixture.inDone = make(chan struct{})
	fixture.outDone = make(chan struct{})
	go func() {
		defer close(fixture.inDone)
		buffers := [][]byte{make([]byte, 65539)}
		sizes := make([]int, 1)
		for {
			count, err := fixture.outer.Read(buffers, sizes, 4)
			if err != nil {
				return
			}
			if count == 1 {
				if _, err = fixture.stackTun.Write([][]byte{buffers[0][:4+sizes[0]]}, 4); err != nil {
					return
				}
			}
		}
	}()
	go func() {
		defer close(fixture.outDone)
		buffers := [][]byte{make([]byte, 65539)}
		sizes := make([]int, 1)
		for {
			count, err := fixture.stackTun.Read(buffers, sizes, 4)
			if err != nil {
				return
			}
			if count == 1 {
				if _, err = fixture.outer.Write([][]byte{buffers[0][:4+sizes[0]]}, 4); err != nil {
					return
				}
			}
		}
	}()
	inner, innerStack, err := netstack.CreateNetTUN([]netip.Addr{a.innerServer}, nil, 1420)
	if err != nil {
		return fail()
	}
	fixture.server = device.NewDevice(inner, &currentServerBind{stack: stack, addresses: a}, device.NewLogger(device.LogLevelSilent, ""))
	profile := "[Interface]\nPrivateKey=" + private + "\nAddress=" + a.innerServer.String() + "/" + strconv.Itoa(a.innerServer.BitLen()) + "\nListenPort=54324\n[Peer]\nPublicKey=" + public + "\nAllowedIPs=" + a.innerClient.String() + "/" + strconv.Itoa(a.innerServer.BitLen()) + "\n"
	config, err := configcore.Parse([]byte(profile))
	if err != nil {
		return fail()
	}
	defer config.Destroy()
	var buffer bytes.Buffer
	if config.WriteUAPI(&buffer, []netip.AddrPort{{}}) != nil {
		return fail()
	}
	defer clear(buffer.Bytes())
	for _, line := range strings.Split(buffer.String(), "\n") {
		if value, ok := strings.CutPrefix(line, "public_key="); ok {
			fixture.clientHex = value
		}
	}
	if fixture.server.IpcSet(buffer.String()) != nil || fixture.server.Up() != nil {
		return fail()
	}
	fixture.echo, err = innerStack.ListenUDPAddrPort(netip.AddrPortFrom(a.innerServer, 54321))
	if err != nil {
		return fail()
	}
	echo := fixture.echo
	go func() {
		data := make([]byte, 256)
		for {
			size, from, err := echo.ReadFrom(data)
			if err != nil {
				return
			}
			if _, err = echo.WriteTo(data[:size], from); err != nil {
				return
			}
		}
	}()
	return fixture, nil
}
func (fixture *currentFixture) roam() bool {
	if fixture.roamed {
		return false
	}
	if fixture.server.IpcSet("listen_port=54328\npublic_key="+fixture.clientHex+"\npersistent_keepalive_interval=1\n") != nil {
		return false
	}
	fixture.roamed = true
	return true
}
func (fixture *currentFixture) conflict() bool {
	if !fixture.roamed || fixture.decoy != nil {
		return false
	}
	a := fixture.addresses
	before, err := physicalRoute(a.old)
	if err != nil {
		return false
	}
	fixture.decoy, err = tun.CreateTUN("utun", 1420)
	if err != nil {
		return false
	}
	name, err := fixture.decoy.Name()
	if err != nil {
		return false
	}
	if currentAssignAddress(name, a.decoy) != nil {
		return false
	}
	fixture.decoyDone = make(chan struct{})
	go func() {
		defer close(fixture.decoyDone)
		buffers := [][]byte{make([]byte, 65539)}
		sizes := make([]int, 1)
		for {
			if _, err := fixture.decoy.Read(buffers, sizes, 4); err != nil {
				return
			}
		}
	}()
	if currentCommand("/sbin/route", "-n", "add", a.family, "-net", netip.PrefixFrom(a.next, a.next.BitLen()).String(), "-interface", name) != nil {
		return false
	}
	after, err := physicalRoute(a.old)
	if err != nil || before != after {
		return false
	}
	changed, err := physicalRoute(a.next)
	if err != nil || !strings.Contains(changed, "interface:"+name) {
		return false
	}
	outer, err := net.InterfaceByName(fixture.name)
	return err == nil && outer.Flags&net.FlagUp != 0
}

func runCurrentPathFixture(ipv6 bool) int {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Geteuid() != 0 {
		return 3
	}
	if unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}) != nil {
		return 3
	}
	// A private bounded pipe carries only ephemeral fixture keys, never argv,
	// environment, files or reports. Control operations are fixed literals.
	commands := make(chan string, 4)
	go func() {
		defer close(commands)
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Buffer(make([]byte, 256), 2048)
		for scanner.Scan() {
			commands <- scanner.Text()
		}
	}()
	var init struct {
		Private string `json:"private"`
		Public  string `json:"public"`
	}
	select {
	case line := <-commands:
		if len(line) > 512 || json.Unmarshal([]byte(line), &init) != nil {
			return 3
		}
	case <-time.After(5 * time.Second):
		return 3
	}
	for _, key := range []string{init.Private, init.Public} {
		data, err := base64.StdEncoding.Strict().DecodeString(key)
		if err != nil || len(data) != 32 || base64.StdEncoding.EncodeToString(data) != key {
			clear(data)
			return 3
		}
		clear(data)
	}
	fixture, err := createCurrentFixture(init.Private, init.Public, ipv6)
	if err != nil {
		json.NewEncoder(os.Stdout).Encode(map[string]bool{"ok": false})
		return 1
	}
	defer fixture.close()
	output := json.NewEncoder(os.Stdout)
	output.Encode(map[string]bool{"ok": true})
	lease := time.NewTimer(45 * time.Second)
	defer lease.Stop()
	for {
		select {
		case command, open := <-commands:
			if !open {
				if fixture.close() {
					output.Encode(map[string]bool{"ok": true, "baseline_restored": true})
					return 0
				}
				return 1
			}
			ok := false
			switch command {
			case "roam":
				ok = fixture.roam()
			case "conflict":
				ok = fixture.conflict()
			default:
				output.Encode(map[string]bool{"ok": false})
				return 1
			}
			output.Encode(map[string]bool{"ok": ok})
			if !ok {
				return 1
			}
		case <-lease.C:
			return 1
		}
	}
}

func checkCurrentEndpointRoaming(client, requirement string, ipv6 bool) (map[string]any, error) {
	failure := errors.New("native current endpoint roaming test failed")
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		return nil, failure
	}
	a := currentTestAddresses(ipv6)
	before, err := physicalRoute(a.innerServer)
	if err != nil {
		return nil, err
	}
	clientPrivate, clientPublic, err := keypair()
	if err != nil {
		return nil, err
	}
	serverPrivate, serverPublic, err := keypair()
	if err != nil {
		return nil, err
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, failure
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/bin/sudo", "-n", "/usr/bin/env", "GITHUB_ACTIONS=true", executable, a.mode)
	input, err := command.StdinPipe()
	if err != nil {
		return nil, failure
	}
	output, err := command.StdoutPipe()
	if err != nil {
		input.Close()
		return nil, failure
	}
	if command.Start() != nil {
		input.Close()
		output.Close()
		return nil, failure
	}
	replies := make(chan bool, 4)
	scanDone := make(chan struct{})
	defer func() { input.Close(); <-scanDone; command.Wait() }()
	go func() {
		defer close(scanDone)
		scanner := bufio.NewScanner(output)
		scanner.Buffer(make([]byte, 128), 512)
		for scanner.Scan() {
			var response struct {
				OK bool `json:"ok"`
			}
			replies <- json.Unmarshal(scanner.Bytes(), &response) == nil && response.OK
		}
		close(replies)
	}()
	ready := func() bool {
		select {
		case ok, open := <-replies:
			return open && ok
		case <-time.After(5 * time.Second):
			return false
		}
	}
	init, _ := json.Marshal(map[string]string{"private": serverPrivate, "public": clientPublic})
	if _, err = input.Write(append(init, '\n')); err != nil || !ready() {
		clear(init)
		return nil, failure
	}
	clear(init)
	profile := "[Interface]\nPrivateKey=" + clientPrivate + "\nAddress=" + a.innerClient.String() + "/" + strconv.Itoa(a.innerClient.BitLen()) + "\n[Peer]\nPublicKey=" + serverPublic + "\nEndpoint=" + netip.AddrPortFrom(a.old, 54324).String() + "\nAllowedIPs=" + a.innerServer.String() + "/" + strconv.Itoa(a.innerClient.BitLen()) + "\nPersistentKeepalive=1\n"
	if _, err = call(client, requirement, "start", profile); err != nil {
		return nil, err
	}
	defer call(client, requirement, "stop", "")
	socket, err := net.DialUDP(a.udp, nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(a.innerServer, 54321)))
	if err != nil {
		return nil, failure
	}
	defer socket.Close()
	echo := func(serial int) bool {
		payload := []byte("LegacyWG native current endpoint challenge " + strconv.Itoa(serial))
		socket.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := socket.Write(payload); err != nil {
			return false
		}
		buffer := make([]byte, 256)
		size, err := socket.Read(buffer)
		return err == nil && bytes.Equal(payload, buffer[:size])
	}
	if !echo(1) {
		return nil, errors.New("native pre-roaming echo failed")
	}
	reply, err := call(client, requirement, "status", "")
	if err != nil {
		return nil, err
	}
	status, ok := reply["status"].(map[string]any)
	if !ok || status["state"] != "Connected" {
		return nil, failure
	}
	iface, _ := status["interface"].(string)
	if _, err = io.WriteString(input, "roam\n"); err != nil || !ready() {
		return nil, errors.New("controlled peer roaming failed")
	}
	// The old server IP/port listener is closed by the actual official rebind.
	// Keepalive authentication must teach the worker the new address. Continue
	// past two monitor ticks: an immediate echo alone could precede sampling.
	for serial := 2; serial <= 4; serial++ {
		time.Sleep(2 * time.Second)
		if !echo(serial) {
			return nil, errors.New("native echo after authenticated roaming failed")
		}
		reply, err = call(client, requirement, "status", "")
		if err != nil {
			return nil, err
		}
		status, ok = reply["status"].(map[string]any)
		if !ok || status["state"] != "Connected" || status["rx_bytes"].(float64) <= 0 || status["tx_bytes"].(float64) <= 0 {
			return nil, failure
		}
	}
	changedAt := time.Now()
	if _, err = io.WriteString(input, "conflict\n"); err != nil || !ready() {
		return nil, errors.New("new-only route conflict not confirmed")
	}
	closed := false
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		reply, err = call(client, requirement, "status", "")
		if err != nil {
			return nil, err
		}
		status, ok = reply["status"].(map[string]any)
		if ok && status["state"] == "Error" && status["tunnel_started"] == false && status["reason"] == "endpoint route changed or became unavailable; tunnel closed" {
			closed = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	detectionMillis := time.Since(changedAt).Milliseconds()
	if !closed {
		return nil, errors.New("new destination route loss was not detected by worker")
	}
	if _, err = net.InterfaceByName(iface); err == nil {
		return nil, errors.New("worker tunnel remains after new-address route loss")
	}
	after, err := physicalRoute(a.innerServer)
	if err != nil || after != before {
		return nil, errors.New("inner destination baseline not restored before Stop")
	}
	if _, err = call(client, requirement, "stop", ""); err != nil {
		return nil, err
	}
	input.Close()
	if !ready() {
		return nil, errors.New("current-path fixture baseline not restored")
	}
	return map[string]any{"status": "PASS", "actual_authenticated_helper": "PASS", "family": a.label, "numeric_address_and_port_roaming": "PASS", "encrypted_echoes": 4,
		"connected_past_two_monitor_ticks": "PASS", "old_destination_route_unchanged": "PASS", "outer_interface_stays_up": "PASS",
		"only_new_destination_redirected": "PASS", "worker_closes_before_coordinator_stop": "PASS", "new_route_loss_detection_ms": detectionMillis,
		"inner_routes_restored_before_stop": "PASS", "outer_routes_and_interface_set_restored": "PASS", "physical_nic": "NOT_RUN", "high_sierra": "NOT_RUN", "protection_ready": false}, nil
}
