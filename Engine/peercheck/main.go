// peercheck is a developer-only end-to-end test; it is never in the app bundle.
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	configcore "legacywg/ConfigCore"
)

func keypair() (string, string, error) {
	var private [32]byte
	if _, err := rand.Read(private[:]); err != nil {
		return "", "", errors.New("ephemeral test key generation failed")
	}
	defer clear(private[:])
	public, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		return "", "", errors.New("official X25519 public key derivation failed")
	}
	return base64.StdEncoding.EncodeToString(private[:]), base64.StdEncoding.EncodeToString(public), nil
}

func call(client, requirement, op, profile string) (map[string]any, error) {
	command := exec.Command(client, requirement, op)
	if profile != "" {
		command.Stdin = strings.NewReader(profile)
	}
	data, err := command.Output()
	if err != nil {
		return nil, errors.New("authenticated helper test request failed")
	}
	var reply map[string]any
	if json.Unmarshal(data, &reply) != nil || reply["ok"] != true {
		return nil, errors.New("helper test operation refused")
	}
	return reply, nil
}

func physicalRoute(address netip.Addr) (string, error) {
	family := "-inet"
	if address.Is6() {
		family = "-inet6"
	}
	data, err := exec.Command("/sbin/route", "-n", "get", family, address.String()).CombinedOutput()
	// Darwin route can print this routing-socket error but return zero. It
	// means an absent baseline route, which must also remain absent on cleanup.
	if address.Is6() && strings.Contains(string(data), "not in table") {
		return "NO_ROUTE", nil
	}
	if err != nil {
		return "", errors.New("cannot capture benchmark route")
	}
	selected := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		field, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok && (field == "interface" || field == "gateway") {
			selected = append(selected, field+":"+strings.TrimSpace(value))
		}
	}
	if len(selected) == 0 {
		return "", fmt.Errorf("benchmark route identity missing: %q", strings.TrimSpace(string(data)))
	}
	return strings.Join(selected, "\n"), nil
}

type checkOptions struct {
	hostname     bool
	routeLoss    bool
	recoveryTest bool
}

func check(client, requirement string, crashParent bool, dnsProbe, dnsMode string, ipv6, outerIPv6 bool, options ...checkOptions) error {
	settings := checkOptions{}
	if len(options) > 0 {
		settings = options[0]
	}
	var closeOuter func() error
	if settings.routeLoss {
		var err error
		closeOuter, err = outerEndpointFixture()
		if err != nil {
			return err
		}
		defer closeOuter()
	}
	var dnsBefore dnsSnapshot
	if dnsMode != "" {
		var err error
		dnsBefore, err = snapshotDNS(dnsProbe)
		if err != nil || dnsBefore.Present {
			return errors.New("DNS baseline is unavailable or already owned")
		}
	}
	serverIP := netip.MustParseAddr("198.18.0.2")
	clientIP := netip.MustParseAddr("198.18.0.1")
	bits := 32
	udpFamily := "udp4"
	endpointHost := "127.0.0.1"
	if settings.routeLoss {
		endpointHost = "198.18.99.3"
	}
	if ipv6 {
		serverIP = netip.MustParseAddr("2001:db8:77::2")
		clientIP = netip.MustParseAddr("2001:db8:77::1")
		bits = 128
		udpFamily = "udp6"
	}
	if outerIPv6 {
		endpointHost = "::1"
	}
	dual := dnsMode == "dual-stack"
	serverAddresses := []netip.Addr{serverIP}
	clientAddresses := fmt.Sprintf("%s/%d", clientIP, bits)
	serverRoutes := fmt.Sprintf("%s/%d", serverIP, bits)
	benchmarkAddresses := []netip.Addr{clientIP, serverIP}
	if dual {
		server4 := netip.MustParseAddr("198.18.0.2")
		client4 := netip.MustParseAddr("198.18.0.1")
		serverAddresses = append(serverAddresses, server4)
		clientAddresses += "," + client4.String() + "/32"
		serverRoutes += "," + server4.String() + "/32"
		benchmarkAddresses = append(benchmarkAddresses, client4, server4)
	}
	routeBefore := map[netip.Addr]string{}
	for _, address := range benchmarkAddresses {
		original, err := physicalRoute(address)
		if err != nil {
			return err
		}
		routeBefore[address] = original
	}
	clientPrivate, clientPublic, err := keypair()
	if err != nil {
		return err
	}
	serverPrivate, serverPublic, err := keypair()
	if err != nil {
		return err
	}
	tunnel, stack, err := netstack.CreateNetTUN(serverAddresses, nil, 1420)
	if err != nil {
		return errors.New("test server network stack creation failed")
	}
	server := device.NewDevice(tunnel, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer server.Close()
	var dnsCount *dnsCounters
	if dnsMode != "" {
		stop, counters, failure := serveDNS(stack, serverIP)
		if failure != nil {
			return failure
		}
		defer stop()
		dnsCount = counters
	}
	profile := fmt.Sprintf("[Interface]\nPrivateKey=%s\nAddress=%s\n[Peer]\nPublicKey=%s\nAllowedIPs=%s\n", serverPrivate, serverRoutes, clientPublic, clientAddresses)
	config, err := configcore.Parse([]byte(profile))
	if err != nil {
		return errors.New("test server profile validation failed")
	}
	defer config.Destroy()
	var buffer bytes.Buffer
	if config.WriteUAPI(&buffer, []netip.AddrPort{{}}) != nil || server.IpcSet(buffer.String()) != nil {
		return errors.New("official test server UAPI setup failed")
	}
	clear(buffer.Bytes())
	if server.Up() != nil {
		return errors.New("test server UDP bind failed")
	}
	uapi, err := server.IpcGet()
	if err != nil {
		return errors.New("test server statistics failed")
	}
	port := 0
	for _, line := range strings.Split(uapi, "\n") {
		if strings.HasPrefix(line, "listen_port=") {
			port, _ = strconv.Atoi(strings.TrimPrefix(line, "listen_port="))
		}
	}
	if port < 1 || port > 65535 {
		return errors.New("test server port missing")
	}
	echo, err := stack.ListenUDPAddrPort(netip.AddrPortFrom(serverIP, 54321))
	if err != nil {
		return errors.New("test echo server failed")
	}
	defer echo.Close()
	echo.SetDeadline(time.Now().Add(12 * time.Second))
	echoResult := make(chan error, 1)
	go func() {
		payload := make([]byte, 256)
		size, remote, err := echo.ReadFrom(payload)
		if err == nil {
			_, err = echo.WriteTo(payload[:size], remote)
		}
		echoResult <- err
	}()
	profile = fmt.Sprintf("[Interface]\nPrivateKey=%s\nAddress=%s\n[Peer]\nPublicKey=%s\nEndpoint=%s\nAllowedIPs=%s\nPersistentKeepalive=1\n", clientPrivate, clientAddresses, serverPublic, net.JoinHostPort(endpointHost, strconv.Itoa(port)), serverRoutes)
	if settings.hostname {
		profile = strings.Replace(profile, net.JoinHostPort(endpointHost, strconv.Itoa(port)), net.JoinHostPort("localhost", strconv.Itoa(port)), 1)
	}
	if dnsMode != "" {
		profile = strings.Replace(profile, "Address=", "DNS="+serverIP.String()+"\nAddress=", 1)
	}
	if _, err = call(client, requirement, "start", profile); err != nil {
		return err
	}
	stopped := false
	defer func() {
		if !stopped {
			call(client, requirement, "stop", "")
		}
	}()
	if settings.recoveryTest {
		data, failure := exec.Command(client, requirement, "recover").Output()
		var refused map[string]any
		if failure == nil || json.Unmarshal(data, &refused) != nil || refused["ok"] != false ||
			refused["error"] != "disconnect required before recovery" {
			return errors.New("recovery did not refuse an active tunnel")
		}
		state, ok := refused["status"].(map[string]any)
		if !ok || state["tunnel_started"] != true || (state["state"] != "Connecting" && state["state"] != "Connected") {
			return errors.New("active tunnel state was lost by recovery refusal")
		}
	}
	socket, err := net.DialUDP(udpFamily, nil, &net.UDPAddr{IP: net.IP(serverIP.AsSlice()), Port: 54321})
	if err != nil {
		return errors.New("native client UDP socket failed")
	}
	defer socket.Close()
	socket.SetDeadline(time.Now().Add(10 * time.Second))
	payload := []byte("LegacyWG encrypted loopback payload")
	if _, err = socket.Write(payload); err != nil {
		return errors.New("native tunnel send failed")
	}
	received := make([]byte, 256)
	size, err := socket.Read(received)
	if err != nil || !bytes.Equal(payload, received[:size]) {
		return errors.New("encrypted tunnel round trip failed")
	}
	if <-echoResult != nil {
		return errors.New("decrypted echo response failed")
	}
	reply, err := call(client, requirement, "status", "")
	if err != nil {
		return err
	}
	status, ok := reply["status"].(map[string]any)
	if !ok || status["state"] != "Connected" || status["rx_bytes"].(float64) <= 0 || status["tx_bytes"].(float64) <= 0 {
		return errors.New("actual handshake and traffic statistics missing")
	}
	iface, _ := status["interface"].(string)
	if dual {
		if err = extraIPv4Echo(stack); err != nil {
			return err
		}
	}
	if dnsMode != "" {
		if status["dns_configured"] != true {
			return errors.New("DNS transaction is not active")
		}
		// configd publishes resolver changes asynchronously after commit.
		time.Sleep(time.Second)
		if err = systemDNS(dnsProbe, dnsCount); err != nil {
			return err
		}
	}
	if settings.routeLoss {
		if err = closeOuter(); err != nil {
			return err
		}
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			if _, err = net.InterfaceByName(iface); err != nil {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
	} else if dnsMode == "agent-crash" {
		// Select the single fixed component installed by this CI test. A
		// truncated process-name match is insufficient on older Darwin.
		pids, failure := exec.Command("/usr/bin/sudo", "-n", "/usr/bin/pgrep", "-f", "^/Library/Application Support/LegacyWG/legacywg-network$").Output()
		fields := strings.Fields(string(pids))
		pid := 0
		if len(fields) == 1 {
			pid, _ = strconv.Atoi(fields[0])
		}
		if failure != nil || pid < 2 || exec.Command("/usr/bin/sudo", "-n", "/bin/kill", "-KILL", strconv.Itoa(pid)).Run() != nil {
			return errors.New("controlled DNS agent crash injection failed")
		}
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			if _, err = net.InterfaceByName(iface); err != nil {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
	} else if crashParent {
		if exec.Command("/usr/bin/sudo", "-n", "/bin/launchctl", "kill", "SIGKILL", "system/org.legacywg.helper").Run() != nil {
			return errors.New("CI helper crash injection failed")
		}
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			if _, err = net.InterfaceByName(iface); err != nil {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
	} else if _, err = call(client, requirement, "stop", ""); err != nil {
		return err
	}
	stopped = true
	reply, err = call(client, requirement, "status", "")
	if err != nil {
		return err
	}
	status, ok = reply["status"].(map[string]any)
	if !ok || (status["state"] != "Disconnected" && !((dnsMode == "agent-crash" || settings.routeLoss) && status["state"] == "Error")) {
		return errors.New("disconnect state failed")
	}
	if settings.routeLoss && (status["state"] != "Error" || status["tunnel_started"] != false || status["reason"] != "endpoint route changed or became unavailable; tunnel closed") {
		return errors.New("endpoint route loss did not produce a closed-tunnel error")
	}
	if _, err = net.InterfaceByName(iface); err == nil {
		return errors.New("native interface still exists after disconnect")
	}
	for address, original := range routeBefore {
		restored, err := physicalRoute(address)
		if err != nil || restored != original {
			return errors.New("benchmark route was not restored after disconnect")
		}
	}
	if dnsMode != "" {
		if err = restoreDNS(dnsProbe, dnsBefore); err != nil {
			return err
		}
		if _, err = call(client, requirement, "stop", ""); err != nil {
			return err
		}
	}
	if settings.routeLoss {
		if _, err = call(client, requirement, "stop", ""); err != nil {
			return err
		}
	}
	return nil
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--outer-fixture" {
		os.Exit(runOuterFixture())
	}
	if len(os.Args) != 4 {
		os.Exit(2)
	}
	started := time.Now()
	for cycle := 0; cycle < 21; cycle++ {
		if err := check(os.Args[1], os.Args[2], cycle == 20, "", "", false, false, checkOptions{recoveryTest: cycle == 0}); err != nil {
			json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "FAIL", "cycle": cycle + 1, "reason": err.Error()})
			os.Exit(1)
		}
	}
	for _, mode := range []string{"disconnect", "helper-crash", "agent-crash"} {
		if err := check(os.Args[1], os.Args[2], mode == "helper-crash", os.Args[3], mode, false, false); err != nil {
			json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "FAIL", "dns_mode": mode, "reason": err.Error()})
			os.Exit(1)
		}
	}
	for _, outer6 := range []bool{false, true} {
		if err := check(os.Args[1], os.Args[2], false, os.Args[3], "disconnect", true, outer6); err != nil {
			json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "FAIL", "ipv6": true, "ipv6_endpoint": outer6, "reason": err.Error()})
			os.Exit(1)
		}
	}
	if err := check(os.Args[1], os.Args[2], false, os.Args[3], "dual-stack", true, true); err != nil {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "FAIL", "dual_stack": true, "reason": err.Error()})
		os.Exit(1)
	}
	if err := check(os.Args[1], os.Args[2], false, os.Args[3], "disconnect", false, false, checkOptions{hostname: true}); err != nil {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "FAIL", "hostname_endpoint": true, "reason": err.Error()})
		os.Exit(1)
	}
	if err := multiplePeers(os.Args[1], os.Args[2]); err != nil {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "FAIL", "multi_peer": true, "reason": err.Error()})
		os.Exit(1)
	}
	if err := check(os.Args[1], os.Args[2], false, "", "", false, false, checkOptions{routeLoss: true}); err != nil {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "FAIL", "endpoint_route_loss": true, "reason": err.Error()})
		os.Exit(1)
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "PASS", "kind": "authenticated-helper-native-utun-encrypted-loopback",
		"connect_disconnect_cycles": 20, "helper_crash_cleanup": "PASS", "route_restoration": "PASS", "elapsed_ms": time.Since(started).Milliseconds(),
		"system_dns_udp_tcp": "PASS", "dns_disconnect_recovery": "PASS", "dns_helper_crash_recovery": "PASS",
		"dns_agent_crash_recovery": "PASS", "foreign_dns_restoration": "PASS",
		"ipv6_encrypted_split": "PASS", "ipv6_endpoint": "PASS", "ipv6_dns_transport_udp_tcp": "PASS",
		"dual_stack_encrypted_split":                  "PASS",
		"localhost_endpoint_encrypted_split":          "PASS",
		"multi_peer_encrypted_routing_and_status":     "PASS",
		"endpoint_route_loss_closes_tunnel":           "PASS",
		"owned_outer_interface_cleanup":               "PASS",
		"recovery_refusal_preserves_encrypted_tunnel": "PASS",
		"external_server":                             "NOT_RUN", "high_sierra": "NOT_RUN"})
}
