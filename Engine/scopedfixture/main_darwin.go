// Developer-only kernel experiment. No code from this package enters the app.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func command(program string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, program, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}
	data, err := cmd.CombinedOutput()
	if err != nil {
		return "", errors.New("fixed fixture network operation failed")
	}
	return string(data), nil
}

func path(address netip.Addr) (string, error) {
	family := "-inet"
	if address.Is6() {
		family = "-inet6"
	}
	output, err := command("/sbin/route", "-n", "get", family, address.String())
	if address.Is6() && strings.Contains(output, "not in table") {
		return "NO_ROUTE", nil
	}
	if err != nil {
		return "", err
	}
	var values []string
	for _, line := range strings.Split(output, "\n") {
		field, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok && (field == "interface" || field == "gateway") {
			values = append(values, field+":"+strings.TrimSpace(value))
		}
	}
	if len(values) == 0 {
		return "", errors.New("fixture route identity missing")
	}
	return strings.Join(values, "\n"), nil
}

func socket(local netip.Addr, index int) (*net.UDPConn, error) {
	return socketPort(local, index, 0)
}
func socketPort(local netip.Addr, index int, port uint16) (*net.UDPConn, error) {
	family, level, option := "udp4", unix.IPPROTO_IP, unix.IP_BOUND_IF
	if local.Is6() {
		family, level, option = "udp6", unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
	}
	config := net.ListenConfig{}
	if index != 0 {
		config.Control = func(_, _ string, raw syscall.RawConn) error {
			var failure error
			err := raw.Control(func(fd uintptr) {
				failure = unix.SetsockoptInt(int(fd), level, option, index)
				if failure == nil {
					actual, err := unix.GetsockoptInt(int(fd), level, option)
					if err != nil || actual != index {
						failure = errors.New("socket interface option not confirmed")
					}
				}
			})
			if err != nil {
				return err
			}
			return failure
		}
	}
	// Match the official standard transport's wildcard listener: selecting a
	// local source IP must not be the reason the socket chooses an interface.
	listen := netip.IPv4Unspecified()
	if local.Is6() {
		listen = netip.IPv6Unspecified()
	}
	value, err := config.ListenPacket(context.Background(), family, net.JoinHostPort(listen.String(), strconv.Itoa(int(port))))
	if err != nil {
		return nil, errors.New("fixture native socket failed")
	}
	return value.(*net.UDPConn), nil
}

func echo(socket *net.UDPConn, remote netip.Addr) bool {
	payload := []byte("LegacyWG scoped kernel endpoint probe")
	socket.SetDeadline(time.Now().Add(600 * time.Millisecond))
	if _, err := socket.WriteToUDPAddrPort(payload, netip.AddrPortFrom(remote, 54323)); err != nil {
		return false
	}
	data := make([]byte, 256)
	size, source, err := socket.ReadFromUDPAddrPort(data)
	return err == nil && source == netip.AddrPortFrom(remote, 54323) && bytes.Equal(data[:size], payload)
}

func check(ipv6 bool) (map[string]any, error) {
	failure := errors.New("scoped UDP experiment failed")
	local, remote, prefix := netip.MustParseAddr("198.18.77.1"), netip.MustParseAddr("198.18.77.2"), "198.18.77.0/24"
	family := "-inet"
	if ipv6 {
		local, remote, prefix = netip.MustParseAddr("2001:db8:77::1"), netip.MustParseAddr("2001:db8:77::2"), "2001:db8:77::/64"
		family = "-inet6"
	}
	baseline, err := path(remote)
	if err != nil {
		return nil, err
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
		for _, value := range addresses {
			p, err := netip.ParsePrefix(value.String())
			if err == nil && (p.Contains(local) || p.Contains(remote)) {
				return nil, errors.New("benchmark addresses already assigned")
			}
		}
	}
	outer, err := tun.CreateTUN("utun", 1420)
	if err != nil {
		return nil, failure
	}
	defer outer.Close()
	name, err := outer.Name()
	if err != nil {
		return nil, failure
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, failure
	}
	if ipv6 {
		_, err = command("/sbin/ifconfig", name, "inet6", local.String(), "prefixlen", "128", "alias")
	} else {
		_, err = command("/sbin/ifconfig", name, "inet", local.String(), local.String(), "netmask", "255.255.255.255", "alias")
	}
	if err != nil {
		return nil, err
	}
	// Only synthetic prefix routes tied to the owned surrogate interface.
	// No physical route, default, PF setting or persistent host escape is changed.
	if _, err = command("/sbin/route", "-n", "add", family, "-net", prefix, "-interface", name); err != nil {
		return nil, err
	}
	// A bound socket needs a usable route in that interface's scope. Prove
	// this separately from the unscoped route; this is still an owned utun
	// route, not permission to install a persistent physical route in product.
	if _, err = command("/sbin/route", "-n", "add", family, "-net", prefix, "-interface", name, "-ifscope", name); err != nil {
		return nil, err
	}
	original, err := path(remote)
	if err != nil || !strings.Contains(original, "interface:"+name) {
		return nil, errors.New("outer fixture prefix not selected")
	}
	serverTun, stack, err := netstack.CreateNetTUN([]netip.Addr{remote}, nil, 1420)
	if err != nil {
		return nil, failure
	}
	incomingDone := make(chan struct{})
	defer func() {
		outer.Close()
		select {
		case <-incomingDone:
		case <-time.After(time.Second):
		}
		serverTun.Close()
	}()
	go func() {
		defer close(incomingDone)
		buffer := [][]byte{make([]byte, 65539)}
		sizes := make([]int, 1)
		for {
			count, err := outer.Read(buffer, sizes, 4)
			if err != nil {
				return
			}
			if count == 1 {
				if _, err = serverTun.Write([][]byte{buffer[0][:4+sizes[0]]}, 4); err != nil {
					return
				}
			}
		}
	}()
	go func() {
		buffer := [][]byte{make([]byte, 65539)}
		sizes := make([]int, 1)
		for {
			count, err := serverTun.Read(buffer, sizes, 4)
			if err != nil {
				return
			}
			if count == 1 {
				if _, err = outer.Write([][]byte{buffer[0][:4+sizes[0]]}, 4); err != nil {
					return
				}
			}
		}
	}()
	server, err := stack.ListenUDPAddrPort(netip.AddrPortFrom(remote, 54323))
	if err != nil {
		return nil, failure
	}
	defer server.Close()
	go func() {
		data := make([]byte, 256)
		for {
			size, from, err := server.ReadFrom(data)
			if err != nil {
				return
			}
			if _, err = server.WriteTo(data[:size], from); err != nil {
				return
			}
		}
	}()
	plain, err := socket(local, 0)
	if err != nil {
		return nil, err
	}
	defer plain.Close()
	bound, err := socket(local, iface.Index)
	if err != nil {
		return nil, err
	}
	defer bound.Close()
	if !echo(plain, remote) || !echo(bound, remote) {
		return nil, errors.New("kernel baseline echo failed")
	}
	encrypted, err := startEncrypted(stack, local, remote, iface.Index)
	if err != nil {
		return nil, err
	}
	defer encrypted.close()
	if !encrypted.roundTrip() || !officialStats(encrypted.client) || !officialStats(encrypted.server) {
		return nil, errors.New("official baseline handshake and encrypted echo failed")
	}
	decoy, err := tun.CreateTUN("utun", 1420)
	if err != nil {
		return nil, failure
	}
	defer decoy.Close()
	decoyName, err := decoy.Name()
	if err != nil {
		return nil, failure
	}
	initialDecoy, err := net.InterfaceByName(decoyName)
	if err != nil {
		return nil, failure
	}
	if ipv6 {
		_, err = command("/sbin/ifconfig", decoyName, "inet6", "2001:db8:77::9", "prefixlen", "128", "alias")
	} else {
		_, err = command("/sbin/ifconfig", decoyName, "inet", "198.18.77.9", "198.18.77.9", "netmask", "255.255.255.255", "alias")
	}
	if err != nil {
		return nil, err
	}
	configuredDecoy, err := net.InterfaceByName(decoyName)
	if err != nil || configuredDecoy.Flags&net.FlagUp == 0 {
		return nil, errors.New("configured decoy interface not up")
	}
	var dropped atomic.Int64
	decoyDone := make(chan struct{})
	go func() {
		defer close(decoyDone)
		buffer := [][]byte{make([]byte, 65539)}
		sizes := make([]int, 1)
		for {
			count, err := decoy.Read(buffer, sizes, 4)
			if err != nil {
				return
			}
			if count == 1 {
				packet := buffer[0][4 : 4+sizes[0]]
				if (!ipv6 && len(packet) >= 20 && packet[0]>>4 == 4 && bytes.Equal(packet[16:20], remote.AsSlice())) ||
					(ipv6 && len(packet) >= 40 && packet[0]>>4 == 6 && bytes.Equal(packet[24:40], remote.AsSlice())) {
					dropped.Add(1)
				}
			}
		}
	}()
	host := netip.PrefixFrom(remote, remote.BitLen()).String()
	if _, err = command("/sbin/route", "-n", "add", family, "-net", host, "-interface", decoyName); err != nil {
		return nil, err
	}
	conflict, err := path(remote)
	if err != nil || !strings.Contains(conflict, "interface:"+decoyName) {
		return map[string]any{"decoy_initially_up": initialDecoy.Flags&net.FlagUp != 0, "decoy_configured_up": true}, errors.New("more specific conflict did not select decoy")
	}
	// The old plain socket may cache a route, so test a fresh unbound socket.
	negative, err := socket(local, 0)
	if err != nil {
		return nil, err
	}
	defer negative.Close()
	if echo(negative, remote) || dropped.Load() == 0 {
		return nil, errors.New("unbound negative control did not enter decoy")
	}
	before := dropped.Load()
	for attempt := 0; attempt < 4; attempt++ {
		if !echo(bound, remote) {
			return map[string]any{"bound_packets_on_decoy": dropped.Load() - before, "scoped_prefix_added": true}, errors.New("interface-bound round trip failed under competing route")
		}
	}
	time.Sleep(100 * time.Millisecond)
	if dropped.Load() != before {
		return nil, errors.New("bound traffic reached decoy")
	}
	before = dropped.Load()
	for attempt := 0; attempt < 4; attempt++ {
		if !encrypted.roundTrip() {
			return nil, errors.New("encrypted scoped echo failed under conflicting route")
		}
	}
	if encrypted.client.Down() != nil || encrypted.client.Up() != nil || encrypted.transport.opens.Load() < 2 || !encrypted.roundTrip() || !officialStats(encrypted.client) || !officialStats(encrypted.server) {
		return nil, errors.New("encrypted scoped transport reopen failed")
	}
	time.Sleep(100 * time.Millisecond)
	if dropped.Load() != before {
		return nil, errors.New("encrypted scoped transport reached decoy")
	}
	// Interface loss must not silently fall back to the conflicting route.
	if outer.Close() != nil {
		return nil, failure
	}
	select {
	case <-incomingDone:
	case <-time.After(time.Second):
		return nil, failure
	}
	before = dropped.Load()
	lost := !echo(bound, remote) && !encrypted.roundTrip()
	time.Sleep(100 * time.Millisecond)
	if !lost || dropped.Load() != before {
		return nil, errors.New("bound socket escaped after interface loss")
	}
	if decoy.Close() != nil {
		return nil, failure
	}
	select {
	case <-decoyDone:
	case <-time.After(time.Second):
		return nil, failure
	}
	restored, err := path(remote)
	if err != nil || restored != baseline {
		return nil, errors.New("baseline route not restored")
	}
	return map[string]any{"status": "PASS", "baseline_plain_and_bound_echo": "PASS", "unbound_conflict_negative_control": "PASS",
		"bound_echo_with_conflicting_host_route": "PASS", "bound_round_trips": 4, "bound_packets_on_decoy": 0,
		"interface_loss_no_fallback": "PASS", "baseline_route_restoration": "PASS",
		"official_handshake_and_counters": "PASS", "encrypted_bound_round_trips": 6, "encrypted_decoy_packets": 0,
		"old_receive_callback_stays_closed_after_reopen": "PASS", "official_device_down_up_scoped_reopen": "PASS",
		"wildcard_listeners": true, "scoped_prefix_added": true, "decoy_initially_up": initialDecoy.Flags&net.FlagUp != 0, "decoy_configured_up": true}, nil
}

func main() {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Geteuid() != 0 {
		os.Exit(3)
	}
	var limits unix.Rlimit
	limits.Cur = 0
	limits.Max = 0
	if unix.Setrlimit(unix.RLIMIT_CORE, &limits) != nil {
		os.Exit(3)
	}
	baselineInterfaces, err := net.Interfaces()
	if err != nil {
		os.Exit(3)
	}
	report := map[string]any{"status": "FAIL", "kind": "developer-only-scoped-UDP-routing",
		"source_commit": os.Getenv("GITHUB_SHA"), "physical_nic": "NOT_RUN", "encrypted_wireguard": "NOT_RUN",
		"high_sierra": "NOT_RUN", "product_transport": "UNCHANGED", "protection_ready": false}
	for _, v6 := range []bool{false, true} {
		name := "ipv4"
		if v6 {
			name = "ipv6"
		}
		proof, err := check(v6)
		if err != nil {
			report[name] = proof
			report["reason"] = err.Error()
			json.NewEncoder(os.Stdout).Encode(report)
			os.Exit(1)
		}
		report[name] = proof
	}
	finalInterfaces, err := net.Interfaces()
	if err != nil || len(finalInterfaces) != len(baselineInterfaces) {
		report["reason"] = "interface baseline not restored"
		json.NewEncoder(os.Stdout).Encode(report)
		os.Exit(1)
	}
	for _, before := range baselineInterfaces {
		found := false
		for _, after := range finalInterfaces {
			if before.Index == after.Index && before.Name == after.Name {
				found = true
			}
		}
		if !found {
			report["reason"] = "interface baseline identity changed"
			json.NewEncoder(os.Stdout).Encode(report)
			os.Exit(1)
		}
	}
	report["interface_set_restored"] = "PASS"
	report["encrypted_wireguard"] = "PASS"
	report["status"] = "PASS"
	json.NewEncoder(os.Stdout).Encode(report)
}
