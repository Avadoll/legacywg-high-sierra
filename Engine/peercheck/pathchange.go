package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// Disposable CI fixture: an independently owned outer utun/local host address
// reaches the real official peer's kernel UDP listener. Closing that utun
// changes the endpoint path without altering a physical NIC/default gateway,
// overwriting a foreign route or fabricating a worker status.
func createOuterFixture() (func() error, error) {
	failure := errors.New("controlled outer endpoint fixture failed")
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Geteuid() != 0 {
		return nil, failure
	}
	address := netip.MustParseAddr("198.18.99.3")
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) > 1024 {
		return nil, failure
	}
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil || len(addresses) > 256 {
			return nil, failure
		}
		for _, value := range addresses {
			prefix, err := netip.ParsePrefix(value.String())
			if err == nil && prefix.Contains(address) {
				return nil, errors.New("benchmark outer address already assigned")
			}
		}
	}
	original, err := physicalRoute(address)
	if err != nil {
		return nil, failure
	}
	outer, err := tun.CreateTUN("utun", 1420)
	if err != nil {
		return nil, failure
	}
	name, err := outer.Name()
	if err != nil {
		outer.Close()
		return nil, failure
	}
	var once sync.Once
	var closeError error
	closeOuter := func() error {
		once.Do(func() {
			if outer.Close() != nil {
				closeError = failure
				return
			}
			if _, err := net.InterfaceByName(name); err == nil {
				closeError = errors.New("owned outer interface was not removed")
				return
			}
			after, err := physicalRoute(address)
			if err != nil || after != original {
				closeError = errors.New("outer endpoint baseline route was not restored")
			}
		})
		return closeError
	}
	// No shell; the address is a constant test fixture and name is returned by
	// the official native TUN implementation, never supplied by a profile.
	command := exec.Command("/sbin/ifconfig", name, "inet", address.String(), address.String(), "netmask", "255.255.255.255", "alias")
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}
	if command.Run() != nil {
		closeOuter()
		return nil, failure
	}
	selected, err := physicalRoute(address)
	if err != nil || selected == original {
		closeOuter()
		return nil, failure
	}
	// The point-to-point host route sends packets to the utun descriptor.
	// Reflect only UDP packets whose source and destination are this isolated
	// test address back through its ingress. This is a kernel UDP path, not a
	// replacement WireGuard engine or a simulated handshake.
	go func() {
		buffers := [][]byte{make([]byte, 65539)}
		sizes := make([]int, 1)
		for {
			n, err := outer.Read(buffers, sizes, 4)
			if err != nil {
				return
			}
			if n != 1 || sizes[0] < 28 {
				continue
			}
			packet := buffers[0][4 : 4+sizes[0]]
			if packet[0] != 0x45 || packet[9] != 17 || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) || binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
				continue
			}
			if netip.AddrFrom4([4]byte(packet[12:16])) != address || netip.AddrFrom4([4]byte(packet[16:20])) != address {
				continue
			}
			if int(binary.BigEndian.Uint16(packet[24:26])) != len(packet)-20 {
				continue
			}
			if _, err = outer.Write([][]byte{buffers[0][:4+sizes[0]]}, 4); err != nil {
				return
			}
		}
	}()
	return closeOuter, nil
}

func runOuterFixture() int {
	closeOuter, err := createOuterFixture()
	if err != nil {
		json.NewEncoder(os.Stdout).Encode(map[string]bool{"ok": false})
		return 1
	}
	defer closeOuter()
	if json.NewEncoder(os.Stdout).Encode(map[string]bool{"ok": true}) != nil {
		return 1
	}
	done := make(chan struct{})
	go func() { io.Copy(io.Discard, os.Stdin); close(done) }()
	// A parent crash closes the pipe; the independent lease also closes the
	// fixture if a paused/malfunctioning parent still owns an open pipe.
	select {
	case <-done:
	case <-time.After(30 * time.Second):
	}
	if closeOuter() != nil {
		return 1
	}
	return 0
}

func outerEndpointFixture() (func() error, error) {
	failure := errors.New("controlled outer endpoint fixture failed")
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		return nil, failure
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, failure
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	command := exec.CommandContext(ctx, "/usr/bin/sudo", "-n", "/usr/bin/env", "GITHUB_ACTIONS=true", executable, "--outer-fixture")
	input, err := command.StdinPipe()
	if err != nil {
		cancel()
		return nil, failure
	}
	output, err := command.StdoutPipe()
	if err != nil {
		input.Close()
		cancel()
		return nil, failure
	}
	if command.Start() != nil {
		input.Close()
		output.Close()
		cancel()
		return nil, failure
	}
	var once sync.Once
	var closeError error
	closeOuter := func() error {
		once.Do(func() {
			input.Close()
			io.Copy(io.Discard, output)
			if command.Wait() != nil {
				closeError = failure
			}
			cancel()
		})
		return closeError
	}
	ready := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(output)
		scanner.Buffer(make([]byte, 128), 512)
		var reply struct {
			OK bool `json:"ok"`
		}
		ready <- scanner.Scan() && json.Unmarshal(scanner.Bytes(), &reply) == nil && reply.OK
	}()
	select {
	case ok := <-ready:
		if ok {
			if verifyOuterUDP() != nil {
				closeOuter()
				return nil, errors.New("controlled outer kernel UDP probe failed")
			}
			return closeOuter, nil
		}
	case <-time.After(5 * time.Second):
	}
	closeOuter()
	return nil, failure
}

func verifyOuterUDP() error {
	failure := errors.New("outer kernel UDP probe failed")
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return failure
	}
	defer listener.Close()
	listener.SetDeadline(time.Now().Add(2 * time.Second))
	go func() {
		buffer := make([]byte, 128)
		n, remote, err := listener.ReadFromUDP(buffer)
		if err == nil {
			listener.WriteToUDP(buffer[:n], remote)
		}
	}()
	client, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(198, 18, 99, 3), Port: listener.LocalAddr().(*net.UDPAddr).Port})
	if err != nil {
		return failure
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(2 * time.Second))
	payload := "LegacyWG owned outer UDP probe"
	if _, err = client.Write([]byte(payload)); err != nil {
		return failure
	}
	buffer := make([]byte, 128)
	n, err := client.Read(buffer)
	if err != nil || string(buffer[:n]) != payload {
		return failure
	}
	return nil
}
