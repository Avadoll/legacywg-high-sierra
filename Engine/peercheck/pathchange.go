package main

import (
	"bufio"
	"context"
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
			return closeOuter, nil
		}
	case <-time.After(5 * time.Second):
	}
	closeOuter()
	return nil, failure
}
