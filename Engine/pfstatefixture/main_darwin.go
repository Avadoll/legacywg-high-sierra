//go:build darwin

// Developer-only native TCP peer. It never ships with the app, accepts no
// profiles/keys/addresses/commands, and uses the pinned official netstack.
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
	"regexp"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const server4 = "198.18.99.130"
const server6 = "fd00:198:18:99::130"

var packets4, packets6, accepted atomic.Uint64

func command(program string, arguments ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	process := exec.CommandContext(ctx, program, arguments...)
	process.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}
	if process.Run() != nil {
		return errors.New("owned TCP fixture setup failed")
	}
	return nil
}

func bridge(source, destination tun.Device, observe bool) {
	buffer := make([]byte, 65536)
	buffers, sizes := [][]byte{buffer}, []int{0}
	for {
		n, err := source.Read(buffers, sizes, 4)
		if err != nil || n != 1 || sizes[0] < 1 || sizes[0] > len(buffer)-4 {
			return
		}
		packet := buffer[4 : 4+sizes[0]]
		if observe {
			if packet[0]>>4 == 4 && len(packet) >= 40 && packet[9] == 6 {
				packets4.Add(1)
			}
			if packet[0]>>4 == 6 && len(packet) >= 60 && packet[6] == 6 {
				packets6.Add(1)
			}
		}
		if _, err := destination.Write([][]byte{buffer[:4+sizes[0]]}, 4); err != nil {
			return
		}
	}
}

func serve(listener net.Listener) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		accepted.Add(1)
		go func() {
			defer connection.Close()
			connection.SetDeadline(time.Now().Add(4 * time.Minute))
			// Only a bounded echo fixture, no DNS or external dial/proxy.
			io.Copy(connection, io.LimitReader(connection, 64*1024))
		}()
	}
}

func fixture() error {
	if len(os.Args) != 1 || os.Geteuid() != 0 || os.Getenv("GITHUB_ACTIONS") != "true" {
		return errors.New("disposable native CI fixture only")
	}
	if unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}) != nil {
		return errors.New("cannot disable fixture core dumps")
	}
	native, err := tun.CreateTUN("utun", 1280)
	if err != nil {
		return errors.New("cannot create owned TCP fixture interface")
	}
	defer native.Close()
	name, err := native.Name()
	if err != nil || !regexp.MustCompile(`^utun[0-9]{1,10}$`).MatchString(name) {
		return errors.New("cannot identify owned TCP fixture interface")
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return errors.New("cannot identify owned TCP fixture index")
	}
	virtual, stack, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(server4), netip.MustParseAddr(server6)}, nil, 1280)
	if err != nil {
		return errors.New("cannot create pinned TCP fixture stack")
	}
	defer virtual.Close()
	var listeners []net.Listener
	defer func() {
		for _, listener := range listeners {
			listener.Close()
		}
	}()
	for _, address := range []string{server4 + ":45111", server4 + ":45112", "[" + server6 + "]:45111", "[" + server6 + "]:45112"} {
		listener, err := stack.ListenTCPAddrPort(netip.MustParseAddrPort(address))
		if err != nil {
			return errors.New("cannot listen on owned TCP fixture")
		}
		listeners = append(listeners, listener)
		go serve(listener)
	}
	go bridge(native, virtual, true)
	go bridge(virtual, native, false)
	if command("/sbin/ifconfig", name, "inet", "198.18.99.129", "198.18.99.129", "netmask", "255.255.255.255", "alias") != nil ||
		command("/sbin/ifconfig", name, "inet6", "fd00:198:18:99::129", "prefixlen", "128", "alias") != nil ||
		command("/sbin/ifconfig", name, "up") != nil ||
		command("/sbin/route", "-n", "add", "-inet", "-host", server4, "-interface", name) != nil ||
		command("/sbin/route", "-n", "add", "-inet6", "-host", server6, "-interface", name) != nil {
		return errors.New("owned TCP fixture addressing failed")
	}
	// The identity stays on the private developer pipe; reports omit it.
	encoder := json.NewEncoder(os.Stdout)
	if encoder.Encode(map[string]any{"ready": true, "interface": name, "index": iface.Index}) != nil {
		return errors.New("fixture control pipe unavailable")
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64), 256)
	for scanner.Scan() {
		switch scanner.Text() {
		case "stats":
			encoder.Encode(map[string]uint64{"tcp4_packets": packets4.Load(), "tcp6_packets": packets6.Load(), "accepted": accepted.Load()})
		default:
			return errors.New("unsupported fixture operation")
		}
	}
	return nil // EOF closes this utun and its interface-bound routes.
}

func main() {
	if err := fixture(); err != nil {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"ready": false, "error": err.Error()})
		os.Exit(1)
	}
}
