package session

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	configcore "legacywg/ConfigCore"
)

type nativeNetwork struct {
	iface  string
	index  int
	routes []netip.Prefix
}

func (network *nativeNetwork) name() string { return network.iface }

func nativeCommand(program string, arguments ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, program, arguments...)
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}
	// No profile, key or UAPI appears in argv. All arguments below are typed
	// canonical addresses and the kernel-selected utun name; no shell.
	if err := command.Run(); err != nil {
		return errors.New("native network operation failed")
	}
	return nil
}

func (network *nativeNetwork) close() error {
	interfaces, err := net.Interfaces()
	if err != nil {
		return errors.New("cannot verify native interface ownership during recovery")
	}
	same := false
	for _, current := range interfaces {
		if current.Name == network.iface && current.Index == network.index {
			same = true
		}
	}
	if !same {
		// The original interface has gone. Never delete routes on a reused
		// utun name belonging to a different kernel interface instance.
		network.routes = nil
		return nil
	}
	remaining := []netip.Prefix{}
	for index := len(network.routes) - 1; index >= 0; index-- {
		prefix := network.routes[index]
		// Scope deletion to the actual tunnel interface, not an unrelated
		// route created by another application with the same destination.
		if err := nativeCommand("/sbin/route", "-n", "delete", "-inet", "-net", prefix.String(), "-interface", network.iface); err != nil {
			remaining = append(remaining, prefix)
		}
	}
	network.routes = remaining
	if len(remaining) != 0 {
		return errors.New("route recovery requires attention")
	}
	return nil
}

func openNative(config *configcore.Config, uapi string) (*device.Device, *nativeNetwork, error) {
	if os.Geteuid() != 0 {
		return nil, nil, errors.New("authorized privileged component required")
	}
	mtu := int(config.MTU)
	if mtu == 0 {
		mtu = 1420
	}
	tunnel, err := tun.CreateTUN("utun", mtu)
	if err != nil {
		return nil, nil, errors.New("cannot create native utun")
	}
	name, err := tunnel.Name()
	if err != nil || !regexp.MustCompile(`^utun[0-9]+$`).MatchString(name) {
		tunnel.Close()
		return nil, nil, errors.New("invalid native interface identity")
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		tunnel.Close()
		return nil, nil, errors.New("cannot identify native interface")
	}
	network := &nativeNetwork{iface: name, index: iface.Index}
	engine := device.NewDevice(tunnel, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	fail := func() (*device.Device, *nativeNetwork, error) {
		// Removing the utun automatically removes its interface-bound routes.
		engine.Close()
		return nil, nil, errors.New("tunnel transaction failed; native interface closed")
	}
	if err := engine.IpcSet(uapi); err != nil {
		return fail()
	}
	for _, prefix := range config.Addresses {
		// Point-to-point host addresses avoid implicit broad connected routes;
		// AllowedIPs explicitly determines which networks use this interface.
		if err := nativeCommand("/sbin/ifconfig", name, "inet", prefix.Addr().String(), prefix.Addr().String(),
			"netmask", "255.255.255.255", "alias"); err != nil {
			return fail()
		}
	}
	if err := engine.Up(); err != nil {
		return fail()
	}
	seen := map[netip.Prefix]bool{}
	for _, peer := range config.Peers {
		for _, prefix := range peer.AllowedIPs {
			prefix = prefix.Masked()
			if seen[prefix] {
				continue
			}
			if err := nativeCommand("/sbin/route", "-n", "add", "-inet", "-net", prefix.String(), "-interface", name); err != nil {
				return fail()
			}
			seen[prefix] = true
			network.routes = append(network.routes, prefix)
		}
	}
	return engine, network, nil
}
