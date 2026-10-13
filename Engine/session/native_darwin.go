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
	recoverycore "legacywg/RecoveryCore"
)

type nativeNetwork struct {
	iface   string
	index   int
	routes  []netip.Prefix
	dns     *dnsProcess
	path    *pathWatch
	journal *recoverycore.Store
}

func (network *nativeNetwork) name() string    { return network.iface }
func (network *nativeNetwork) dnsActive() bool { return network.dns != nil && network.dns.alive.Load() }
func (network *nativeNetwork) dnsDone() <-chan struct{} {
	if network.dns == nil {
		return nil
	}
	return network.dns.done
}

func (network *nativeNetwork) pathDone() <-chan struct{} {
	if network.path == nil {
		return nil
	}
	return network.path.lost
}

func (network *nativeNetwork) finishRecovery() error {
	if network.journal == nil {
		return nil
	}
	return network.journal.Finish()
}

func reconcileNative() error { return recoverycore.Reconcile() }

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

func routeFamily(address netip.Addr) string {
	if address.Is6() {
		return "-inet6"
	}
	return "-inet"
}

func (network *nativeNetwork) close() error {
	if network.path != nil {
		if err := network.path.close(); err != nil {
			return err
		}
	}
	if network.dns != nil {
		if err := network.dns.close(); err != nil {
			return err
		}
	}
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
		if err := nativeCommand("/sbin/route", "-n", "delete", routeFamily(prefix.Addr()), "-net", prefix.String(), "-interface", network.iface); err != nil {
			remaining = append(remaining, prefix)
		}
	}
	network.routes = remaining
	if len(remaining) != 0 {
		return errors.New("route recovery requires attention")
	}
	return nil
}

func openNative(config *configcore.Config, uapi string, endpoints []netip.AddrPort) (*device.Device, *nativeNetwork, error) {
	if os.Geteuid() != 0 {
		return nil, nil, errors.New("authorized privileged component required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	paths, err := captureEndpointPaths(ctx, endpoints, nativeEndpointPath)
	cancel()
	if err != nil {
		return nil, nil, err
	}
	journal, err := recoverycore.Begin()
	if err != nil {
		return nil, nil, err
	}
	failBeforeEngine := func(tunnel tun.Device, reason error) (*device.Device, *nativeNetwork, error) {
		if tunnel != nil {
			tunnel.Close()
		}
		if journal.Finish() != nil {
			reason = recoverycore.ErrRecoveryRequired
		}
		journal.Close()
		return nil, nil, reason
	}
	mtu := int(config.MTU)
	if mtu == 0 {
		mtu = 1420
	}
	tunnel, err := tun.CreateTUN("utun", mtu)
	if err != nil {
		return failBeforeEngine(nil, errors.New("cannot create native utun"))
	}
	name, err := tunnel.Name()
	if err != nil || !regexp.MustCompile(`^utun[0-9]+$`).MatchString(name) {
		return failBeforeEngine(tunnel, errors.New("invalid native interface identity"))
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return failBeforeEngine(tunnel, errors.New("cannot identify native interface"))
	}
	if err := journal.MarkInterface(name, iface.Index); err != nil {
		return failBeforeEngine(tunnel, err)
	}
	network := &nativeNetwork{iface: name, index: iface.Index, journal: journal}
	engine := device.NewDevice(tunnel, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	fail := func() (*device.Device, *nativeNetwork, error) {
		if network.path != nil {
			network.path.close()
		}
		if network.dns != nil {
			network.dns.close()
		}
		// Removing the utun automatically removes its interface-bound routes.
		engine.Close()
		if network.finishRecovery() != nil {
			journal.Close()
			return nil, nil, recoverycore.ErrRecoveryRequired
		}
		return nil, nil, errors.New("tunnel transaction failed; native interface closed")
	}
	if err := engine.IpcSet(uapi); err != nil {
		return fail()
	}
	for _, prefix := range config.Addresses {
		if prefix.Addr().Is6() {
			if err := nativeCommand("/sbin/ifconfig", name, "inet6", prefix.Addr().String(), "prefixlen", "128", "alias"); err != nil {
				return fail()
			}
			continue
		}
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
			if err := nativeCommand("/sbin/route", "-n", "add", routeFamily(prefix.Addr()), "-net", prefix.String(), "-interface", name); err != nil {
				return fail()
			}
			seen[prefix] = true
			network.routes = append(network.routes, prefix)
		}
	}
	if len(config.DNS) > 0 {
		network.dns, err = startDNS(name, config.DNS)
		if err != nil {
			return fail()
		}
	}
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	err = verifyEndpointPaths(ctx, paths, nativeEndpointPath)
	cancel()
	if err != nil {
		return fail()
	}
	if journal.MarkConfigured(network.dns != nil) != nil {
		return fail()
	}
	network.path = startPathWatch(paths, nativeEndpointPath)
	return engine, network, nil
}
