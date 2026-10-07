// Package session adapts validated profiles to the unmodified official engine.
package session

import (
	"bufio"
	"bytes"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/device"
	configcore "legacywg/ConfigCore"
	networkcore "legacywg/NetworkCore"
)

type Status struct {
	State         string `json:"state"`
	Interface     string `json:"interface,omitempty"`
	Peers         int    `json:"peers"`
	Rx            uint64 `json:"rx_bytes"`
	Tx            uint64 `json:"tx_bytes"`
	LastHandshake int64  `json:"last_handshake_unix,omitempty"`
	Protected     bool   `json:"protected"`
}

type Session struct {
	mutex   sync.Mutex
	engine  *device.Device
	network *nativeNetwork
	peers   int
}

// Initial executor intentionally rejects unsupported policies before side
// effects. It is a real IPv4 split tunnel, never a fake full-tunnel safeguard.
func CheckCapabilities(config *configcore.Config) ([]netip.AddrPort, error) {
	plan, err := networkcore.Build(config, true)
	if err != nil {
		return nil, err
	}
	if plan.FullIPv4 || plan.FullIPv6 {
		return nil, errors.New("full tunnel is unavailable until IPv6 and DNS protection are implemented")
	}
	if len(config.DNS) != 0 {
		return nil, errors.New("DNS profiles require the native DNS transaction implementation")
	}
	if len(plan.Routes) > 64 {
		return nil, errors.New("initial native executor permits at most 64 routes")
	}
	if len(config.Addresses) > 4 {
		return nil, errors.New("initial native executor permits at most four local addresses")
	}
	for _, prefix := range append(append([]netip.Prefix(nil), plan.Addresses...), plan.Routes...) {
		if !prefix.Addr().Is4() {
			return nil, errors.New("IPv6 executor is not available")
		}
	}
	endpoints := make([]netip.AddrPort, len(config.Peers))
	for index, peer := range config.Peers {
		if peer.Endpoint == nil {
			continue
		}
		address, err := netip.ParseAddr(peer.Endpoint.Host)
		if err != nil || !address.Is4() {
			return nil, errors.New("initial native executor requires a numeric IPv4 endpoint")
		}
		for _, route := range plan.Routes {
			if route.Contains(address) {
				return nil, errors.New("endpoint overlaps a tunnel route; physical endpoint routing required")
			}
		}
		endpoints[index] = netip.AddrPortFrom(address, peer.Endpoint.Port)
	}
	return endpoints, nil
}

func (session *Session) Start(profile []byte) error {
	session.mutex.Lock()
	defer session.mutex.Unlock()
	if session.engine != nil {
		return errors.New("a tunnel is already active")
	}
	config, err := configcore.Parse(profile)
	if err != nil {
		return err
	}
	defer config.Destroy()
	endpoints, err := CheckCapabilities(config)
	if err != nil {
		return err
	}
	var configuration bytes.Buffer
	if err := config.WriteUAPI(&configuration, endpoints); err != nil {
		return err
	}
	defer clear(configuration.Bytes())
	engine, network, err := openNative(config, configuration.String())
	if err != nil {
		return err
	}
	session.engine, session.network, session.peers = engine, network, len(config.Peers)
	return nil
}

func (session *Session) Stop() error {
	session.mutex.Lock()
	defer session.mutex.Unlock()
	var cleanupError error
	if session.network != nil {
		cleanupError = session.network.close()
	}
	if session.engine != nil {
		session.engine.Close()
		session.engine = nil
	}
	if session.network != nil && cleanupError != nil {
		cleanupError = session.network.close()
	}
	if cleanupError != nil {
		return cleanupError
	}
	session.network = nil
	session.peers = 0
	return nil
}

func (session *Session) Status() (Status, error) {
	session.mutex.Lock()
	defer session.mutex.Unlock()
	result := Status{State: "Disconnected"}
	if session.engine == nil {
		if session.network != nil {
			result.State = "RecoveryRequired"
		}
		return result, nil
	}
	result.State, result.Interface, result.Peers = "Connecting", session.network.name(), session.peers
	raw, err := session.engine.IpcGet()
	if err != nil {
		return result, errors.New("cannot read engine statistics")
	}
	// The private-key-bearing UAPI is never returned or logged. Only these
	// numeric fields cross the privilege boundary.
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		field, value, found := strings.Cut(scanner.Text(), "=")
		if !found {
			continue
		}
		number, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			continue
		}
		switch field {
		case "rx_bytes":
			result.Rx += number
		case "tx_bytes":
			result.Tx += number
		case "last_handshake_time_sec":
			if number <= uint64(time.Now().Unix()) && int64(number) > result.LastHandshake {
				result.LastHandshake = int64(number)
			}
		}
	}
	if result.LastHandshake > 0 {
		result.State = "Connected"
	}
	return result, nil
}
