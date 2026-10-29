// Package session adapts validated profiles to the unmodified official engine.
package session

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/device"
	configcore "legacywg/ConfigCore"
	networkcore "legacywg/NetworkCore"
	recoverycore "legacywg/RecoveryCore"
)

type Status struct {
	State         string       `json:"state"`
	Interface     string       `json:"interface,omitempty"`
	Peers         int          `json:"peers"`
	Rx            uint64       `json:"rx_bytes"`
	Tx            uint64       `json:"tx_bytes"`
	LastHandshake int64        `json:"last_handshake_unix,omitempty"`
	Protected     bool         `json:"protected"`
	DNSConfigured bool         `json:"dns_configured"`
	Reason        string       `json:"reason,omitempty"`
	TunnelStarted bool         `json:"tunnel_started"`
	PeerDetails   []PeerStatus `json:"peer_details,omitempty"`
}

type Session struct {
	mutex            sync.Mutex
	engine           *device.Device
	network          *nativeNetwork
	peers            int
	failure          string
	recoveryRequired bool
	peerIndices      map[string]int
}

// Initialize is called by the private worker before processing requests.
// It never creates a tunnel or profile and preserves ambiguous owned records.
func (session *Session) Initialize() {
	session.mutex.Lock()
	defer session.mutex.Unlock()
	if session.engine == nil && session.network == nil {
		session.recoveryRequired = reconcileNative() != nil
	}
}

func CheckCapabilities(config *configcore.Config) ([]netip.AddrPort, error) {
	plan, err := networkcore.Build(config, true)
	if err != nil {
		return nil, err
	}
	full := plan.FullIPv4 || plan.FullIPv6
	if full {
		if err := checkFullMode(config, plan); err != nil {
			return nil, err
		}
	}
	if len(config.DNS) > 8 {
		return nil, errors.New("at most eight DNS servers are supported")
	}
	for _, address := range config.DNS {
		covered := false
		for _, route := range plan.Routes {
			covered = covered || route.Contains(address)
		}
		if !covered {
			return nil, errors.New("profile DNS must be routed through the tunnel")
		}
	}
	if len(plan.Routes) > 64 {
		return nil, errors.New("initial native executor permits at most 64 routes")
	}
	if len(config.Addresses) > 4 {
		return nil, errors.New("initial native executor permits at most four local addresses")
	}
	hasIPv4, hasIPv6 := false, false
	for _, prefix := range plan.Addresses {
		hasIPv4 = hasIPv4 || prefix.Addr().Is4()
		hasIPv6 = hasIPv6 || prefix.Addr().Is6()
	}
	if hasIPv6 && config.MTU != 0 && config.MTU < 1280 {
		return nil, errors.New("IPv6 requires an MTU of at least 1280")
	}
	for _, route := range plan.Routes {
		if route.Addr().Is4() && !hasIPv4 || route.Addr().Is6() && !hasIPv6 {
			return nil, errors.New("tunnel route requires a local address of the same family")
		}
	}
	endpoints := make([]netip.AddrPort, len(config.Peers))
	for index, peer := range config.Peers {
		if peer.Endpoint == nil {
			continue
		}
		address, err := netip.ParseAddr(peer.Endpoint.Host)
		if err != nil {
			// Pure validation must never issue DNS requests. Start resolves
			// these entries before creating an interface or changing DNS.
			continue
		}
		for _, local := range config.Addresses {
			if address == local.Addr() {
				return nil, errors.New("endpoint cannot equal a local tunnel address")
			}
		}
		for _, route := range plan.Routes {
			if !full && route.Contains(address) {
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
	if session.engine != nil || session.network != nil {
		return errors.New("a tunnel is already active")
	}
	if session.recoveryRequired {
		return recoverycore.ErrRecoveryRequired
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	endpoints, err = resolveEndpoints(ctx, config, endpoints, systemLookup)
	cancel()
	if err != nil {
		return err
	}
	var configuration bytes.Buffer
	if err := config.WriteUAPI(&configuration, endpoints); err != nil {
		return err
	}
	defer clear(configuration.Bytes())
	engine, network, err := openNative(config, configuration.String(), endpoints)
	if err != nil {
		if errors.Is(err, recoverycore.ErrRecoveryRequired) {
			session.recoveryRequired = true
		}
		return err
	}
	session.engine, session.network, session.peers = engine, network, len(config.Peers)
	session.peerIndices = peerIndices(configuration.String())
	session.failure = ""
	session.recoveryRequired = false
	if done := network.dnsDone(); done != nil {
		go session.watchNetwork(network, done, "native DNS configuration was lost; tunnel closed")
	}
	if done := network.pathDone(); done != nil {
		go session.watchNetwork(network, done, "endpoint route changed or became unavailable; tunnel closed")
	}
	return nil
}

func (session *Session) watchNetwork(network *nativeNetwork, done <-chan struct{}, reason string) {
	<-done
	session.mutex.Lock()
	defer session.mutex.Unlock()
	if session.network != network || session.engine == nil {
		return
	}
	session.engine.Close()
	session.engine = nil
	session.failure = reason
	if network.close() == nil && network.finishRecovery() == nil {
		session.network = nil
		session.peers = 0
		session.peerIndices = nil
	}
}

func (session *Session) Stop() error {
	session.mutex.Lock()
	defer session.mutex.Unlock()
	return session.stopLocked()
}

// Recover refuses to stop a live connection implicitly. Explicit Disconnect
// retains its own semantics; recovery only completes an interrupted cleanup.
func (session *Session) Recover() error {
	session.mutex.Lock()
	defer session.mutex.Unlock()
	if session.engine != nil {
		return errors.New("disconnect required before recovery")
	}
	session.recoveryRequired = true
	return session.stopLocked()
}

func (session *Session) stopLocked() error {
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
	if cleanupError == nil && session.network != nil {
		cleanupError = session.network.finishRecovery()
	}
	if cleanupError != nil {
		session.recoveryRequired = true
		return cleanupError
	}
	session.network = nil
	if session.recoveryRequired && reconcileNative() != nil {
		return recoverycore.ErrRecoveryRequired
	}
	session.recoveryRequired = false
	session.peers = 0
	session.peerIndices = nil
	session.failure = ""
	return nil
}

func (session *Session) Status() (Status, error) {
	session.mutex.Lock()
	defer session.mutex.Unlock()
	result := Status{State: "Disconnected"}
	if session.engine == nil {
		if session.network != nil || session.recoveryRequired {
			result.State = "RecoveryRequired"
			result.Reason = recoverycore.ErrRecoveryRequired.Error()
		} else if session.failure != "" {
			result.State = "Error"
			result.Reason = session.failure
		}
		return result, nil
	}
	result.State, result.Interface, result.Peers = "Connecting", session.network.name(), session.peers
	result.DNSConfigured = session.network.dnsActive()
	result.TunnelStarted = true
	raw, err := session.engine.IpcGet()
	if err != nil {
		return result, errors.New("cannot read engine statistics")
	}
	if err := readPeerStatistics(raw, session.peerIndices, time.Now().Unix(), &result); err != nil {
		return result, err
	}
	if result.LastHandshake > 0 {
		result.State = "Connected"
	}
	return result, nil
}
