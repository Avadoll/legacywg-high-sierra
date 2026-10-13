//go:build !darwin

package session

import (
	"errors"
	"golang.zx2c4.com/wireguard/device"
	configcore "legacywg/ConfigCore"
	"net/netip"
)

type nativeNetwork struct{}

func reconcileNative() error { return nil }

func (*nativeNetwork) name() string              { return "" }
func (*nativeNetwork) close() error              { return nil }
func (*nativeNetwork) dnsActive() bool           { return false }
func (*nativeNetwork) dnsDone() <-chan struct{}  { return nil }
func (*nativeNetwork) pathDone() <-chan struct{} { return nil }
func (*nativeNetwork) finishRecovery() error     { return nil }
func openNative(*configcore.Config, string, []netip.AddrPort) (*device.Device, *nativeNetwork, error) {
	return nil, nil, errors.New("native VPN sessions require macOS")
}
