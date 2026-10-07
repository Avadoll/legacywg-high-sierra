//go:build !darwin

package session

import (
	"errors"
	"golang.zx2c4.com/wireguard/device"
	configcore "legacywg/ConfigCore"
)

type nativeNetwork struct{}

func (*nativeNetwork) name() string { return "" }
func (*nativeNetwork) close() error { return nil }
func openNative(*configcore.Config, string) (*device.Device, *nativeNetwork, error) {
	return nil, nil, errors.New("native VPN sessions require macOS")
}
