package main

import (
	"errors"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"os"
	"time"
)

func probe() error {
	if os.Geteuid() != 0 {
		return errors.New("developer probe requires administrator privileges on the authorized test Mac")
	}
	// No addresses, system routes, DNS, PF rules, profiles or keys are changed.
	tunDevice, err := tun.CreateTUN("utun", 1420)
	if err != nil {
		return errors.New("native utun creation failed")
	}
	engine := device.NewDevice(tunDevice, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer engine.Close()
	if err := engine.IpcSet("listen_port=0\nreplace_peers=true\n"); err != nil {
		return errors.New("engine UAPI set failed")
	}
	if err := engine.Up(); err != nil {
		return errors.New("native UDP bind failed")
	}
	if _, err := engine.IpcGet(); err != nil {
		return errors.New("engine UAPI get failed")
	}
	// A short dwell exercises event handling and teardown, not connectivity.
	time.Sleep(100 * time.Millisecond)
	if err := engine.Down(); err != nil {
		return errors.New("engine shutdown failed")
	}
	return nil
}
