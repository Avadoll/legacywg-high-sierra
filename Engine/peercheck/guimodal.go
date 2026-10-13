package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os/exec"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

// Only the real GUI sends helper requests during this interval. UDP echo
// traffic does not refresh the helper's 15-second client watchdog.
func guiModal(stack *netstack.Net, serverIP netip.Addr, executable string) (map[string]any, error) {
	echo, err := stack.ListenUDPAddrPort(netip.AddrPortFrom(serverIP, 54322))
	if err != nil {
		return nil, errors.New("modal echo listener failed")
	}
	defer echo.Close()
	go func() {
		buffer := make([]byte, 256)
		for {
			size, remote, failure := echo.ReadFrom(buffer)
			if failure != nil {
				return
			}
			if _, failure = echo.WriteTo(buffer[:size], remote); failure != nil {
				return
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable)
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, errors.New("modal GUI output unavailable")
	}
	if command.Start() != nil {
		return nil, errors.New("modal GUI launch failed")
	}
	waited := false
	defer func() {
		if !waited {
			cancel()
			command.Wait()
		}
	}()
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 4096), 8192)
	var ready map[string]any
	if !scanner.Scan() || json.Unmarshal(scanner.Bytes(), &ready) != nil || ready["status"] != "READY" || ready["phase"] != "sheet_open" {
		return nil, errors.New("real GUI license sheet did not open")
	}
	socket, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IP(serverIP.AsSlice()), Port: 54322})
	if err != nil {
		return nil, errors.New("modal native UDP client failed")
	}
	defer socket.Close()
	began := time.Now()
	for _, delay := range []time.Duration{0, 9 * time.Second, 17 * time.Second, 21 * time.Second} {
		if remaining := time.Until(began.Add(delay)); remaining > 0 {
			select {
			case <-time.After(remaining):
			case <-ctx.Done():
				return nil, errors.New("modal traffic deadline")
			}
		}
		payload := []byte("LegacyWG live modal encrypted echo")
		socket.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err = socket.Write(payload); err != nil {
			return nil, errors.New("modal encrypted send failed")
		}
		buffer := make([]byte, 256)
		size, failure := socket.Read(buffer)
		if failure != nil || !bytes.Equal(payload, buffer[:size]) {
			return nil, errors.New("modal encrypted round trip failed")
		}
	}
	var report map[string]any
	if !scanner.Scan() || json.Unmarshal(scanner.Bytes(), &report) != nil || report["status"] != "PASS" {
		return nil, errors.New("real GUI modal heartbeat proof failed")
	}
	if scanner.Scan() || scanner.Err() != nil {
		return nil, errors.New("unexpected modal GUI output")
	}
	err = command.Wait()
	waited = true
	if err != nil {
		return nil, errors.New("modal GUI exit failed")
	}
	report["encrypted_echo_during_sheet_and_hidden_window"] = "PASS"
	report["encrypted_round_trips"] = 4
	report["helper_requests_from_test_during_sheet"] = 0
	return report, nil
}
