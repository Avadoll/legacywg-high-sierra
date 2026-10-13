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
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

// Only the real GUI sends helper requests during this interval. UDP echo
// traffic does not refresh the helper's 15-second client watchdog.
func guiModal(stack *netstack.Net, serverIP netip.Addr, executable, mode, iface string) (map[string]any, error) {
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
	if mode != "" {
		command.Args = append(command.Args, mode)
	}
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
	phase := "sheet_open"
	if mode == "--quit-cancel" || mode == "--quit-accept" {
		phase = "quit_prompt"
	}
	if !scanner.Scan() || json.Unmarshal(scanner.Bytes(), &ready) != nil || ready["status"] != "READY" || ready["phase"] != phase {
		return ready, errors.New("real GUI modal window did not open")
	}
	socket, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IP(serverIP.AsSlice()), Port: 54322})
	if err != nil {
		return nil, errors.New("modal native UDP client failed")
	}
	defer socket.Close()
	roundTrip := func() error {
		payload := []byte("LegacyWG live modal encrypted echo")
		socket.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err = socket.Write(payload); err != nil {
			return errors.New("modal encrypted send failed")
		}
		buffer := make([]byte, 256)
		size, failure := socket.Read(buffer)
		if failure != nil || !bytes.Equal(payload, buffer[:size]) {
			return errors.New("modal encrypted round trip failed")
		}
		return nil
	}
	if mode == "--crash" {
		if _, err = net.InterfaceByName(iface); err != nil {
			return nil, errors.New("active GUI crash interface missing")
		}
		if err = roundTrip(); err != nil {
			return nil, err
		}
		if command.Process.Kill() != nil {
			return nil, errors.New("controlled GUI SIGKILL failed")
		}
		err = command.Wait()
		waited = true
		status, ok := command.ProcessState.Sys().(syscall.WaitStatus)
		if err == nil || !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
			return nil, errors.New("GUI did not die from SIGKILL")
		}
		crashed := time.Now()
		time.Sleep(2 * time.Second)
		if err = roundTrip(); err != nil {
			return nil, errors.New("GUI watchdog grace traffic failed")
		}
		for time.Since(crashed) < 22*time.Second {
			interfaces, failure := net.Interfaces()
			if failure != nil {
				return nil, errors.New("cannot inspect GUI crash cleanup interfaces")
			}
			found := false
			for _, item := range interfaces {
				if item.Name == iface {
					found = true
				}
			}
			if !found {
				elapsed := time.Since(crashed)
				if elapsed < 12*time.Second {
					return nil, errors.New("interface vanished before expected watchdog grace")
				}
				return map[string]any{"status": "PASS", "kind": "native-real-gui-sigkill-watchdog",
					"actual_sigkill": "PASS", "active_interface_removed": "PASS", "watchdog_grace_encrypted_echo": "PASS",
					"cleanup_after_sigkill_ms": elapsed.Milliseconds(), "helper_requests_after_sigkill": 0,
					"high_sierra": "NOT_RUN", "immediate_fail_closed": "NOT_IMPLEMENTED"}, nil
			}
			time.Sleep(100 * time.Millisecond)
		}
		return nil, errors.New("helper did not remove tunnel after GUI heartbeat loss")
	}
	when := []time.Duration{0, 9 * time.Second, 17 * time.Second, 21 * time.Second}
	if mode == "--quit-cancel" {
		when = when[:3]
	}
	if mode == "--quit-accept" {
		when = when[:1]
	}
	began := time.Now()
	for _, delay := range when {
		if remaining := time.Until(began.Add(delay)); remaining > 0 {
			select {
			case <-time.After(remaining):
			case <-ctx.Done():
				return nil, errors.New("modal traffic deadline")
			}
		}
		if err = roundTrip(); err != nil {
			return nil, err
		}
	}
	var report map[string]any
	if !scanner.Scan() || json.Unmarshal(scanner.Bytes(), &report) != nil || report["status"] != "PASS" {
		return report, errors.New("real GUI modal heartbeat proof failed")
	}
	if scanner.Scan() || scanner.Err() != nil {
		return nil, errors.New("unexpected modal GUI output")
	}
	err = command.Wait()
	waited = true
	if err != nil {
		return nil, errors.New("modal GUI exit failed")
	}
	if mode == "" {
		report["encrypted_echo_during_sheet_and_hidden_window"] = "PASS"
	} else {
		report["encrypted_echo_during_quit_confirmation"] = "PASS"
	}
	report["encrypted_round_trips"] = len(when)
	report["helper_requests_from_test_during_modal"] = 0
	if mode == "" {
		report["helper_requests_from_test_during_sheet"] = 0
	}
	return report, nil
}
