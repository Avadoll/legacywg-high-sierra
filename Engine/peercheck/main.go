// peercheck is a developer-only end-to-end test; it is never in the app bundle.
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	configcore "legacywg/ConfigCore"
)

func keypair() (string, string, error) {
	var private [32]byte
	if _, err := rand.Read(private[:]); err != nil {
		return "", "", errors.New("ephemeral test key generation failed")
	}
	defer clear(private[:])
	public, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		return "", "", errors.New("official X25519 public key derivation failed")
	}
	return base64.StdEncoding.EncodeToString(private[:]), base64.StdEncoding.EncodeToString(public), nil
}

func call(client, requirement, op, profile string) (map[string]any, error) {
	command := exec.Command(client, requirement, op)
	if profile != "" {
		command.Stdin = strings.NewReader(profile)
	}
	data, err := command.Output()
	if err != nil {
		return nil, errors.New("authenticated helper test request failed")
	}
	var reply map[string]any
	if json.Unmarshal(data, &reply) != nil || reply["ok"] != true {
		return nil, errors.New("helper test operation refused")
	}
	return reply, nil
}

func check(client, requirement string, crashParent bool) error {
	serverIP := netip.MustParseAddr("198.18.0.2")
	clientIP := netip.MustParseAddr("198.18.0.1")
	clientPrivate, clientPublic, err := keypair()
	if err != nil {
		return err
	}
	serverPrivate, serverPublic, err := keypair()
	if err != nil {
		return err
	}
	tunnel, stack, err := netstack.CreateNetTUN([]netip.Addr{serverIP}, nil, 1420)
	if err != nil {
		return errors.New("test server network stack creation failed")
	}
	server := device.NewDevice(tunnel, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer server.Close()
	profile := fmt.Sprintf("[Interface]\nPrivateKey=%s\nAddress=%s/32\n[Peer]\nPublicKey=%s\nAllowedIPs=%s/32\n", serverPrivate, serverIP, clientPublic, clientIP)
	config, err := configcore.Parse([]byte(profile))
	if err != nil {
		return errors.New("test server profile validation failed")
	}
	defer config.Destroy()
	var buffer bytes.Buffer
	if config.WriteUAPI(&buffer, []netip.AddrPort{{}}) != nil || server.IpcSet(buffer.String()) != nil {
		return errors.New("official test server UAPI setup failed")
	}
	clear(buffer.Bytes())
	if server.Up() != nil {
		return errors.New("test server UDP bind failed")
	}
	uapi, err := server.IpcGet()
	if err != nil {
		return errors.New("test server statistics failed")
	}
	port := 0
	for _, line := range strings.Split(uapi, "\n") {
		if strings.HasPrefix(line, "listen_port=") {
			port, _ = strconv.Atoi(strings.TrimPrefix(line, "listen_port="))
		}
	}
	if port < 1 || port > 65535 {
		return errors.New("test server port missing")
	}
	echo, err := stack.ListenUDPAddrPort(netip.AddrPortFrom(serverIP, 54321))
	if err != nil {
		return errors.New("test echo server failed")
	}
	defer echo.Close()
	echo.SetDeadline(time.Now().Add(12 * time.Second))
	echoResult := make(chan error, 1)
	go func() {
		payload := make([]byte, 256)
		size, remote, err := echo.ReadFrom(payload)
		if err == nil {
			_, err = echo.WriteTo(payload[:size], remote)
		}
		echoResult <- err
	}()
	profile = fmt.Sprintf("[Interface]\nPrivateKey=%s\nAddress=%s/32\n[Peer]\nPublicKey=%s\nEndpoint=127.0.0.1:%d\nAllowedIPs=%s/32\nPersistentKeepalive=1\n", clientPrivate, clientIP, serverPublic, port, serverIP)
	if _, err = call(client, requirement, "start", profile); err != nil {
		return err
	}
	stopped := false
	defer func() {
		if !stopped {
			call(client, requirement, "stop", "")
		}
	}()
	socket, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IP(serverIP.AsSlice()), Port: 54321})
	if err != nil {
		return errors.New("native client UDP socket failed")
	}
	defer socket.Close()
	socket.SetDeadline(time.Now().Add(10 * time.Second))
	payload := []byte("LegacyWG encrypted loopback payload")
	if _, err = socket.Write(payload); err != nil {
		return errors.New("native tunnel send failed")
	}
	received := make([]byte, 256)
	size, err := socket.Read(received)
	if err != nil || !bytes.Equal(payload, received[:size]) {
		return errors.New("encrypted tunnel round trip failed")
	}
	if <-echoResult != nil {
		return errors.New("decrypted echo response failed")
	}
	reply, err := call(client, requirement, "status", "")
	if err != nil {
		return err
	}
	status, ok := reply["status"].(map[string]any)
	if !ok || status["state"] != "Connected" || status["rx_bytes"].(float64) <= 0 || status["tx_bytes"].(float64) <= 0 {
		return errors.New("actual handshake and traffic statistics missing")
	}
	iface, _ := status["interface"].(string)
	if crashParent {
		if exec.Command("/usr/bin/sudo", "-n", "/bin/launchctl", "kill", "SIGKILL", "system/org.legacywg.helper").Run() != nil {
			return errors.New("CI helper crash injection failed")
		}
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			if _, err = net.InterfaceByName(iface); err != nil {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
	} else if _, err = call(client, requirement, "stop", ""); err != nil {
		return err
	}
	stopped = true
	reply, err = call(client, requirement, "status", "")
	if err != nil {
		return err
	}
	status, ok = reply["status"].(map[string]any)
	if !ok || status["state"] != "Disconnected" {
		return errors.New("disconnect state failed")
	}
	if _, err = net.InterfaceByName(iface); err == nil {
		return errors.New("native interface still exists after disconnect")
	}
	return nil
}

func main() {
	if len(os.Args) != 3 {
		os.Exit(2)
	}
	started := time.Now()
	for cycle := 0; cycle < 21; cycle++ {
		if err := check(os.Args[1], os.Args[2], cycle == 20); err != nil {
			json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "FAIL", "cycle": cycle + 1, "reason": err.Error()})
			os.Exit(1)
		}
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "PASS", "kind": "authenticated-helper-native-utun-encrypted-loopback",
		"connect_disconnect_cycles": 20, "helper_crash_cleanup": "PASS", "elapsed_ms": time.Since(started).Milliseconds(),
		"external_server": "NOT_RUN", "high_sierra": "NOT_RUN"})
}
