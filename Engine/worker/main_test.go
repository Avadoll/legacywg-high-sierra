package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"legacywg/Engine/session"
	"strings"
	"testing"
)

func fixtureKey(value byte) string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Repeat(string([]byte{value}), 32)))
}

func TestPrivateValidationPreviewWithoutKeysOrNetwork(t *testing.T) {
	private, public, psk := fixtureKey(1), fixtureKey(2), fixtureKey(3)
	text := "[Interface]\nPrivateKey = " + private + "\nAddress = 10.7.0.2/24, fd00:7::2/64\n[Peer]\nPublicKey = " + public + "\nPresharedKey = " + psk + "\nEndpoint = no-resolution.example.invalid:51820\nAllowedIPs = 10.20.0.0/24, fd00:20::/64\n"
	engine := &session.Session{}
	message, _ := json.Marshal(request{Version: 1, Op: "validate", Profile: text})
	result := handle(engine, message).(map[string]any)
	data, err := json.Marshal(result)
	if err != nil || result["ok"] != true || result["native_supported"] != true {
		t.Fatal("valid preview refused")
	}
	for _, key := range []string{private, public, psk, "PrivateKey", "PublicKey", "PresharedKey"} {
		if strings.Contains(string(data), key) {
			t.Fatal("validation preview exposed a key")
		}
	}
	view := result["preview"].(profilePreview)
	if view.Routing != "split" || view.RouteCount != 2 || view.AddressCount != 2 || view.Addresses[0] != "10.7.0.2/24" || view.Addresses[1] != "fd00:7::2/64" || view.Endpoints[0] != "no-resolution.example.invalid:51820" {
		t.Fatal("selected profile metadata differs from validated config")
	}
	status, err := engine.Status()
	if err != nil || status.TunnelStarted || status.State != "Disconnected" {
		t.Fatal("preview changed the session")
	}
	// The same coverage algorithm must recognise equivalent fragmented defaults.
	text = strings.Replace(text, "10.20.0.0/24, fd00:20::/64", "0.0.0.0/1, 128.0.0.0/1, ::/0", 1)
	message, _ = json.Marshal(request{Version: 1, Op: "validate", Profile: text})
	result = handle(engine, message).(map[string]any)
	if result["ok"] != true || result["native_supported"] != false || result["preview"].(profilePreview).Routing != "full_dual_stack" {
		t.Fatal("full route preview falsely classified as split")
	}
}

func TestValidationPreviewBoundedForLargeProfile(t *testing.T) {
	addresses := make([]string, 1024)
	for index := range addresses {
		addresses[index] = fmt.Sprintf("10.100.%d.%d/32", index/256, index%256)
	}
	host := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	text := "[Interface]\nPrivateKey = " + fixtureKey(1) + "\nAddress = " + strings.Join(addresses, ",") + "\n"
	for index := 0; index < 16; index++ {
		text += fmt.Sprintf("[Peer]\nPublicKey = %s\nEndpoint = %s:51820\nAllowedIPs = 10.20.0.%d/32\n", fixtureKey(byte(index+2)), host, index)
	}
	message, _ := json.Marshal(request{Version: 1, Op: "validate", Profile: text})
	result := handle(&session.Session{}, message).(map[string]any)
	if result["ok"] != true {
		t.Fatal("large valid fixture refused")
	}
	data, _ := json.Marshal(result)
	view := result["preview"].(profilePreview)
	if len(data) > 8192 || len(view.Addresses) != 8 || view.AddressCount != 1024 || len(view.Endpoints) != 16 || view.RouteCount != 16 {
		t.Fatal("preview limit or counts incorrect")
	}
}

func TestPrivateProtocolRejectsUnknownAndTrailingData(t *testing.T) {
	for _, message := range []string{`{"version":1,"op":"status","command":"/bin/sh"}`,
		`{"version":1,"op":"status"} {}`, `{"version":2,"op":"status"}`,
		`{"version":1,"op":"status","profile":"secret marker"}`} {
		result := handle(&session.Session{}, []byte(message))
		encoded, err := json.Marshal(result)
		if err != nil || !strings.Contains(string(encoded), `"ok":false`) || strings.Contains(string(encoded), "secret marker") {
			t.Fatal("invalid private protocol accepted or echoed sensitive input")
		}
	}
}

func TestRecoveryProtocolRejectsCallerSuppliedUndo(t *testing.T) {
	for _, message := range []string{
		`{"version":1,"op":"recover","path":"private-marker"}`,
		`{"version":1,"op":"recover","profile":"private-marker"}`,
		`{"version":1,"op":"recover","command":"private-marker"}`,
	} {
		data, err := json.Marshal(handle(&session.Session{}, []byte(message)))
		if err != nil || !strings.Contains(string(data), `"ok":false`) || strings.Contains(string(data), "private-marker") {
			t.Fatal("caller supplied recovery data accepted or echoed")
		}
	}
}
