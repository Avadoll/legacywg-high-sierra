package configcore

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// These deterministic values are parser fixtures, never network credentials.
func testKey(value byte) string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Repeat(string([]byte{value}), 32)))
}

func profile() string {
	return "[Interface]\nPrivateKey = " + testKey(1) + "\nAddress = 10.7.0.2/24\nDNS = 10.7.0.1\n" +
		"[Peer]\nPublicKey = " + testKey(2) + "\nEndpoint = vpn.example.test:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n"
}

func TestSupportedProfiles(t *testing.T) {
	for name, text := range map[string]string{
		"IPv4":              profile(),
		"BOM CRLF comments": "\ufeff# comment\r\n" + strings.ReplaceAll(profile(), "\n", "\r\n") + "\r\n",
		"dual stack":        strings.ReplaceAll(strings.ReplaceAll(profile(), "10.7.0.2/24", "10.7.0.2/24, fd00::2/64"), "0.0.0.0/0", "0.0.0.0/0, ::/0"),
		"IPv6 endpoint":     strings.ReplaceAll(profile(), "vpn.example.test:51820", "[2001:db8::1]:51820"),
		"split":             strings.ReplaceAll(profile(), "0.0.0.0/0", "10.20.0.7/24, 192.168.5.0/24"),
		"PSK":               strings.ReplaceAll(profile(), "[Peer]", "[Peer]\nPresharedKey = "+testKey(3)),
		"multiple peers":    strings.ReplaceAll(profile(), "0.0.0.0/0", "10.20.0.0/24") + "[Peer]\nPublicKey = " + testKey(4) + "\nAllowedIPs = 10.21.0.0/24\n",
	} {
		t.Run(name, func(t *testing.T) {
			config, err := Parse([]byte(text))
			if err != nil || config == nil {
				t.Fatalf("valid fixture rejected: %v", err)
			}
		})
	}
	config, _ := Parse([]byte(strings.ReplaceAll(profile(), "0.0.0.0/0", "10.20.0.7/24")))
	if config.Peers[0].AllowedIPs[0].String() != "10.20.0.0/24" {
		t.Fatal("routing prefix not normalized")
	}
	if config.Addresses[0].String() != "10.7.0.2/24" {
		t.Fatal("interface address lost its host bits")
	}
}

func TestRejectUnsafeOrUnsupportedProfiles(t *testing.T) {
	cases := map[string]string{
		"missing Interface":    "[Peer]\nPublicKey = " + testKey(2),
		"missing key":          strings.ReplaceAll(profile(), "PrivateKey = "+testKey(1)+"\n", ""),
		"invalid key":          strings.ReplaceAll(profile(), testKey(1), "TOP_SECRET_INVALID_KEY"),
		"short key":            strings.ReplaceAll(profile(), testKey(1), "AQ=="),
		"zero key":             strings.ReplaceAll(profile(), testKey(1), testKey(0)),
		"duplicate scalar":     strings.ReplaceAll(profile(), "[Peer]", "MTU = 1400\nMTU = 1401\n[Peer]"),
		"unknown field":        profile() + "Unexpected = value\n",
		"AmneziaWG":            strings.ReplaceAll(profile(), "[Peer]", "Jc = 4\n[Peer]"),
		"hook":                 strings.ReplaceAll(profile(), "[Peer]", "PostUp = touch /tmp/pwned\n[Peer]"),
		"Table":                strings.ReplaceAll(profile(), "[Peer]", "Table = off\n[Peer]"),
		"bad CIDR":             strings.ReplaceAll(profile(), "0.0.0.0/0", "0.0.0.0/33"),
		"duplicate CIDR":       strings.ReplaceAll(profile(), "0.0.0.0/0", "10.0.0.0/8, 10.1.2.3/8"),
		"DNS search domain":    strings.ReplaceAll(profile(), "DNS = 10.7.0.1", "DNS = example.test"),
		"shell endpoint":       strings.ReplaceAll(profile(), "vpn.example.test:51820", "$(whoami):51820"),
		"traversal endpoint":   strings.ReplaceAll(profile(), "vpn.example.test:51820", "../../tmp:51820"),
		"URL endpoint":         strings.ReplaceAll(profile(), "vpn.example.test:51820", "https://example.test:51820"),
		"IPv6 no brackets":     strings.ReplaceAll(profile(), "vpn.example.test:51820", "2001:db8::1:51820"),
		"invalid numeric host": strings.ReplaceAll(profile(), "vpn.example.test:51820", "999.999.1.1:51820"),
		"port zero":            strings.ReplaceAll(profile(), ":51820", ":0"),
		"port overflow":        strings.ReplaceAll(profile(), ":51820", ":65536"),
		"NUL":                  profile() + "\x00",
		"bidi control":         profile() + "\u202e",
		"invalid UTF8":         profile() + "\xff",
		"mapped IPv6":          strings.ReplaceAll(profile(), "0.0.0.0/0", "::ffff:192.0.2.0/120"),
		"IPv6 MTU":             strings.ReplaceAll(strings.ReplaceAll(profile(), "10.7.0.2/24", "fd00::2/64"), "[Peer]", "MTU = 1200\n[Peer]"),
		"oversized":            strings.Repeat(" ", MaxFileBytes+1),
		"overlapping peers":    profile() + "[Peer]\nPublicKey = " + testKey(4) + "\nAllowedIPs = 10.0.0.0/8\n",
		"duplicate peer key":   strings.ReplaceAll(profile(), "0.0.0.0/0", "10.0.0.0/8") + "[Peer]\nPublicKey = " + testKey(2) + "\nAllowedIPs = 192.168.0.0/16\n",
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			config, err := Parse([]byte(text))
			if err == nil || config != nil {
				t.Fatal("invalid fixture accepted")
			}
			if strings.Contains(err.Error(), "TOP_SECRET") || strings.Contains(err.Error(), testKey(1)) {
				t.Fatal("error leaked secret")
			}
		})
	}
}

func TestResourceLimits(t *testing.T) {
	boundary := profile() + "#" + strings.Repeat(" ", MaxFileBytes-len(profile())-1)
	if _, err := Parse([]byte(boundary)); err != nil {
		t.Fatal("size boundary rejected", err)
	}
	if _, err := Parse([]byte(boundary + " ")); err == nil {
		t.Fatal("size limit bypassed")
	}
	text := strings.ReplaceAll(profile(), "0.0.0.0/0", "10.0.0.1/32")
	for i := 1; i < MaxPeers; i++ {
		text += "[Peer]\nPublicKey = " + testKey(byte(i+3)) + fmt.Sprintf("\nAllowedIPs = 10.0.%d.1/32\n", i)
	}
	if _, err := Parse([]byte(text)); err != nil {
		t.Fatal("peer boundary rejected", err)
	}
	if _, err := Parse([]byte(text + "[Peer]\n")); err == nil {
		t.Fatal("peer limit bypassed")
	}
	items := make([]string, MaxCIDRs-1)
	for i := range items {
		items[i] = fmt.Sprintf("10.%d.%d.1/32", i/256, i%256)
	}
	text = strings.ReplaceAll(profile(), "0.0.0.0/0", strings.Join(items, ","))
	if _, err := Parse([]byte(text)); err != nil {
		t.Fatal("CIDR boundary rejected", err)
	}
	if _, err := Parse([]byte(strings.ReplaceAll(text, "PersistentKeepalive", "AllowedIPs = 192.0.2.1/32\nPersistentKeepalive"))); err == nil {
		t.Fatal("duplicate AllowedIPs accepted")
	}
	if _, err := Parse([]byte(strings.ReplaceAll(text, items[len(items)-1], items[len(items)-1]+",192.0.2.1/32"))); err == nil {
		t.Fatal("CIDR limit bypassed")
	}
}

func TestSecretFormatting(t *testing.T) {
	config, err := Parse([]byte(strings.ReplaceAll(profile(), "[Peer]", "[Peer]\nPresharedKey = "+testKey(3))))
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%x", "%X", "%q", "%d"} {
		text := fmt.Sprintf(format, config.PrivateKey)
		if text != "[REDACTED]" {
			t.Fatal("unsafe key formatter", format)
		}
	}
	data, err := json.Marshal(config)
	if err != nil || strings.Contains(string(data), testKey(1)) || strings.Contains(string(data), testKey(3)) {
		t.Fatal("JSON leaked secret")
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(profile()))
	f.Add([]byte("[Interface]\nPostUp = rm -rf /\n"))
	f.Add([]byte("\xff\x00"))
	f.Fuzz(func(t *testing.T, input []byte) {
		config, err := Parse(input)
		if err == nil {
			if config == nil || len(config.Peers) == 0 || len(config.Peers) > MaxPeers {
				t.Fatal("invalid successful parse")
			}
		} else if config != nil {
			t.Fatal("partial config exposed on error")
		}
	})
}
