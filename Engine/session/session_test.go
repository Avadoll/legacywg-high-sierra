package session

import (
	"encoding/base64"
	configcore "legacywg/ConfigCore"
	"strings"
	"testing"
)

func splitProfile() string {
	private, public := make([]byte, 32), make([]byte, 32)
	private[0], public[0] = 1, 2
	return "[Interface]\nPrivateKey=" + base64.StdEncoding.EncodeToString(private) +
		"\nAddress=198.18.0.1/32\n[Peer]\nPublicKey=" + base64.StdEncoding.EncodeToString(public) +
		"\nEndpoint=127.0.0.1:51820\nAllowedIPs=198.18.0.2/32\n"
}

func TestUnsupportedPoliciesRefusedBeforeNativeSideEffects(t *testing.T) {
	for name, profile := range map[string]string{
		"full":          strings.Replace(splitProfile(), "198.18.0.2/32", "0.0.0.0/0", 1),
		"unrouted_dns":  strings.Replace(splitProfile(), "Address=", "DNS=1.1.1.1\nAddress=", 1),
		"ipv6":          strings.Replace(splitProfile(), "198.18.0.2/32", "::/0", 1),
		"loop":          strings.Replace(splitProfile(), "198.18.0.2/32", "127.0.0.0/8", 1),
		"ipv6_no_local": strings.Replace(splitProfile(), "198.18.0.2/32", "2001:db8:77::2/128", 1),
		"ipv6_mtu":      strings.Replace(strings.Replace(splitProfile(), "Address=198.18.0.1/32", "MTU=1200\nAddress=2001:db8:77::1/128", 1), "198.18.0.2/32", "2001:db8:77::2/128", 1),
	} {
		t.Run(name, func(t *testing.T) {
			engine := &Session{}
			if engine.Start([]byte(profile)) == nil {
				t.Fatal("unsupported policy started")
			}
			status, err := engine.Status()
			if err != nil || status.State != "Disconnected" || engine.engine != nil || engine.network != nil {
				t.Fatal("unsupported policy caused a native side effect")
			}
		})
	}
}

func TestIPv6SplitIntent(t *testing.T) {
	profile := strings.Replace(splitProfile(), "198.18.0.1/32", "2001:db8:77::1/128", 1)
	profile = strings.Replace(profile, "198.18.0.2/32", "2001:db8:77::2/128", 1)
	profile = strings.Replace(profile, "127.0.0.1:51820", "[::1]:51820", 1)
	profile = strings.Replace(profile, "Address=", "DNS=2001:db8:77::2\nAddress=", 1)
	config, err := configcore.Parse([]byte(profile))
	if err != nil {
		t.Fatal(err)
	}
	defer config.Destroy()
	endpoints, err := CheckCapabilities(config)
	if err != nil || len(endpoints) != 1 || endpoints[0].String() != "[::1]:51820" {
		t.Fatal("IPv6 split intent refused", err)
	}
}

func TestRoutedProfileDNS(t *testing.T) {
	profile := strings.Replace(splitProfile(), "Address=", "DNS=198.18.0.2\nAddress=", 1)
	config, err := configcore.Parse([]byte(profile))
	if err != nil {
		t.Fatal(err)
	}
	defer config.Destroy()
	if _, err := CheckCapabilities(config); err != nil {
		t.Fatal("routed DNS refused", err)
	}
}

func TestSupportedSplitIntent(t *testing.T) {
	config, err := configcore.Parse([]byte(splitProfile()))
	if err != nil {
		t.Fatal(err)
	}
	defer config.Destroy()
	endpoints, err := CheckCapabilities(config)
	if err != nil || len(endpoints) != 1 || endpoints[0].String() != "127.0.0.1:51820" {
		t.Fatal("valid split intent refused")
	}
}
