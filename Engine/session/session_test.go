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
		"full":     strings.Replace(splitProfile(), "198.18.0.2/32", "0.0.0.0/0", 1),
		"dns":      strings.Replace(splitProfile(), "Address=", "DNS=1.1.1.1\nAddress=", 1),
		"hostname": strings.Replace(splitProfile(), "127.0.0.1", "example.com", 1),
		"ipv6":     strings.Replace(splitProfile(), "198.18.0.2/32", "::/0", 1),
		"loop":     strings.Replace(splitProfile(), "198.18.0.2/32", "127.0.0.0/8", 1),
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
