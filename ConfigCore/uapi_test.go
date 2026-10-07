package configcore

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"
)

func TestUAPISecretEncodingAndResolution(t *testing.T) {
	config, err := Parse([]byte(profile()))
	if err != nil {
		t.Fatal(err)
	}
	defer config.Destroy()
	var output bytes.Buffer
	endpoints := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:51820")}
	if err := config.WriteUAPI(&output, endpoints); err != nil {
		t.Fatal(err)
	}
	private, _ := base64.StdEncoding.DecodeString(testKey(1))
	if !strings.Contains(output.String(), "private_key="+hex.EncodeToString(private)) ||
		!strings.Contains(output.String(), "endpoint=192.0.2.1:51820\n") ||
		!strings.Contains(output.String(), "replace_peers=true\n") {
		t.Fatal("private UAPI differs from the validated profile")
	}
	clear(private)
	clear(output.Bytes())
}

func TestUAPIInvalidResolutionWritesNoSecret(t *testing.T) {
	config, err := Parse([]byte(profile()))
	if err != nil {
		t.Fatal(err)
	}
	defer config.Destroy()
	var output bytes.Buffer
	for _, endpoints := range [][]netip.AddrPort{nil, {{}}, {netip.MustParseAddrPort("0.0.0.0:1")}} {
		if config.WriteUAPI(&output, endpoints) == nil || output.Len() != 0 {
			t.Fatal("invalid resolved endpoint must fail before secret output")
		}
	}
}
