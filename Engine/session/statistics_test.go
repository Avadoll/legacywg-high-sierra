package session

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPeerStatisticsOrderPrivacyAndQuietHandshake(t *testing.T) {
	indices := peerIndices("private_key=private-marker\npublic_key=first-key\npublic_key=second-key\n")
	raw := "private_key=private-marker\npublic_key=second-key\nendpoint=private-endpoint\npreshared_key=private-psk\nrx_bytes=31\ntx_bytes=17\nlast_handshake_time_sec=0\npublic_key=first-key\nrx_bytes=7\ntx_bytes=13\nlast_handshake_time_sec=100\n"
	status := Status{}
	if err := readPeerStatistics(raw, indices, 10000, &status); err != nil {
		t.Fatal(err)
	}
	if status.Rx != 38 || status.Tx != 30 || status.LastHandshake != 100 || len(status.PeerDetails) != 2 || status.PeerDetails[0].LastHandshake != 100 || status.PeerDetails[1].Rx != 31 || status.PeerDetails[0].Index != 1 {
		t.Fatal("peer order, totals or quiet handshake lost")
	}
	encoded, _ := json.Marshal(status)
	for _, marker := range []string{"private-", "first-key", "second-key", "public_key", "endpoint", "preshared"} {
		if strings.Contains(string(encoded), marker) {
			t.Fatal("status leaked private metadata")
		}
	}
}

func TestPeerStatisticsRejectsUntrustworthyResults(t *testing.T) {
	for _, raw := range []string{
		"rx_bytes=1\npublic_key=first\n",
		"public_key=foreign\n",
		"public_key=first\npublic_key=first\n",
		"public_key=first\nrx_bytes=-1\n",
		"public_key=first\nrx_bytes=18446744073709551615\npublic_key=second\nrx_bytes=1\n",
		"public_key=first\n" + strings.Repeat("x", 4097),
	} {
		status := Status{}
		if readPeerStatistics(raw, map[string]int{"first": 0, "second": 1}, 100, &status) == nil || len(status.PeerDetails) != 0 {
			t.Fatal("incomplete/malformed/foreign stats accepted")
		}
	}
}

func TestFutureHandshakeIsNotEvidence(t *testing.T) {
	status := Status{}
	if readPeerStatistics("public_key=first\nlast_handshake_time_sec=101\n", map[string]int{"first": 0}, 100, &status) != nil || status.LastHandshake != 0 {
		t.Fatal("future handshake accepted")
	}
}
