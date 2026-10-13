package session

import (
	"bufio"
	"errors"
	"math"
	"strconv"
	"strings"
)

type PeerStatus struct {
	Index         int    `json:"index"`
	Rx            uint64 `json:"rx_bytes"`
	Tx            uint64 `json:"tx_bytes"`
	LastHandshake int64  `json:"last_handshake_unix,omitempty"`
}

// Keep the mapping in private session memory so statistics refer to profile
// order even when the engine returns peers in a different order. No public
// key, endpoint or UAPI string is returned through the public status DTO.
func peerIndices(uapi string) map[string]int {
	result := make(map[string]int)
	for _, line := range strings.Split(uapi, "\n") {
		if key, ok := strings.CutPrefix(line, "public_key="); ok {
			result[strings.Clone(key)] = len(result)
		}
	}
	return result
}

func readPeerStatistics(raw string, indices map[string]int, now int64, status *Status) error {
	failure := errors.New("cannot read validated peer statistics")
	if len(raw) > 128*1024 || len(indices) == 0 || len(indices) > 16 || now < 0 {
		return failure
	}
	peers := make([]PeerStatus, len(indices))
	for index := range peers {
		peers[index].Index = index + 1
	}
	seen := make(map[int]bool)
	current := -1
	scanner := bufio.NewScanner(strings.NewReader(raw))
	scanner.Buffer(make([]byte, 1024), 4096)
	for scanner.Scan() {
		field, value, found := strings.Cut(scanner.Text(), "=")
		if !found {
			continue
		}
		if field == "public_key" {
			index, known := indices[value]
			if !known || index < 0 || index >= len(peers) || seen[index] {
				return failure
			}
			seen[index], current = true, index
			continue
		}
		if field != "rx_bytes" && field != "tx_bytes" && field != "last_handshake_time_sec" {
			continue
		}
		if current < 0 {
			return failure
		}
		number, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return failure
		}
		switch field {
		case "rx_bytes":
			peers[current].Rx = number
		case "tx_bytes":
			peers[current].Tx = number
		case "last_handshake_time_sec":
			if number <= uint64(now) {
				peers[current].LastHandshake = int64(number)
			}
		}
	}
	if scanner.Err() != nil || len(seen) != len(indices) {
		return failure
	}
	var rx, tx uint64
	var handshake int64
	for _, peer := range peers {
		if peer.Rx > math.MaxUint64-rx || peer.Tx > math.MaxUint64-tx {
			return failure
		}
		rx += peer.Rx
		tx += peer.Tx
		if peer.LastHandshake > handshake {
			handshake = peer.LastHandshake
		}
	}
	status.Rx, status.Tx, status.LastHandshake, status.PeerDetails = rx, tx, handshake, peers
	return nil
}
