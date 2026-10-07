// Package configcore validates standard WireGuard profiles without side effects.
package configcore

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	MaxFileBytes = 256 * 1024
	MaxPeers     = 16
	MaxCIDRs     = 2048
)

// Key has no public formatting or JSON representation containing its value.
type Key struct{ value [32]byte }

func (Key) String() string                    { return "[REDACTED]" }
func (Key) GoString() string                  { return "[REDACTED]" }
func (Key) MarshalJSON() ([]byte, error)      { return []byte(`"[REDACTED]"`), nil }
func (Key) Format(state fmt.State, verb rune) { _, _ = state.Write([]byte("[REDACTED]")) }

type Endpoint struct {
	Host string
	Port uint16
}

type Peer struct {
	PublicKey           Key
	PresharedKey        *Key
	Endpoint            *Endpoint
	AllowedIPs          []netip.Prefix
	PersistentKeepalive uint16
}

type Config struct {
	PrivateKey Key
	Addresses  []netip.Prefix
	DNS        []netip.Addr
	MTU        uint16
	ListenPort uint16
	Peers      []Peer
}

// ParseError contains only a line and a fixed reason, never profile contents.
type ParseError struct {
	Line   int
	Reason string
}

func (e *ParseError) Error() string         { return fmt.Sprintf("line %d: %s", e.Line, e.Reason) }
func failure(line int, reason string) error { return &ParseError{line, reason} }

func parseKey(value string) (Key, bool) {
	var key Key
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != len(key.value) || base64.StdEncoding.EncodeToString(decoded) != value {
		return key, false
	}
	copy(key.value[:], decoded)
	clear(decoded)
	return key, true
}

func number(value string, minimum, maximum int) (uint16, bool) {
	if value == "" {
		return 0, false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(value)
	return uint16(n), err == nil && n >= minimum && n <= maximum
}

func list(value string) ([]string, bool) {
	items := strings.Split(value, ",")
	for i := range items {
		items[i] = strings.TrimSpace(items[i])
		if items[i] == "" {
			return nil, false
		}
	}
	return items, true
}

func prefixes(value string, addresses bool) ([]netip.Prefix, bool) {
	items, ok := list(value)
	if !ok || len(items) > MaxCIDRs {
		return nil, false
	}
	result := make([]netip.Prefix, 0, len(items))
	seen := map[netip.Prefix]bool{}
	for _, item := range items {
		prefix, err := netip.ParsePrefix(item)
		if err != nil || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
			return nil, false
		}
		if addresses {
			if prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() {
				return nil, false
			}
		} else {
			prefix = prefix.Masked()
		}
		if seen[prefix] {
			return nil, false
		}
		seen[prefix] = true
		result = append(result, prefix)
	}
	return result, true
}

func endpoint(value string) (*Endpoint, bool) {
	host, portText, err := net.SplitHostPort(value)
	if err != nil || host == "" {
		return nil, false
	}
	port, ok := number(portText, 1, 65535)
	if !ok {
		return nil, false
	}
	if address, err := netip.ParseAddr(host); err == nil {
		if address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() || address.Is4In6() {
			return nil, false
		}
		if address.Is6() != strings.HasPrefix(value, "[") {
			return nil, false
		}
		host = address.String()
	} else {
		if strings.HasPrefix(value, "[") || len(host) > 253 {
			return nil, false
		}
		candidate := strings.TrimSuffix(host, ".")
		if candidate == "" {
			return nil, false
		}
		allNumeric := true
		for _, label := range strings.Split(candidate, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return nil, false
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
					return nil, false
				}
				if c < '0' || c > '9' {
					allNumeric = false
				}
			}
		}
		if allNumeric {
			return nil, false
		}
		host = strings.ToLower(host)
	}
	return &Endpoint{Host: host, Port: port}, true
}

// Parse accepts a restricted, documented wg-quick file syntax. It does not
// resolve DNS, open sockets, write files, or install privileged components.
func Parse(data []byte) (*Config, error) {
	if len(data) > MaxFileBytes {
		return nil, failure(0, "profile exceeds size limit")
	}
	if !utf8.Valid(data) {
		return nil, failure(0, "profile must be UTF-8")
	}
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
	for _, c := range string(data) {
		if (unicode.IsControl(c) && c != '\n' && c != '\r' && c != '\t') || c == '\ufeff' || unicode.Is(unicode.Cf, c) {
			return nil, failure(0, "profile contains forbidden control characters")
		}
	}
	config := &Config{}
	section := ""
	interfaceSeen := false
	privateKeySeen := false
	seen := map[string]bool{}
	peerSeen := []map[string]bool{}
	line := 0
	cidrCount := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 1024), MaxFileBytes+1)
	for scanner.Scan() {
		line++
		text := scanner.Text()
		if index := strings.IndexByte(text, '#'); index >= 0 {
			text = text[:index]
		}
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		if strings.HasPrefix(text, "[") {
			switch text {
			case "[Interface]":
				if interfaceSeen || len(config.Peers) != 0 {
					return nil, failure(line, "duplicate or misplaced Interface section")
				}
				interfaceSeen = true
				section = "Interface"
				seen = map[string]bool{}
			case "[Peer]":
				if !interfaceSeen {
					return nil, failure(line, "Peer precedes Interface")
				}
				if len(config.Peers) >= MaxPeers {
					return nil, failure(line, "peer limit exceeded")
				}
				config.Peers = append(config.Peers, Peer{})
				section = "Peer"
				seen = map[string]bool{}
				peerSeen = append(peerSeen, seen)
			default:
				return nil, failure(line, "unsupported or malformed section")
			}
			continue
		}
		if section == "" {
			return nil, failure(line, "field outside section")
		}
		field, value, found := strings.Cut(text, "=")
		field, value = strings.TrimSpace(field), strings.TrimSpace(value)
		if !found || value == "" {
			return nil, failure(line, "malformed field")
		}
		if seen[field] {
			return nil, failure(line, "duplicate field")
		}
		seen[field] = true
		valid := true
		if section == "Interface" {
			switch field {
			case "PrivateKey":
				config.PrivateKey, valid = parseKey(value)
				privateKeySeen = true
			case "Address":
				config.Addresses, valid = prefixes(value, true)
				cidrCount += len(config.Addresses)
				if cidrCount > MaxCIDRs {
					return nil, failure(line, "CIDR limit exceeded")
				}
			case "DNS":
				var items []string
				items, valid = list(value)
				if len(items) > 16 {
					valid = false
				}
				seenDNS := map[netip.Addr]bool{}
				for _, item := range items {
					address, err := netip.ParseAddr(item)
					if err != nil || address.Zone() != "" || address.Is4In6() || address.IsUnspecified() || address.IsMulticast() || seenDNS[address] {
						valid = false
						break
					}
					seenDNS[address] = true
					config.DNS = append(config.DNS, address)
				}
			case "MTU":
				config.MTU, valid = number(value, 576, 9000)
			case "ListenPort":
				config.ListenPort, valid = number(value, 0, 65535)
			default:
				return nil, failure(line, "unsupported Interface field; standard WireGuard configuration required")
			}
		} else {
			peer := &config.Peers[len(config.Peers)-1]
			switch field {
			case "PublicKey":
				peer.PublicKey, valid = parseKey(value)
			case "PresharedKey":
				var key Key
				key, valid = parseKey(value)
				peer.PresharedKey = &key
			case "Endpoint":
				peer.Endpoint, valid = endpoint(value)
			case "AllowedIPs":
				peer.AllowedIPs, valid = prefixes(value, false)
				cidrCount += len(peer.AllowedIPs)
				if cidrCount > MaxCIDRs {
					return nil, failure(line, "CIDR limit exceeded")
				}
			case "PersistentKeepalive":
				peer.PersistentKeepalive, valid = number(value, 0, 65535)
			default:
				return nil, failure(line, "unsupported Peer field; standard WireGuard configuration required")
			}
		}
		if !valid {
			return nil, failure(line, "invalid field value")
		}
	}
	if scanner.Err() != nil {
		return nil, failure(line, "cannot read profile")
	}
	if !interfaceSeen || len(config.Addresses) == 0 {
		return nil, failure(0, "Interface Address is required")
	}
	if !privateKeySeen || config.PrivateKey.value == [32]byte{} {
		return nil, failure(0, "nonzero PrivateKey is required")
	}
	if len(config.Peers) == 0 {
		return nil, failure(0, "at least one Peer is required")
	}
	for _, address := range config.Addresses {
		if address.Addr().Is6() && config.MTU != 0 && config.MTU < 1280 {
			return nil, failure(0, "IPv6 requires MTU of at least 1280")
		}
	}
	publicKeys := map[Key]bool{}
	for i, peer := range config.Peers {
		if !peerSeen[i]["PublicKey"] || peer.PublicKey.value == [32]byte{} || len(peer.AllowedIPs) == 0 {
			return nil, failure(0, "Peer requires a nonzero PublicKey and AllowedIPs")
		}
		if publicKeys[peer.PublicKey] {
			return nil, failure(0, "duplicate peer PublicKey")
		}
		publicKeys[peer.PublicKey] = true
		for _, prefix := range peer.AllowedIPs {
			for j := 0; j < i; j++ {
				for _, previous := range config.Peers[j].AllowedIPs {
					if prefix.Overlaps(previous) {
						return nil, failure(0, "overlapping AllowedIPs across peers")
					}
				}
			}
		}
	}
	return config, nil
}
