package recoverycore

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type pfInterface struct {
	name  string
	index int
}

type pfUDPEscape struct {
	path       pfInterface
	source     netip.Addr
	endpoint   netip.AddrPort
	sourcePort uint16
}

// Internal typed policy. No raw rules/macros/tables/paths/hostnames/hooks are
// accepted. Endpoint and tunnel lifetime/physical route admission remain
// separate gates before this API may be connected to a client request.
type pfPolicy struct {
	loopback bool
	tunnel   *pfInterface
	escapes  []pfUDPEscape
}

var pfInterfaceName = regexp.MustCompile(`^[a-z][a-z0-9]{0,14}$`)
var pfUDPRule = regexp.MustCompile(`^pass out quick on ([a-z][a-z0-9]{0,14}) (inet6?) proto udp from ([0-9a-f.:]+) port = ([0-9]{1,5}) to ([0-9a-f.:]+) port = ([0-9]{1,5}) user = (?:0|root) no state$`)
var pfTunnelRule = regexp.MustCompile(`^pass out quick on (utun[0-9]{1,10}) all(?: flags any)? no state$`)

func pfNumericAddress(address netip.Addr) bool {
	return address.IsValid() && address.Zone() == "" && !address.Is4In6() && !address.IsUnspecified() && !address.IsMulticast() && address.String() != "255.255.255.255"
}

func pfEscapeKey(escape pfUDPEscape) string {
	return escape.path.name + "\x00" + escape.source.String() + "\x00" + escape.endpoint.String() + "\x00" + strconv.FormatUint(uint64(escape.sourcePort), 10)
}

func (policy pfPolicy) frozen() (pfPolicy, error) {
	if len(policy.escapes) > maxPFReferences {
		return pfPolicy{}, ErrRecoveryRequired
	}
	copyPolicy := pfPolicy{loopback: policy.loopback, escapes: append([]pfUDPEscape(nil), policy.escapes...)}
	if policy.tunnel != nil {
		value := *policy.tunnel
		if !utunName.MatchString(value.name) || value.index < 1 || value.index > 2147483647 {
			return pfPolicy{}, ErrRecoveryRequired
		}
		copyPolicy.tunnel = &value
	}
	for _, escape := range copyPolicy.escapes {
		if !pfInterfaceName.MatchString(escape.path.name) || escape.path.index < 1 || escape.path.index > 2147483647 || !pfNumericAddress(escape.source) || !escape.endpoint.IsValid() || escape.endpoint.Port() == 0 || escape.sourcePort == 0 || !pfNumericAddress(escape.endpoint.Addr()) || escape.source.Is4() != escape.endpoint.Addr().Is4() {
			return pfPolicy{}, ErrRecoveryRequired
		}
	}
	sort.Slice(copyPolicy.escapes, func(i, j int) bool { return pfEscapeKey(copyPolicy.escapes[i]) < pfEscapeKey(copyPolicy.escapes[j]) })
	unique := copyPolicy.escapes[:0]
	for _, escape := range copyPolicy.escapes {
		if len(unique) > 0 && pfEscapeKey(unique[len(unique)-1]) == pfEscapeKey(escape) {
			if unique[len(unique)-1].path.index != escape.path.index {
				return pfPolicy{}, ErrRecoveryRequired
			}
			continue
		}
		unique = append(unique, escape)
	}
	copyPolicy.escapes = unique
	return copyPolicy, nil
}

func (policy pfPolicy) render() (string, error) {
	policy, err := policy.frozen()
	if err != nil {
		return "", ErrRecoveryRequired
	}
	var text strings.Builder
	if policy.loopback {
		text.WriteString("pass out quick on lo0 all flags any no state\n")
	}
	if policy.tunnel != nil {
		fmt.Fprintf(&text, "pass out quick on %s all flags any no state\n", policy.tunnel.name)
	}
	for _, escape := range policy.escapes {
		family := "inet6"
		if escape.source.Is4() {
			family = "inet"
		}
		// The worker opens outer UDP sockets as root. A mandatory local port
		// narrows this exception to its admitted socket tuple. The owner must
		// revoke/re-admit it when that socket closes or reopens; PF does not
		// identify a worker PID or prevent privileged reuse of the tuple.
		fmt.Fprintf(&text, "pass out quick on %s %s proto udp from %s port = %d to %s port = %d user = 0 no state\n", escape.path.name, family, escape.source, escape.sourcePort, escape.endpoint.Addr(), escape.endpoint.Port())
	}
	text.WriteString(stagedPFRule)
	return text.String(), nil
}

// Parse only the restricted native display grammar. Exact native bytes are
// hashed separately; a permissive semantic parse never authorizes a third hash.
// Index is absent from PF text and must be checked against OS observations.
func parsePFPolicy(text string) (pfPolicy, error) {
	if text == "" || len(text) > 65536 || !strings.HasSuffix(text, stagedPFRule) {
		return pfPolicy{}, ErrRecoveryRequired
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) > maxPFReferences+3 || lines[len(lines)-1]+"\n" != stagedPFRule {
		return pfPolicy{}, ErrRecoveryRequired
	}
	var policy pfPolicy
	for _, line := range lines[:len(lines)-1] {
		if line == "pass out quick on lo0 all flags any no state" || line == "pass out quick on lo0 all no state" {
			if policy.loopback || policy.tunnel != nil || len(policy.escapes) != 0 {
				return pfPolicy{}, ErrRecoveryRequired
			}
			policy.loopback = true
			continue
		}
		if match := pfTunnelRule.FindStringSubmatch(line); match != nil {
			if policy.tunnel != nil || len(policy.escapes) != 0 {
				return pfPolicy{}, ErrRecoveryRequired
			}
			policy.tunnel = &pfInterface{match[1], 1}
			continue
		}
		match := pfUDPRule.FindStringSubmatch(line)
		if match == nil {
			return pfPolicy{}, ErrRecoveryRequired
		}
		source, err := netip.ParseAddr(match[3])
		sourcePort, second := strconv.ParseUint(match[4], 10, 16)
		destination, third := netip.ParseAddr(match[5])
		port, fourth := strconv.ParseUint(match[6], 10, 16)
		if err != nil || second != nil || third != nil || fourth != nil || sourcePort == 0 || port == 0 || !pfNumericAddress(source) || !pfNumericAddress(destination) || source.Is4() != destination.Is4() || (match[2] == "inet") != source.Is4() || source.String() != match[3] || destination.String() != match[5] || strconv.FormatUint(sourcePort, 10) != match[4] || strconv.FormatUint(port, 10) != match[6] {
			return pfPolicy{}, ErrRecoveryRequired
		}
		policy.escapes = append(policy.escapes, pfUDPEscape{path: pfInterface{match[1], 1}, source: source, endpoint: netip.AddrPortFrom(destination, uint16(port)), sourcePort: uint16(sourcePort)})
	}
	validated, err := policy.frozen()
	if err != nil || len(validated.escapes) != len(policy.escapes) {
		return pfPolicy{}, ErrRecoveryRequired
	}
	return validated, nil
}

func samePFPolicy(a, b pfPolicy) bool {
	if a.loopback != b.loopback || (a.tunnel == nil) != (b.tunnel == nil) || len(a.escapes) != len(b.escapes) {
		return false
	}
	if a.tunnel != nil && a.tunnel.name != b.tunnel.name {
		return false
	}
	for i := range a.escapes {
		if pfEscapeKey(a.escapes[i]) != pfEscapeKey(b.escapes[i]) {
			return false
		}
	}
	return true
}
