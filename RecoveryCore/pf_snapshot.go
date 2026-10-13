package recoverycore

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

// Initial compiled deny rule. Dynamic typed exceptions are added only through
// the journal-bound update coordinator, never from caller-supplied rule text.
const stagedPFRule = "block drop out quick all\n"

func pfDigest(data string) string {
	digest := sha256.Sum256([]byte(data))
	return hex.EncodeToString(digest[:])
}

var pfAnchorLine = regexp.MustCompile(`^(?:scrub-anchor|anchor|nat-anchor|rdr-anchor) "([A-Za-z0-9_.*/-]+)"(?: all)?(?: fragment reassemble)?$`)

// Only empty anchor calls and our exact compiled rule are admitted. This is
// deliberately narrower than arbitrary existing firewall coexistence. Brace
// nesting identifies ownership; a matching name outside com.apple is refused.
// Formatting is normalized, but order, call kind and foreign names are hashed.
func pfForeignView(text, owned string) (string, bool, error) {
	if !strings.HasPrefix(owned, "com.apple/legacywg-") || !hexID.MatchString(strings.TrimPrefix(owned, "com.apple/legacywg-")) || len(text) > 65536 {
		return "", false, ErrRecoveryRequired
	}
	var stack []string
	var lines []string
	var ownLines []string
	seen, inOwn := false, false
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if line == "}" {
			if len(stack) == 0 {
				return "", false, ErrRecoveryRequired
			}
			if inOwn && len(ownLines) > 0 {
				if _, err := parsePFPolicy(strings.Join(ownLines, "\n") + "\n"); err != nil {
					return "", false, ErrRecoveryRequired
				}
				ownLines = nil
			}
			if !inOwn {
				lines = append(lines, "}")
			}
			stack = stack[:len(stack)-1]
			inOwn = len(stack) > 0 && stack[len(stack)-1] == owned
			continue
		}
		block := strings.HasSuffix(line, " {")
		call := strings.TrimSuffix(line, " {")
		match := pfAnchorLine.FindStringSubmatch(call)
		if match == nil {
			if !inOwn || block || len(ownLines) >= maxPFReferences+3 {
				return "", false, ErrRecoveryRequired
			}
			ownLines = append(ownLines, line)
			continue
		}
		name := match[1]
		path := name
		if len(stack) > 0 && !strings.Contains(name, "/") {
			path = strings.TrimSuffix(stack[len(stack)-1], "/*") + "/" + name
		}
		// pfctl may render a wildcard's child using its fully qualified path.
		isOwn := path == owned
		if isOwn && len(stack) > 0 && stack[len(stack)-1] != "com.apple/*" && stack[len(stack)-1] != "com.apple" {
			return "", false, ErrRecoveryRequired
		}
		if inOwn || (strings.Contains(name, "legacywg-") && !isOwn) {
			return "", false, ErrRecoveryRequired
		}
		if isOwn {
			if seen || !block || !strings.HasPrefix(call, "anchor ") {
				return "", false, ErrRecoveryRequired
			}
			seen = true
		} else {
			lines = append(lines, line)
		}
		if block {
			if len(stack) >= 16 {
				return "", false, ErrRecoveryRequired
			}
			stack = append(stack, path)
			inOwn = isOwn
		}
	}
	if len(stack) != 0 {
		return "", false, ErrRecoveryRequired
	}
	return strings.Join(lines, "\n") + "\n", seen, nil
}
