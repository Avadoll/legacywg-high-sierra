package recoverycore

import (
	"context"
	"strings"
)

type pfAnchorObservation struct {
	path       string
	children   []string
	rules, nat string
}

func readPFAnchorText(ctx context.Context, path, kind string) (string, error) {
	if (path != "" && !validPFAnchorPath(path)) || (kind != "rules" && kind != "nat" && kind != "Anchors") {
		return "", ErrRecoveryRequired
	}
	if path == "" {
		return runOwnedPF(ctx, "", "-s", kind)
	}
	return runOwnedPF(ctx, "", "-a", path, "-s", kind)
}

// Independently enumerate every direct kernel child; do not infer the tree
// from inline/wildcard rule printing. The root also counts toward the bound.
func enumeratePFAnchors(ctx context.Context) ([]pfAnchorObservation, error) {
	queue := []string{""}
	seen := map[string]bool{"": true}
	var observations []pfAnchorObservation
	totalBytes := 0
	for len(queue) > 0 {
		if ctx.Err() != nil {
			return nil, ErrRecoveryRequired
		}
		path := queue[0]
		queue = queue[1:]
		text, err := readPFAnchorText(ctx, path, "Anchors")
		if err != nil {
			return nil, ErrRecoveryRequired
		}
		children, err := parsePFChildren(path, text)
		if err != nil {
			return nil, ErrRecoveryRequired
		}
		for _, child := range children {
			if seen[child] || len(seen) >= maxPFAnchors {
				return nil, ErrRecoveryRequired
			}
			seen[child] = true
			queue = append(queue, child)
		}
		rules, err := readPFAnchorText(ctx, path, "rules")
		if err != nil {
			return nil, ErrRecoveryRequired
		}
		nat, err := readPFAnchorText(ctx, path, "nat")
		if err != nil {
			return nil, ErrRecoveryRequired
		}
		totalBytes += len(text) + len(rules) + len(nat)
		if totalBytes > 256*1024 {
			return nil, ErrRecoveryRequired
		}
		observations = append(observations, pfAnchorObservation{path, children, rules, nat})
	}
	// Re-enumerate the same direct child sets after all content reads. This
	// catches ordinary tree mutation but cannot provide an atomic PF snapshot.
	for _, observation := range observations {
		text, err := readPFAnchorText(ctx, observation.path, "Anchors")
		if err != nil {
			return nil, ErrRecoveryRequired
		}
		children, err := parsePFChildren(observation.path, text)
		if err != nil || len(children) != len(observation.children) {
			return nil, ErrRecoveryRequired
		}
		for i := range children {
			if children[i] != observation.children[i] {
				return nil, ErrRecoveryRequired
			}
		}
		for _, content := range []struct{ kind, expected string }{{"rules", observation.rules}, {"nat", observation.nat}} {
			actual, err := readPFAnchorText(ctx, observation.path, content.kind)
			if err != nil || actual != content.expected {
				return nil, ErrRecoveryRequired
			}
		}
	}
	return observations, nil
}

func pfEnumeratedDigests(observations []pfAnchorObservation, owned string) (string, string, error) {
	if !strings.HasPrefix(owned, "com.apple/legacywg-") || !hexID.MatchString(strings.TrimPrefix(owned, "com.apple/legacywg-")) || len(observations) < 1 || len(observations) > maxPFAnchors {
		return "", "", ErrRecoveryRequired
	}
	var filter, nat strings.Builder
	filter.WriteString("kernel-anchor-tree-v1\x00filter\x00")
	nat.WriteString("kernel-anchor-tree-v1\x00nat\x00")
	for _, observation := range observations {
		if observation.path == owned {
			if len(observation.children) != 0 || observation.nat != "" {
				return "", "", ErrRecoveryRequired
			}
			if observation.rules != "" {
				if _, err := parsePFPolicy(observation.rules); err != nil {
					return "", "", ErrRecoveryRequired
				}
			}
			continue
		}
		if strings.HasPrefix(observation.path, owned+"/") {
			return "", "", ErrRecoveryRequired
		}
		// Unknown foreign filter/NAT policy is refused even when its rules
		// are not displayed by the root wildcard-recursion command.
		if _, ownCall, err := pfForeignView(observation.rules, owned); err != nil || ownCall {
			return "", "", ErrRecoveryRequired
		}
		if _, ownCall, err := pfForeignView(observation.nat, owned); err != nil || ownCall {
			return "", "", ErrRecoveryRequired
		}
		filter.WriteString(observation.path + "\x00" + observation.rules + "\x00")
		nat.WriteString(observation.path + "\x00" + observation.nat + "\x00")
		for _, child := range observation.children {
			if child != owned {
				filter.WriteString(child + "\x00")
				nat.WriteString(child + "\x00")
			}
		}
		filter.WriteByte('\n')
		nat.WriteByte('\n')
	}
	return pfDigest(filter.String()), pfDigest(nat.String()), nil
}
