package recoverycore

import (
	"regexp"
	"sort"
	"strings"
)

const maxPFAnchors = 64
const maxPFAnchorDepth = 8

var pfAnchorPath = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*(?:/[A-Za-z0-9_][A-Za-z0-9_.-]*)*$`)

// DIOCGETRULESET-backed pfctl enumeration returns direct children. Accept a
// basename or the exact fully qualified direct child, never a wildcard, option,
// traversal, sibling, deeper descendant or duplicate. Names remain private.
func parsePFChildren(parent, text string) ([]string, error) {
	if len(text) > 65536 || (parent != "" && !validPFAnchorPath(parent)) {
		return nil, ErrRecoveryRequired
	}
	var children []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(text, "\n") {
		name := strings.TrimSpace(line)
		if name == "" {
			continue
		}
		if !validPFAnchorPath(name) {
			return nil, ErrRecoveryRequired
		}
		path := name
		if parent != "" && !strings.Contains(name, "/") {
			path = parent + "/" + name
		}
		prefix := ""
		if parent != "" {
			prefix = parent + "/"
		}
		if !strings.HasPrefix(path, prefix) || strings.Contains(strings.TrimPrefix(path, prefix), "/") || seen[path] || !validPFAnchorPath(path) || len(children) >= maxPFAnchors {
			return nil, ErrRecoveryRequired
		}
		seen[path] = true
		children = append(children, path)
	}
	sort.Strings(children)
	return children, nil
}

func validPFAnchorPath(path string) bool {
	if path == "" || len(path) > 1023 || !pfAnchorPath.MatchString(path) || strings.Count(path, "/") >= maxPFAnchorDepth {
		return false
	}
	for _, part := range strings.Split(path, "/") {
		if part == "." || part == ".." || len(part) > 63 {
			return false
		}
	}
	return true
}
