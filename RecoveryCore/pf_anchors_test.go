package recoverycore

import (
	"strings"
	"testing"
)

func TestPFChildrenDirectCanonicalBoundaries(t *testing.T) {
	for _, text := range []string{" b\n a\n", " com.apple/b\n com.apple/a\n"} {
		children, err := parsePFChildren("com.apple", text)
		if err != nil || len(children) != 2 || children[0] != "com.apple/a" || children[1] != "com.apple/b" {
			t.Fatal("direct kernel child normalization/order changed")
		}
	}
	for _, text := range []string{"a\na\n", "a\ncom.apple/a\n", "com.other/a\n", "com.apple/a/deep\n", "../x\n", "a/*\n", "-F\n", "a b\n", "a\x00b\n", "/a\n"} {
		if _, err := parsePFChildren("com.apple", text); err == nil {
			t.Fatal("ambiguous, indirect, wildcard, traversal or option-like name accepted")
		}
	}
	if _, err := parsePFChildren("", "a/deep\n"); err == nil {
		t.Fatal("root enumeration accepted a non-direct descendant")
	}
	if _, err := parsePFChildren(strings.Repeat("a/", 8)+"a", "child\n"); err == nil {
		t.Fatal("unbounded depth accepted")
	}
	if validPFAnchorPath(strings.Repeat("a", 64)) {
		t.Fatal("unbounded kernel name accepted")
	}
}
