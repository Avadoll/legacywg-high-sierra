package recoverycore

import (
	"strings"
	"testing"
)

func TestPFForeignViewOwnershipAndAmbiguity(t *testing.T) {
	owned := "com.apple/legacywg-" + strings.Repeat("a", 32)
	base := "anchor \"com.apple/*\" all {\n}\n"
	want, seen, err := pfForeignView(base, owned)
	if err != nil || seen {
		t.Fatal("empty baseline refused")
	}
	for _, name := range []string{owned, strings.TrimPrefix(owned, "com.apple/")} {
		text := "anchor \"com.apple/*\" all {\n anchor \"" + name + "\" all {\n  " + stagedPFRule + " }\n}\n"
		got, seen, err := pfForeignView(text, owned)
		if err != nil || !seen || got != want {
			t.Fatal("own child changed foreign baseline")
		}
	}
	for _, text := range []string{
		"block drop out quick all\n",
		"anchor \"foreign\" all {\n anchor \"" + strings.TrimPrefix(owned, "com.apple/") + "\" all {\n }\n}\n",
		"anchor \"foreign\" all {\n anchor \"" + owned + "\" all {\n }\n}\n",
		"anchor \"" + owned + "\" all {\n pass out all\n}\n",
		"anchor \"" + owned + "\" all {\n anchor \"child\" all {\n }\n}\n",
		"anchor \"" + owned + "\" all {\n}\nanchor \"" + owned + "\" all {\n}\n",
		"anchor \"" + owned + "\" all {\n",
		"}\n", "pass out quick all\n",
	} {
		if _, _, err := pfForeignView(text, owned); err == nil {
			t.Fatal("foreign, nested, ambiguous or malformed policy accepted")
		}
	}
	a, _, err := pfForeignView("anchor \"a\" all {\n anchor \"b\" all {\n }\n}\n", owned)
	b, _, second := pfForeignView("anchor \"a\" all {\n}\nanchor \"b\" all {\n}\n", owned)
	if err != nil || second != nil || a == b {
		t.Fatal("foreign hierarchy change lost from identity")
	}
}
