package main

import (
	"encoding/json"
	"legacywg/Engine/session"
	"strings"
	"testing"
)

func TestPrivateProtocolRejectsUnknownAndTrailingData(t *testing.T) {
	for _, message := range []string{`{"version":1,"op":"status","command":"/bin/sh"}`,
		`{"version":1,"op":"status"} {}`, `{"version":2,"op":"status"}`,
		`{"version":1,"op":"status","profile":"secret marker"}`} {
		result := handle(&session.Session{}, []byte(message))
		encoded, err := json.Marshal(result)
		if err != nil || !strings.Contains(string(encoded), `"ok":false`) || strings.Contains(string(encoded), "secret marker") {
			t.Fatal("invalid private protocol accepted or echoed sensitive input")
		}
	}
}
