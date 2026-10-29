package main

import (
	"runtime"
)

// A successful process start proves loading of this exact linked worker. This
// path never initializes Session, reads a profile or changes system networking.
func platformCheck() map[string]any {
	return map[string]any{
		"schema": 1, "kind": "worker-runtime-check", "ok": runtime.GOOS == "darwin" && runtime.GOARCH == "amd64",
		"os": runtime.GOOS, "arch": runtime.GOARCH, "go": runtime.Version(),
		"network_changed": false, "vpn_tested": false,
	}
}
