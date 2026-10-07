// The smoke command is a developer probe, excluded from any release bundle.
package main

import (
	"encoding/json"
	"os"
	"runtime"
	"time"
)

func main() {
	started := time.Now()
	result := map[string]any{"go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH, "test": "native-utun-engine-lifecycle"}
	if err := probe(); err != nil {
		result["status"] = "FAIL"
		result["reason"] = err.Error()
		_ = json.NewEncoder(os.Stdout).Encode(result)
		os.Exit(1)
	}
	result["status"] = "PASS"
	result["elapsed_ms"] = time.Since(started).Milliseconds()
	result["handshake"] = "NOT_RUN"
	result["server_traffic"] = "NOT_RUN"
	_ = json.NewEncoder(os.Stdout).Encode(result)
}
