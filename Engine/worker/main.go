// worker accepts a bounded private pipe protocol, never a public socket/UAPI.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	configcore "legacywg/ConfigCore"
	"legacywg/Engine/session"
)

type request struct {
	Version int    `json:"version"`
	Op      string `json:"op"`
	Profile string `json:"profile,omitempty"`
}

func respond(output io.Writer, value any) { _ = json.NewEncoder(output).Encode(value) }
func handle(engine *session.Session, input []byte) any {
	var message request
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&message) != nil || message.Version != 1 {
		return map[string]any{"ok": false, "error": "invalid private request"}
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return map[string]any{"ok": false, "error": "trailing private request data"}
	}
	if message.Op != "validate" && message.Op != "start" && message.Profile != "" {
		return map[string]any{"ok": false, "error": "unexpected profile"}
	}
	var err error
	switch message.Op {
	case "validate":
		profile := []byte(message.Profile)
		defer clear(profile)
		config, failure := configcore.Parse(profile)
		if failure != nil {
			err = failure
			break
		}
		defer config.Destroy()
		_, capability := session.CheckCapabilities(config)
		reason := ""
		if capability != nil {
			reason = capability.Error()
		}
		return map[string]any{"ok": true, "peers": len(config.Peers), "dns_count": len(config.DNS),
			"native_supported": capability == nil, "limitation": reason}
	case "start":
		profile := []byte(message.Profile)
		defer clear(profile)
		err = engine.Start(profile)
	case "stop":
		err = engine.Stop()
	case "status":
	default:
		err = fmt.Errorf("unsupported private operation")
	}
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	status, err := engine.Status()
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	return map[string]any{"ok": true, "status": status}
}

func main() {
	if disableCoreDumps() != nil {
		respond(os.Stdout, map[string]any{"ok": false, "error": "cannot disable engine core dumps"})
		return
	}
	engine := &session.Session{}
	defer engine.Stop()
	if len(os.Args) == 2 && os.Args[1] == "--validate" {
		data, err := io.ReadAll(io.LimitReader(os.Stdin, configcore.MaxFileBytes+1))
		if err != nil || len(data) > configcore.MaxFileBytes {
			respond(os.Stdout, map[string]any{"ok": false, "error": "profile size limit"})
			os.Exit(1)
		}
		message, _ := json.Marshal(request{Version: 1, Op: "validate", Profile: string(data)})
		clear(data)
		result := handle(engine, message)
		clear(message)
		respond(os.Stdout, result)
		return
	}
	if len(os.Args) != 1 {
		return
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		result := handle(engine, line)
		clear(line)
		respond(os.Stdout, result)
	}
}
