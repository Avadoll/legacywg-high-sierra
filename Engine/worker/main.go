// worker accepts a bounded private pipe protocol, never a public socket/UAPI.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"

	configcore "legacywg/ConfigCore"
	"legacywg/Engine/session"
	networkcore "legacywg/NetworkCore"
)

type request struct {
	Version int    `json:"version"`
	Op      string `json:"op"`
	Profile string `json:"profile,omitempty"`
}

// Selected-profile metadata stays on the private validation pipe. It is never
// attached to public runtime status or diagnostics. Bound the preview below
// 8KiB so the GUI's wait-before-read cannot fill the native output pipe.
type profilePreview struct {
	Routing      string   `json:"routing"`
	Addresses    []string `json:"addresses"`
	AddressCount int      `json:"address_count"`
	Endpoints    []string `json:"endpoints"`
	RouteCount   int      `json:"route_count"`
}

func preview(config *configcore.Config) profilePreview {
	result := profilePreview{Routing: "unavailable", Addresses: []string{}, Endpoints: []string{}, AddressCount: len(config.Addresses)}
	for index, address := range config.Addresses {
		if index >= 8 {
			break
		}
		result.Addresses = append(result.Addresses, address.String())
	}
	for _, peer := range config.Peers {
		endpoint := ""
		if peer.Endpoint != nil {
			endpoint = net.JoinHostPort(peer.Endpoint.Host, strconv.Itoa(int(peer.Endpoint.Port)))
		}
		result.Endpoints = append(result.Endpoints, endpoint)
	}
	if plan, err := networkcore.Build(config, false); err == nil {
		result.RouteCount = len(plan.Routes)
		switch {
		case plan.FullIPv4 && plan.FullIPv6:
			result.Routing = "full_dual_stack"
		case plan.FullIPv4:
			result.Routing = "full_ipv4"
		case plan.FullIPv6:
			result.Routing = "full_ipv6"
		default:
			result.Routing = "split"
		}
	}
	return result
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
			"native_supported": capability == nil, "limitation": reason, "preview": preview(config)}
	case "start":
		profile := []byte(message.Profile)
		defer clear(profile)
		err = engine.Start(profile)
	case "stop":
		err = engine.Stop()
	case "recover":
		err = engine.Recover()
	case "status":
	default:
		err = fmt.Errorf("unsupported private operation")
	}
	if err != nil {
		status, statusError := engine.Status()
		if statusError == nil {
			return map[string]any{"ok": false, "error": err.Error(), "status": status}
		}
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
	if len(os.Args) == 2 && os.Args[1] == "--platform-check" {
		result := platformCheck()
		respond(os.Stdout, result)
		if result["ok"] != true {
			os.Exit(1)
		}
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
	engine.Initialize()
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
