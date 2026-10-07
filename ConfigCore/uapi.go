package configcore

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
)

// WriteUAPI is for the in-process official engine only. Never send its output
// to logs, command line arguments, public IPC or a persistent file.
func (config *Config) WriteUAPI(output io.Writer, endpoints []netip.AddrPort) error {
	if config == nil || len(endpoints) != len(config.Peers) {
		return errors.New("validated profile and resolved peer endpoints required")
	}
	for index, peer := range config.Peers {
		endpoint := endpoints[index]
		if peer.Endpoint != nil && (!endpoint.IsValid() || endpoint.Port() == 0 ||
			endpoint.Addr().IsUnspecified() || endpoint.Addr().IsMulticast() || endpoint.Addr().Zone() != "") {
			return errors.New("invalid resolved peer endpoint")
		}
		if peer.Endpoint == nil && endpoint.IsValid() {
			return errors.New("unexpected peer endpoint")
		}
	}
	key := func(name string, value Key) error {
		var encoded [64]byte
		defer clear(encoded[:])
		hex.Encode(encoded[:], value.value[:])
		if _, err := io.WriteString(output, name+"="); err != nil {
			return err
		}
		_, err := output.Write(encoded[:])
		if err != nil {
			return err
		}
		_, err = io.WriteString(output, "\n")
		return err
	}
	if err := key("private_key", config.PrivateKey); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(output, "listen_port=%d\nreplace_peers=true\n", config.ListenPort); err != nil {
		return err
	}
	for index, peer := range config.Peers {
		if err := key("public_key", peer.PublicKey); err != nil {
			return err
		}
		if peer.PresharedKey != nil {
			if err := key("preshared_key", *peer.PresharedKey); err != nil {
				return err
			}
		}
		if _, err := io.WriteString(output, "replace_allowed_ips=true\n"); err != nil {
			return err
		}
		for _, prefix := range peer.AllowedIPs {
			if _, err := fmt.Fprintf(output, "allowed_ip=%s\n", prefix.Masked()); err != nil {
				return err
			}
		}
		if peer.Endpoint != nil {
			if _, err := fmt.Fprintf(output, "endpoint=%s\n", endpoints[index]); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(output, "persistent_keepalive_interval=%d\n", peer.PersistentKeepalive); err != nil {
			return err
		}
	}
	return nil
}

// Destroy clears the typed key arrays. It cannot guarantee removal of copies
// in the parser, Go runtime, IPC buffers or the official device implementation.
func (config *Config) Destroy() {
	if config == nil {
		return
	}
	clear(config.PrivateKey.value[:])
	for index := range config.Peers {
		clear(config.Peers[index].PublicKey.value[:])
		if config.Peers[index].PresharedKey != nil {
			clear(config.Peers[index].PresharedKey.value[:])
		}
	}
}
