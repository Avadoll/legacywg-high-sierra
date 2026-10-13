package session

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"
)

type dnsProcess struct {
	command    *exec.Cmd
	input      io.WriteCloser
	done       chan struct{}
	alive      atomic.Bool
	lastBeat   atomic.Int64
	closeInput sync.Once
}

func startDNS(iface string, servers []netip.Addr) (*dnsProcess, error) {
	process := &dnsProcess{command: exec.Command("/Library/Application Support/LegacyWG/legacywg-network"), done: make(chan struct{})}
	process.command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	input, err := process.command.StdinPipe()
	if err != nil {
		return nil, errors.New("cannot open DNS transaction input")
	}
	process.input = input
	output, err := process.command.StdoutPipe()
	if err != nil {
		input.Close()
		return nil, errors.New("cannot open DNS transaction output")
	}
	if err = process.command.Start(); err != nil {
		input.Close()
		output.Close()
		return nil, errors.New("cannot start verified DNS transaction component")
	}
	process.alive.Store(true)
	process.lastBeat.Store(1)
	response := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(output)
		scanner.Buffer(make([]byte, 128), 1024)
		var reply struct {
			OK bool `json:"ok"`
		}
		ok := scanner.Scan() && json.Unmarshal(scanner.Bytes(), &reply) == nil && reply.OK
		response <- ok
		for ok && scanner.Scan() {
			ok = json.Unmarshal(scanner.Bytes(), &reply) == nil && reply.OK
			if ok {
				process.lastBeat.Add(1)
			}
		}
		// Malformed/negative heartbeats close only our DNS transaction.
		process.closeInput.Do(func() { process.input.Close() })
		if !ok {
			process.command.Process.Kill()
		}
		io.Copy(io.Discard, output)
		process.command.Wait()
		process.alive.Store(false)
		close(process.done)
	}()
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		previous := process.lastBeat.Load()
		observed := time.Now()
		for {
			select {
			case <-process.done:
				return
			case now := <-ticker.C:
				current := process.lastBeat.Load()
				if current != previous {
					previous = current
					observed = now
				}
				// Monotonic elapsed time survives wall-clock/NTP changes.
				if now.Sub(observed) > 4*time.Second {
					process.command.Process.Kill()
					return
				}
			}
		}
	}()
	numeric := make([]string, len(servers))
	for i, address := range servers {
		numeric[i] = address.String()
	}
	message := struct {
		Version   int      `json:"version"`
		Interface string   `json:"interface"`
		Servers   []string `json:"servers"`
	}{1, iface, numeric}
	if json.NewEncoder(input).Encode(message) != nil {
		process.close()
		return nil, errors.New("cannot submit DNS transaction")
	}
	select {
	case ok := <-response:
		if ok {
			return process, nil
		}
	case <-time.After(3 * time.Second):
	}
	process.close()
	return nil, errors.New("native DNS transaction was refused")
}

func (process *dnsProcess) close() error {
	if process == nil {
		return nil
	}
	process.closeInput.Do(func() { process.input.Close() })
	select {
	case <-process.done:
		return nil
	case <-time.After(2 * time.Second):
		process.command.Process.Kill()
	}
	select {
	case <-process.done:
		return nil
	case <-time.After(time.Second):
		return errors.New("DNS transaction cleanup requires attention")
	}
}
