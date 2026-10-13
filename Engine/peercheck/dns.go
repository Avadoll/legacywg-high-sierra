package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func dnsAnswer(packet []byte, allowTruncation bool) ([]byte, bool, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(packet)
	if err != nil {
		return nil, false, err
	}
	question, err := parser.Question()
	if err != nil {
		return nil, false, err
	}
	name := strings.ToLower(question.Name.String())
	known := strings.HasSuffix(name, ".legacywg.test.") && question.Type == dnsmessage.TypeA
	truncated := known && allowTruncation && strings.HasPrefix(name, "tcp-")
	rcode := dnsmessage.RCodeSuccess
	if !known {
		rcode = dnsmessage.RCodeNameError
	}
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: header.ID, Response: true,
		RecursionDesired: header.RecursionDesired, RecursionAvailable: true, Truncated: truncated, RCode: rcode})
	builder.EnableCompression()
	if err = builder.StartQuestions(); err == nil {
		err = builder.Question(question)
	}
	if err == nil && known && !truncated {
		err = builder.StartAnswers()
		if err == nil {
			err = builder.AResource(dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 0},
				dnsmessage.AResource{A: [4]byte{198, 18, 0, 77}})
		}
	}
	if err != nil {
		return nil, false, err
	}
	answer, err := builder.Finish()
	return answer, known, err
}

type dnsCounters struct{ udp, tcp atomic.Int64 }

func serveDNS(stack *netstack.Net, address netip.Addr) (func(), *dnsCounters, error) {
	udp, err := stack.ListenUDPAddrPort(netip.AddrPortFrom(address, 53))
	if err != nil {
		return nil, nil, errors.New("controlled UDP DNS listener failed")
	}
	tcp, err := stack.ListenTCPAddrPort(netip.AddrPortFrom(address, 53))
	if err != nil {
		udp.Close()
		return nil, nil, errors.New("controlled TCP DNS listener failed")
	}
	counters := &dnsCounters{}
	go func() {
		for {
			packet := make([]byte, 4096)
			size, remote, err := udp.ReadFrom(packet)
			if err != nil {
				return
			}
			answer, known, err := dnsAnswer(packet[:size], true)
			if err == nil {
				if known {
					counters.udp.Add(1)
				}
				udp.WriteTo(answer, remote)
			}
		}
	}()
	go func() {
		for {
			connection, err := tcp.Accept()
			if err != nil {
				return
			}
			go func(connection net.Conn) {
				defer connection.Close()
				connection.SetDeadline(time.Now().Add(3 * time.Second))
				var length [2]byte
				if _, err := io.ReadFull(connection, length[:]); err != nil {
					return
				}
				size := binary.BigEndian.Uint16(length[:])
				if size == 0 || size > 4096 {
					return
				}
				packet := make([]byte, size)
				if _, err := io.ReadFull(connection, packet); err != nil {
					return
				}
				answer, known, err := dnsAnswer(packet, false)
				if err != nil {
					return
				}
				if known {
					counters.tcp.Add(1)
				}
				binary.BigEndian.PutUint16(length[:], uint16(len(answer)))
				connection.Write(append(length[:], answer...))
			}(connection)
		}
	}()
	return func() { udp.Close(); tcp.Close() }, counters, nil
}

type dnsSnapshot struct {
	Present bool   `json:"dns_present"`
	Digest  string `json:"foreign_digest"`
	Count   int    `json:"foreign_count"`
}

func snapshotDNS(probe string) (dnsSnapshot, error) {
	var snapshot dnsSnapshot
	data, err := exec.Command(probe, "snapshot").Output()
	if err != nil || json.Unmarshal(data, &snapshot) != nil || snapshot.Digest == "" {
		return snapshot, errors.New("native DNS snapshot failed")
	}
	return snapshot, nil
}

func restoreDNS(probe string, before dnsSnapshot) error {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		now, err := snapshotDNS(probe)
		if err == nil && !now.Present && now.Digest == before.Digest && now.Count == before.Count {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("DNS cleanup did not restore original resolver state")
}

func systemDNS(probe string, counters *dnsCounters) error {
	for _, protocol := range []string{"udp", "tcp"} {
		name := protocol + "-" + time.Now().Format("150405.000000000") + ".legacywg.test"
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		data, err := exec.CommandContext(ctx, probe, "resolve", name).Output()
		cancel()
		var answer struct {
			OK bool `json:"ok"`
		}
		if err != nil || json.Unmarshal(data, &answer) != nil || !answer.OK {
			return errors.New("system resolver did not receive controlled tunnel DNS answer")
		}
	}
	if counters.udp.Load() < 2 || counters.tcp.Load() < 1 {
		return errors.New("DNS transport was not proved through UDP and TCP")
	}
	return nil
}
