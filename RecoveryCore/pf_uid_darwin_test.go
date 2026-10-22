package recoverycore

// Test-only ordinary-process negative control on the same owned synthetic
// outer path. No private root metadata or installed request is exposed.
import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestPFRuleUnprivilegedPacketChild(t *testing.T) {
	if os.Getenv("LEGACYWG_PF_UID_CHILD") != "1" {
		t.Skip("explicit isolated ordinary-user probe")
	}
	uid, err := strconv.ParseUint(os.Getenv("LEGACYWG_PF_NONROOT_UID"), 10, 32)
	gid, gidErr := strconv.ParseUint(os.Getenv("LEGACYWG_PF_NONROOT_GID"), 10, 32)
	if err != nil || gidErr != nil || uid == 0 || gid == 0 || uint64(os.Getuid()) != uid || uint64(os.Geteuid()) != uid || uint64(os.Getgid()) != gid || uint64(os.Getegid()) != gid || os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Fatal("ordinary probe kernel UID identity differs")
	}
	iface, err := net.InterfaceByName(os.Getenv("LEGACYWG_PF_UID_INTERFACE"))
	if err != nil || !utunName.MatchString(iface.Name) || iface.Flags&net.FlagUp == 0 {
		t.Fatal("ordinary probe owned path unavailable")
	}
	family := os.Getenv("LEGACYWG_PF_UID_FAMILY")
	network, source, destination := "udp4", "198.18.99.129", pfPacketServer4
	if family == "6" {
		network, source, destination = "udp6", "fd00:198:18:99::129", pfPacketServer6
	} else if family != "4" {
		t.Fatal("ordinary probe family refused")
	}
	udp, err := net.ListenUDP(network, &net.UDPAddr{IP: net.ParseIP(source)})
	if err != nil {
		t.Fatal("ordinary probe socket unavailable")
	}
	defer udp.Close()
	local, ok := udp.LocalAddr().(*net.UDPAddr)
	if !ok || local.Port < 1 || local.Port > 65535 || !local.IP.Equal(net.ParseIP(source)) {
		t.Fatal("ordinary probe socket identity unavailable")
	}
	// Announce only the port of this still-open socket. The parent admits that
	// exact port with user=0, so later refusal tests UID rather than port mismatch.
	fmt.Printf("NONROOT_PACKET_BOUND:%d\n", local.Port)
	connection := &pfFixtureUDPConnection{udp, &net.UDPAddr{IP: net.ParseIP(destination), Port: 45121}}
	commands := bufio.NewScanner(os.Stdin)
	commands.Buffer(make([]byte, 32), 32)
	for count := 0; commands.Scan(); count++ {
		if count >= 8 {
			t.Fatal("ordinary probe command limit exceeded")
		}
		switch commands.Text() {
		case "CLOSE":
			return
		case "PROBE":
		default:
			t.Fatal("ordinary probe command refused")
		}
		if err := udp.SetDeadline(time.Now().Add(650 * time.Millisecond)); err != nil {
			t.Fatal("ordinary probe deadline unavailable")
		}
		query := bytes.Repeat([]byte{0x47}, 32)
		reply := make([]byte, len(query))
		n, err := connection.Write(query)
		succeeded := false
		if err == nil && n == len(query) {
			_, err = io.ReadFull(connection, reply)
			succeeded = err == nil && bytes.Equal(query, reply)
		}
		if succeeded {
			fmt.Println("NONROOT_PACKET_REPLY")
		} else {
			fmt.Println("NONROOT_PACKET_NO_REPLY")
		}
	}
	t.Fatal("ordinary probe command stream ended before close")
}

type pfNonrootPacketSession struct {
	sourcePort uint16
	family     int
	capture    *pfPacketObservation
	input      io.WriteCloser
	output     <-chan string
	completed  <-chan error
}

func pfStartNonrootPacketSession(t *testing.T, ctx context.Context, iface *net.Interface, capture *pfPacketObservation, family int) *pfNonrootPacketSession {
	t.Helper()
	uid, err := strconv.ParseUint(os.Getenv("LEGACYWG_PF_NONROOT_UID"), 10, 32)
	gid, gidErr := strconv.ParseUint(os.Getenv("LEGACYWG_PF_NONROOT_GID"), 10, 32)
	if err != nil || gidErr != nil || uid == 0 || gid == 0 {
		t.Fatal("ordinary CI probe identity unavailable")
	}
	childCtx, cancelChild := context.WithTimeout(context.Background(), 165*time.Second)
	child := exec.CommandContext(childCtx, os.Args[0], "-test.run=^TestPFRuleUnprivilegedPacketChild$", "-test.timeout=160s")
	child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	child.Env = append(os.Environ(), "LEGACYWG_PF_UID_CHILD=1", "LEGACYWG_PF_UID_FAMILY="+strconv.Itoa(family), "LEGACYWG_PF_UID_INTERFACE="+iface.Name)
	input, err := child.StdinPipe()
	if err != nil {
		cancelChild()
		t.Fatal("ordinary probe command pipe unavailable")
	}
	stdout, err := child.StdoutPipe()
	if err != nil {
		input.Close()
		cancelChild()
		t.Fatal("ordinary probe response pipe unavailable")
	}
	if err := child.Start(); err != nil {
		input.Close()
		stdout.Close()
		cancelChild()
		t.Fatal("ordinary kernel packet child failed to start")
	}
	output := make(chan string, 16)
	completed := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 256), 1024)
		count := 0
		for scanner.Scan() {
			count++
			if count > 12 {
				_ = child.Process.Kill()
				break
			}
			output <- scanner.Text()
		}
		if scanner.Err() != nil {
			_ = child.Process.Kill()
		}
		waitErr := child.Wait()
		if waitErr == nil && (scanner.Err() != nil || count > 12) {
			waitErr = io.ErrUnexpectedEOF
		}
		completed <- waitErr
		close(output)
	}()
	session := &pfNonrootPacketSession{family: family, capture: capture, input: input, output: output, completed: completed}
	t.Cleanup(func() {
		defer cancelChild()
		_, writeErr := io.WriteString(input, "CLOSE\n")
		_ = input.Close()
		select {
		case err := <-completed:
			if err != nil || writeErr != nil {
				t.Error("ordinary packet child did not close cleanly")
			}
		case <-time.After(3 * time.Second):
			_ = child.Process.Kill()
			select {
			case <-completed:
			case <-time.After(3 * time.Second):
			}
			t.Error("ordinary packet child close deadline exceeded")
		}
	})
	ready := session.message(t, ctx)
	portText, found := strings.CutPrefix(ready, "NONROOT_PACKET_BOUND:")
	port, err := strconv.ParseUint(portText, 10, 16)
	if !found || err != nil || port == 0 || strconv.FormatUint(port, 10) != portText {
		t.Fatal("ordinary probe live socket readiness refused")
	}
	session.sourcePort = uint16(port)
	return session
}

func (session *pfNonrootPacketSession) message(t *testing.T, ctx context.Context) string {
	t.Helper()
	select {
	case message, open := <-session.output:
		if !open {
			t.Fatal("ordinary probe child exited before response")
		}
		return message
	case <-ctx.Done():
		t.Fatal("ordinary probe context ended")
	case <-time.After(5 * time.Second):
		t.Fatal("ordinary probe response deadline exceeded")
	}
	return ""
}

func (session *pfNonrootPacketSession) probe(t *testing.T, ctx context.Context, allowed bool) {
	t.Helper()
	before := session.capture.count(pfPacketKey{session.family, 17, 45121})
	if _, err := io.WriteString(session.input, "PROBE\n"); err != nil {
		t.Fatal("ordinary kernel packet command failed")
	}
	response := session.message(t, ctx)
	reply := response == "NONROOT_PACKET_REPLY"
	noReply := response == "NONROOT_PACKET_NO_REPLY"
	time.Sleep(100 * time.Millisecond)
	observed := session.capture.count(pfPacketKey{session.family, 17, 45121}) - before
	if reply == noReply || reply != allowed || (allowed && observed < 1) || (!allowed && observed != 0) {
		t.Fatalf("ordinary process packet policy differs: family=%d allowed=%t", session.family, allowed)
	}
}
