package recoverycore

// Test-only ordinary-process negative control on the same owned synthetic
// outer path. No private root metadata or installed request is exposed.
import (
	"bytes"
	"context"
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
	if err != nil || uid == 0 || uint64(os.Getuid()) != uid || uint64(os.Geteuid()) != uid || os.Getenv("GITHUB_ACTIONS") != "true" {
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
	_ = udp.SetDeadline(time.Now().Add(650 * time.Millisecond))
	connection := &pfFixtureUDPConnection{udp, &net.UDPAddr{IP: net.ParseIP(destination), Port: 45121}}
	query := bytes.Repeat([]byte{0x47}, 32)
	reply := make([]byte, len(query))
	n, err := connection.Write(query)
	succeeded := false
	if err == nil && n == len(query) {
		_, err = io.ReadFull(connection, reply)
		succeeded = err == nil && bytes.Equal(query, reply)
	}
	if succeeded {
		t.Log("NONROOT_PACKET_REPLY")
	} else {
		t.Log("NONROOT_PACKET_NO_REPLY")
	}
}

func pfNonrootPacketProbe(t *testing.T, ctx context.Context, iface *net.Interface, capture *pfPacketObservation, family int, allowed bool) {
	t.Helper()
	uid, err := strconv.ParseUint(os.Getenv("LEGACYWG_PF_NONROOT_UID"), 10, 32)
	gid, gidErr := strconv.ParseUint(os.Getenv("LEGACYWG_PF_NONROOT_GID"), 10, 32)
	if err != nil || gidErr != nil || uid == 0 || gid == 0 {
		t.Fatal("ordinary CI probe identity unavailable")
	}
	before := capture.count(pfPacketKey{family, 17, 45121})
	probeCtx, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	child := exec.CommandContext(probeCtx, os.Args[0], "-test.run=^TestPFRuleUnprivilegedPacketChild$", "-test.v")
	child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	child.Env = append(os.Environ(), "LEGACYWG_PF_UID_CHILD=1", "LEGACYWG_PF_UID_FAMILY="+strconv.Itoa(family), "LEGACYWG_PF_UID_INTERFACE="+iface.Name)
	output, err := child.Output()
	if err != nil || len(output) > 4096 || strings.Contains(string(output), "SKIP") {
		t.Fatal("ordinary kernel packet child failed")
	}
	text := string(output)
	reply := strings.Contains(text, "NONROOT_PACKET_REPLY")
	noReply := strings.Contains(text, "NONROOT_PACKET_NO_REPLY")
	time.Sleep(100 * time.Millisecond)
	observed := capture.count(pfPacketKey{family, 17, 45121}) - before
	if reply == noReply || reply != allowed || (allowed && observed < 1) || (!allowed && observed != 0) {
		t.Fatalf("ordinary process packet policy differs: family=%d allowed=%t", family, allowed)
	}
}
