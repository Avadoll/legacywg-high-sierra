package networkcore

import (
	"encoding/binary"
	"errors"
	"testing"
	"unsafe"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func TestDarwinRouteHeaderErrorIsNotUseCounter(t *testing.T) {
	var header unix.RtMsghdr
	if unsafe.Offsetof(header.Errno) != 24 || unsafe.Offsetof(header.Use) != 28 || unsafe.Sizeof(header) != 92 {
		t.Fatal("pinned Darwin header layout mismatch")
	}
	for _, kind := range []int{unix.RTM_GET, unix.RTM_ADD, unix.RTM_DELETE} {
		for _, fixture := range []struct{ errno, use uint32 }{{0, 0}, {0, 123}, {uint32(unix.ESRCH), 0}, {uint32(unix.EEXIST), 99}, {uint32(unix.EPERM), 0}} {
			reply := fixtureReply(false)
			reply.Type = kind
			data, err := reply.Marshal()
			if err != nil {
				t.Fatal("route header fixture encoding failed")
			}
			binary.LittleEndian.PutUint32(data[24:28], fixture.errno)
			binary.LittleEndian.PutUint32(data[28:32], fixture.use)
			messages, err := parseRouteFrames(data)
			if err != nil || len(messages) != 1 {
				t.Fatal("route header fixture parsing failed")
			}
			parsed, ok := messages[0].(*route.RouteMessage)
			if !ok || (fixture.errno == 0 && parsed.Err != nil) || (fixture.errno != 0 && !errors.Is(parsed.Err, unix.Errno(fixture.errno))) || !sameRequest(reply, parsed) {
				t.Fatal("route errno/use counter conflated or correlation changed")
			}
			if _, err := parseRouteFrames(append(append([]byte(nil), data...), 0)); err == nil {
				t.Fatal("trailing truncated frame accepted")
			}
		}
	}
}
