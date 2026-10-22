package networkcore

import (
	"encoding/binary"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// Pinned x/net v0.39.0 route_classic.go reads Err at byte28, which is rtm_use
// on Darwin. Apple's rt_msghdr (legacy and current) stores rtm_errno at24.
// Keep the pinned library for sockaddr parsing, normalize only this header
// field in our adapter, and validate it against the native SDK in CI. Never
// modify the dependency or infer success/absence from its uncorrected Err.
func parseRouteFrames(data []byte) ([]route.Message, error) {
	var result []route.Message
	for count := 0; len(data) > 0; count++ {
		if count >= 1024 || len(data) < 4 {
			return nil, ErrPathUnavailable
		}
		length := int(binary.LittleEndian.Uint16(data[:2]))
		if length < 4 || length > len(data) {
			return nil, ErrPathUnavailable
		}
		frame := data[:length]
		messages, err := route.ParseRIB(route.RIBTypeRoute, frame)
		if err != nil || len(messages) > 1 {
			return nil, ErrPathUnavailable
		}
		for _, message := range messages {
			if reply, ok := message.(*route.RouteMessage); ok {
				if len(frame) < unix.SizeofRtMsghdr || reply.Version != unix.RTM_VERSION {
					return nil, ErrPathUnavailable
				}
				reply.Err = nil
				if errno := binary.LittleEndian.Uint32(frame[24:28]); errno != 0 {
					reply.Err = unix.Errno(errno)
				}
			}
			result = append(result, message)
		}
		data = data[length:]
	}
	return result, nil
}
