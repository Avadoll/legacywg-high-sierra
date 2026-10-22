package recoverycore

import (
	"encoding/binary"
	"net/netip"
	"strings"
)

// Unsupported Intel LP64 Darwin ABI. Layout comes from compiler comparison of
// pinned XNU4570/11417 declarations; native tests compare complete rule payloads
// against compiled primary structs. These pure frames perform no kernel call.
// A future owned coordinator must bind actual transaction/pool tickets and
// revalidate OS paths/ownership before use; no client request calls this codec.
const pfFilterFrameSize = 3104
const pfFilterRuleOffset = 2064

type pfFilterFrame [pfFilterFrameSize]byte

func compiledPFFilterFrames(anchor string, policy pfPolicy) ([]pfFilterFrame, error) {
	if !strings.HasPrefix(anchor, "com.apple/legacywg-") || !hexID.MatchString(strings.TrimPrefix(anchor, "com.apple/legacywg-")) {
		return nil, ErrRecoveryRequired
	}
	policy, err := policy.frozen()
	if err != nil {
		return nil, ErrRecoveryRequired
	}
	frames := make([]pfFilterFrame, 0, len(policy.escapes)+3)
	base := func(ifname string, block bool) pfFilterFrame {
		var frame pfFilterFrame
		copy(frame[16:1040], anchor)
		copy(frame[pfFilterRuleOffset+256:pfFilterRuleOffset+272], ifname)
		if block {
			frame[pfFilterRuleOffset+1004] = 1 // PF_DROP
		}
		frame[pfFilterRuleOffset+1005] = 2 // PF_OUT
		frame[pfFilterRuleOffset+1008] = 1 // quick
		// All other bytes stay zero: no state/flags mask/NAT/table/tag/owner,
		// pointers, rtable scope (Apple IFSCOPE_NONE=0) or rule options.
		return frame
	}
	if policy.loopback {
		frames = append(frames, base("lo0", false))
	}
	if policy.tunnel != nil {
		frames = append(frames, base(policy.tunnel.name, false))
	}
	address := func(frame *pfFilterFrame, offset int, value netip.Addr) {
		size := 16
		if value.Is4() {
			bytes := value.As4()
			copy(frame[offset:offset+4], bytes[:])
			size = 4
		} else {
			bytes := value.As16()
			copy(frame[offset:offset+16], bytes[:])
		}
		for i := 0; i < size; i++ {
			frame[offset+16+i] = 255 // exact source/destination, never a subnet
		}
	}
	for _, escape := range policy.escapes {
		frame := base(escape.path.name, false)
		family := byte(30) // Darwin AF_INET6
		if escape.source.Is4() {
			family = 2 // Darwin AF_INET
		}
		frame[pfFilterRuleOffset+1013] = family
		frame[pfFilterRuleOffset+1014] = 17 // UDP
		address(&frame, pfFilterRuleOffset, escape.source)
		address(&frame, pfFilterRuleOffset+64, escape.endpoint.Addr())
		sourcePort := pfFilterRuleOffset + 48 // src.xport.range.port
		binary.BigEndian.PutUint16(frame[sourcePort:sourcePort+2], escape.sourcePort)
		binary.BigEndian.PutUint16(frame[sourcePort+2:sourcePort+4], escape.sourcePort)
		frame[sourcePort+4] = 2              // PF_OP_EQ: the admitted local UDP port only
		port := pfFilterRuleOffset + 64 + 48 // dst.xport.range.port
		binary.BigEndian.PutUint16(frame[port:port+2], escape.endpoint.Port())
		binary.BigEndian.PutUint16(frame[port+2:port+4], escape.endpoint.Port())
		frame[port+4] = 2 // PF_OP_EQ, not a range
		// pf_rule.uid: two native uint32 UID0 bounds remain zero, op at +8.
		// Full primary-C payload comparison measures this unsupported layout.
		frame[pfFilterRuleOffset+976+8] = 2 // PF_OP_EQ: root-owned socket only
		frames = append(frames, frame)
	}
	frames = append(frames, base("", true))
	return frames, nil
}
