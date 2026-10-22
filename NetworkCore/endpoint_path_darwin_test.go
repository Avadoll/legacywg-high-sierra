package networkcore

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func fixtureIP(text string) route.Addr {
	address := netip.MustParseAddr(text)
	if address.Is4() {
		return &route.Inet4Addr{IP: address.As4()}
	}
	return &route.Inet6Addr{IP: address.As16()}
}

func fixtureReply(six bool) *route.RouteMessage {
	addrs := make([]route.Addr, unix.RTAX_MAX)
	addrs[unix.RTAX_IFP] = &route.LinkAddr{Index: 42}
	if six {
		addrs[unix.RTAX_DST] = fixtureIP("2001:db8:1::")
		addrs[unix.RTAX_NETMASK] = fixtureIP("ffff:ffff:ffff:ffff::")
		addrs[unix.RTAX_GATEWAY] = &route.Inet6Addr{IP: netip.MustParseAddr("fe80::1").As16(), ZoneID: 42}
		addrs[unix.RTAX_IFA] = fixtureIP("2001:db8:1::2")
	} else {
		addrs[unix.RTAX_DST] = fixtureIP("192.0.2.0")
		addrs[unix.RTAX_NETMASK] = fixtureIP("255.255.255.0")
		addrs[unix.RTAX_GATEWAY] = fixtureIP("192.0.2.1")
		addrs[unix.RTAX_IFA] = fixtureIP("192.0.2.2")
	}
	return &route.RouteMessage{Version: unix.RTM_VERSION, Type: unix.RTM_GET,
		Flags: unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_IFSCOPE | unix.RTF_STATIC,
		Index: 42, ID: 123, Seq: 7, Addrs: addrs}
}

func fixtureInterface(index int) (*net.Interface, error) {
	if index != 42 {
		return nil, errors.New("unavailable")
	}
	return &net.Interface{Index: 42, Name: "en42", Flags: net.FlagUp}, nil
}

func TestScopedDecoderIPv4IPv6AndDefault(t *testing.T) {
	for _, six := range []bool{false, true} {
		destination := netip.MustParseAddr("192.0.2.99")
		want := netip.MustParsePrefix("192.0.2.0/24")
		if six {
			destination = netip.MustParseAddr("2001:db8:1::99")
			want = netip.MustParsePrefix("2001:db8:1::/64")
		}
		reply := fixtureReply(six)
		path, err := decode(destination, 42, true, reply, fixtureInterface)
		if err != nil || path.Prefix != want || path.InterfaceIndex != 42 || !path.Source.IsValid() {
			t.Fatal("valid scoped fixture refused")
		}
		if six {
			reply.Addrs[unix.RTAX_DST] = fixtureIP("::")
			reply.Addrs[unix.RTAX_NETMASK] = fixtureIP("::")
		} else {
			reply.Addrs[unix.RTAX_DST] = fixtureIP("0.0.0.0")
			reply.Addrs[unix.RTAX_NETMASK] = fixtureIP("0.0.0.0")
		}
		path, err = decode(destination, 42, true, reply, fixtureInterface)
		if err != nil || path.Prefix.Bits() != 0 {
			t.Fatal("explicit scoped default refused")
		}
	}
}

func TestScopedDecoderRefusesWrongIdentity(t *testing.T) {
	cases := map[string]func(*route.RouteMessage){
		"source absent":       func(r *route.RouteMessage) { r.Addrs[unix.RTAX_IFA] = nil },
		"source zero":         func(r *route.RouteMessage) { r.Addrs[unix.RTAX_IFA] = fixtureIP("0.0.0.0") },
		"source wrong family": func(r *route.RouteMessage) { r.Addrs[unix.RTAX_IFA] = fixtureIP("2001:db8::2") },
		"source multicast":    func(r *route.RouteMessage) { r.Addrs[unix.RTAX_IFA] = fixtureIP("224.0.0.1") },
		"source wrong zone": func(r *route.RouteMessage) {
			r.Addrs[unix.RTAX_IFA] = &route.Inet6Addr{IP: netip.MustParseAddr("fe80::2").As16(), ZoneID: 7}
		},
		"gateway absent":             func(r *route.RouteMessage) { r.Addrs[unix.RTAX_GATEWAY] = nil },
		"gateway zero":               func(r *route.RouteMessage) { r.Addrs[unix.RTAX_GATEWAY] = fixtureIP("0.0.0.0") },
		"route not up":               func(r *route.RouteMessage) { r.Flags &^= unix.RTF_UP },
		"reject":                     func(r *route.RouteMessage) { r.Flags |= unix.RTF_REJECT },
		"blackhole":                  func(r *route.RouteMessage) { r.Flags |= unix.RTF_BLACKHOLE },
		"dead":                       func(r *route.RouteMessage) { r.Flags |= unix.RTF_DEAD },
		"condemned":                  func(r *route.RouteMessage) { r.Flags |= unix.RTF_CONDEMNED },
		"implicit scope":             func(r *route.RouteMessage) { r.Flags &^= unix.RTF_IFSCOPE },
		"wrong scope":                func(r *route.RouteMessage) { r.Index = 43; r.Addrs[unix.RTAX_IFP] = &route.LinkAddr{Index: 43} },
		"contradictory index":        func(r *route.RouteMessage) { r.Addrs[unix.RTAX_IFP] = &route.LinkAddr{Index: 43} },
		"destination absent":         func(r *route.RouteMessage) { r.Addrs[unix.RTAX_DST] = nil },
		"destination wrong family":   func(r *route.RouteMessage) { r.Addrs[unix.RTAX_DST] = fixtureIP("2001:db8::") },
		"destination does not cover": func(r *route.RouteMessage) { r.Addrs[unix.RTAX_DST] = fixtureIP("198.51.100.0") },
		"noncanonical prefix":        func(r *route.RouteMessage) { r.Addrs[unix.RTAX_DST] = fixtureIP("192.0.2.7") },
		"missing mask":               func(r *route.RouteMessage) { r.Addrs[unix.RTAX_NETMASK] = nil },
		"noncontiguous mask":         func(r *route.RouteMessage) { r.Addrs[unix.RTAX_NETMASK] = fixtureIP("255.0.255.0") },
		"wrong mask family":          func(r *route.RouteMessage) { r.Addrs[unix.RTAX_NETMASK] = fixtureIP("ffff:ffff:ffff:ffff::") },
		"host with prefix mask":      func(r *route.RouteMessage) { r.Flags |= unix.RTF_HOST },
		"kernel error":               func(r *route.RouteMessage) { r.Err = unix.ESRCH },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			reply := fixtureReply(false)
			change(reply)
			if _, err := decode(netip.MustParseAddr("192.0.2.99"), 42, true, reply, fixtureInterface); err == nil {
				t.Fatal("unsafe scoped identity accepted")
			}
		})
	}
}

func TestScopedDecoderDirectHostAndDynamicLinkAddress(t *testing.T) {
	destination := netip.MustParseAddr("192.0.2.99")
	reply := fixtureReply(false)
	reply.Flags = unix.RTF_UP | unix.RTF_HOST | unix.RTF_IFSCOPE | unix.RTF_LLINFO | unix.RTF_WASCLONED
	reply.Addrs[unix.RTAX_DST] = fixtureIP(destination.String())
	reply.Addrs[unix.RTAX_NETMASK] = nil
	reply.Addrs[unix.RTAX_GATEWAY] = &route.LinkAddr{Index: 42, Addr: []byte{1, 2, 3, 4, 5, 6}}
	before, err := decode(destination, 42, true, reply, fixtureInterface)
	if err != nil || !before.Direct || before.Gateway.IsValid() || before.Prefix.Bits() != 32 {
		t.Fatal("direct host fixture refused")
	}
	reply.Addrs[unix.RTAX_GATEWAY] = &route.LinkAddr{Index: 42, Addr: []byte{6, 5, 4, 3, 2, 1}}
	after, err := decode(destination, 42, true, reply, fixtureInterface)
	if err != nil || after != before {
		t.Fatal("neighbor link metadata changed path identity")
	}
	reply.Addrs[unix.RTAX_GATEWAY] = &route.LinkAddr{Index: 7}
	if _, err := decode(destination, 42, true, reply, fixtureInterface); err == nil {
		t.Fatal("wrong direct gateway interface accepted")
	}
}

func TestUnscopedCompatibilityKeepsOptionalSourceAndNoPrefix(t *testing.T) {
	reply := fixtureReply(false)
	reply.Flags &^= unix.RTF_IFSCOPE
	reply.Addrs[unix.RTAX_IFA] = nil
	reply.Addrs[unix.RTAX_DST] = nil
	reply.Addrs[unix.RTAX_NETMASK] = nil
	path, err := decode(netip.MustParseAddr("192.0.2.99"), 0, false, reply, fixtureInterface)
	if err != nil || path.Source.IsValid() || path.Prefix.IsValid() || path.InterfaceName != "en42" {
		t.Fatal("existing unscoped compatibility changed")
	}
	if _, err := decode(netip.MustParseAddr("192.0.2.99"), 42, true, reply, fixtureInterface); err == nil {
		t.Fatal("compatibility admission escaped into strict path")
	}
}

// Moved with the native decoder from Engine/session. These compatibility-path
// refusals must survive sharing the query with stricter scoped admission.
func TestKernelEndpointRouteRejectsUnsafeReplies(t *testing.T) {
	destination := netip.MustParseAddr("192.0.2.99")
	for _, flags := range []int{0, unix.RTF_UP | unix.RTF_REJECT, unix.RTF_UP | unix.RTF_BLACKHOLE, unix.RTF_UP | unix.RTF_DEAD, unix.RTF_UP | unix.RTF_CONDEMNED} {
		reply := fixtureReply(false)
		reply.Flags = flags
		if _, err := decode(destination, 0, false, reply, fixtureInterface); err == nil {
			t.Fatal("unusable unscoped route flags accepted")
		}
	}
	reply := fixtureReply(false)
	reply.Addrs[unix.RTAX_GATEWAY] = nil
	if _, err := decode(destination, 0, false, reply, fixtureInterface); err == nil {
		t.Fatal("missing unscoped gateway accepted")
	}
	reply = fixtureReply(false)
	reply.Addrs[unix.RTAX_IFP] = &route.LinkAddr{Index: 43}
	if _, err := decode(destination, 0, false, reply, fixtureInterface); err == nil {
		t.Fatal("conflicting unscoped indices accepted")
	}
}

func TestScopedObservationDoesNotAdmitImplicitDefault(t *testing.T) {
	destination := netip.MustParseAddr("192.0.2.99")
	reply := fixtureReply(false)
	reply.Flags &^= unix.RTF_IFSCOPE
	reply.Addrs[unix.RTAX_DST] = fixtureIP("0.0.0.0")
	reply.Addrs[unix.RTAX_NETMASK] = fixtureIP("0.0.0.0")
	observation, err := decode(destination, 42, false, reply, fixtureInterface)
	if err != nil || !observation.Prefix.IsValid() || observation.Prefix.Bits() != 0 || observation.Flags&unix.RTF_IFSCOPE != 0 {
		t.Fatal("implicit default could not be characterized")
	}
	if _, err := decode(destination, 42, true, reply, fixtureInterface); err == nil {
		t.Fatal("observation widened strict scope admission")
	}
}

func TestScopedIPv6GatewayZoneAndInterfaceLoss(t *testing.T) {
	reply := fixtureReply(true)
	destination := netip.MustParseAddr("2001:db8:1::99")
	reply.Addrs[unix.RTAX_GATEWAY] = &route.Inet6Addr{IP: netip.MustParseAddr("fe80::1").As16(), ZoneID: 7}
	if _, err := decode(destination, 42, true, reply, fixtureInterface); err == nil {
		t.Fatal("wrong IPv6 gateway scope accepted")
	}
	reply = fixtureReply(true)
	for _, lookup := range []func(int) (*net.Interface, error){
		func(int) (*net.Interface, error) { return nil, errors.New("gone") },
		func(int) (*net.Interface, error) { return &net.Interface{Index: 42, Name: "en42"}, nil },
		func(int) (*net.Interface, error) {
			return &net.Interface{Index: 43, Name: "en42", Flags: net.FlagUp}, nil
		},
	} {
		if _, err := decode(destination, 42, true, reply, lookup); err == nil {
			t.Fatal("invalid current interface accepted")
		}
	}
}

func TestReplyCorrelationRejectsEveryOtherRequest(t *testing.T) {
	request := fixtureReply(false)
	if !sameRequest(request, fixtureReply(false)) {
		t.Fatal("own reply did not match")
	}
	for _, change := range []func(*route.RouteMessage){
		func(r *route.RouteMessage) { r.ID++ }, func(r *route.RouteMessage) { r.Seq++ },
		func(r *route.RouteMessage) { r.Type = unix.RTM_ADD }, func(r *route.RouteMessage) { r.Version++ },
	} {
		reply := fixtureReply(false)
		change(reply)
		if sameRequest(request, reply) {
			t.Fatal("another request matched")
		}
	}
}

func TestSharedAllocatorConcurrentUniqueAndPermanentlyExhausted(t *testing.T) {
	var counter atomic.Uint64
	var workers sync.WaitGroup
	values := make(chan int, 64)
	for i := 0; i < 64; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			value, err := allocateSequence(&counter)
			if err == nil {
				values <- value
			}
		}()
	}
	workers.Wait()
	close(values)
	seen := map[int]bool{}
	for value := range values {
		if value <= 0 || seen[value] {
			t.Fatal("sequence reused")
		}
		seen[value] = true
	}
	if len(seen) != 64 {
		t.Fatal("sequence allocation lost")
	}
	counter.Store(0x7ffffffe)
	if value, err := allocateSequence(&counter); err != nil || value != 0x7fffffff {
		t.Fatal("last sequence refused")
	}
	for i := 0; i < 3; i++ {
		if _, err := allocateSequence(&counter); err == nil || counter.Load() != 0x7fffffff {
			t.Fatal("exhausted allocator reused or advanced")
		}
	}
}

func TestCanceledQueryRefusesBeforeSocket(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := sequence.Load()
	if _, err := EndpointRoute(ctx, netip.MustParseAddr("127.0.0.1")); err == nil {
		t.Fatal("canceled endpoint query accepted")
	}
	if _, err := ScopedRoute(ctx, netip.MustParseAddr("192.0.2.99"), 42); err == nil {
		t.Fatal("canceled scoped query accepted")
	}
	if sequence.Load() != before {
		t.Fatal("canceled query consumed sequence or reached socket setup")
	}
}
