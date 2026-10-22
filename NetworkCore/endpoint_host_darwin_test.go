package networkcore

import (
	"context"
	"net/netip"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func TestScopedHostOwnershipMatchesOnlyExactStaticIdentity(t *testing.T) {
	for _, six := range []bool{false, true} {
		dst := netip.MustParseAddr("192.0.2.99")
		if six {
			dst = netip.MustParseAddr("2001:db8:1::99")
		}
		reply := fixtureReply(six)
		reply.Flags |= unix.RTF_HOST
		reply.Addrs[unix.RTAX_DST] = routeAddress(dst, 0)
		reply.Addrs[unix.RTAX_NETMASK] = nil
		observed, err := decode(dst, 42, true, reply, fixtureInterface)
		if err != nil {
			t.Fatal("exact route fixture refused")
		}
		host := ScopedHost{dst, observed.Path}
		if !host.Matches(observed) {
			t.Fatal("exact static host not matched")
		}
		for _, flag := range []int{unix.RTF_STATIC, unix.RTF_IFSCOPE, unix.RTF_HOST} {
			other := observed
			other.Flags &^= flag
			if host.Matches(other) {
				t.Fatal("borrowed route mistaken for owned host")
			}
		}
		other := observed
		other.Flags |= unix.RTF_WASCLONED
		if host.Matches(other) {
			t.Fatal("cloned neighbor mistaken for owned host")
		}
		other = observed
		other.Prefix = netip.PrefixFrom(dst, 0).Masked()
		if host.Matches(other) {
			t.Fatal("default route mistaken for owned host")
		}
		other = observed
		other.SourceZone++
		if host.Matches(other) {
			t.Fatal("changed route source accepted")
		}
	}
	if ChangeScopedHost(context.Background(), ScopedHost{}, true) == nil {
		t.Fatal("invalid mutation accepted")
	}
}

func TestScopedHostDirectIPv6NeighborAnnotation(t *testing.T) {
	for _, six := range []bool{false, true} {
		destination := netip.MustParseAddr("192.0.2.99")
		if six {
			destination = netip.MustParseAddr("2001:db8:1::99")
		}
		reply := fixtureReply(six)
		reply.Flags = unix.RTF_UP | unix.RTF_HOST | unix.RTF_STATIC | unix.RTF_IFSCOPE | unix.RTF_LLINFO
		reply.Addrs[unix.RTAX_DST] = routeAddress(destination, 0)
		reply.Addrs[unix.RTAX_NETMASK] = nil
		reply.Addrs[unix.RTAX_GATEWAY] = &route.LinkAddr{Index: 42}
		observed, err := decode(destination, 42, true, reply, fixtureInterface)
		if err != nil {
			t.Fatal("annotated direct route refused by decoder")
		}
		host := ScopedHost{Destination: destination, Path: observed.Path}
		if host.Matches(observed) != six {
			t.Fatal("neighbor annotation exception crossed its proven scope")
		}
		observed.Flags |= unix.RTF_WASCLONED
		if host.Matches(observed) {
			t.Fatal("cloned neighbor claimed as static ownership")
		}
	}
}
