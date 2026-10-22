package networkcore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// Fixed destinations are only AF_ROUTE query keys. No socket is opened for
// payloads, no DNS is used, and no packet is sent to these addresses.
var egressDestinations = [2]netip.Addr{
	netip.MustParseAddr("198.18.99.90"),
	netip.MustParseAddr("2001:db8:198:18::90"),
}

var enName = regexp.MustCompile(`^en[0-9]+$`)

type egressReport struct {
	Status                         string `json:"status"`
	StrictScopedSnapshot           string `json:"strict_scoped_snapshot"`
	ConcurrentStatus               string `json:"concurrent_status"`
	UnscopedQuerySucceeded         bool   `json:"unscoped_query_succeeded"`
	ScopedQuerySucceeded           bool   `json:"scoped_query_succeeded"`
	ENInterfaceName                bool   `json:"en_interface_name"`
	EthernetType                   bool   `json:"ethernet_type"`
	InterfaceIdentityCurrent       bool   `json:"interface_identity_current"`
	SourceAssigned                 bool   `json:"source_assigned"`
	ScopeMatchesEgress             bool   `json:"scope_matches_egress"`
	PathMatchesUnscoped            bool   `json:"path_matches_unscoped"`
	ExplicitScopedFlag             bool   `json:"explicit_scoped_flag"`
	SelectedRouteIsDefault         bool   `json:"selected_route_is_default"`
	BaselineUnchanged              bool   `json:"baseline_unchanged"`
	ConcurrentQueriesChecked       bool   `json:"concurrent_queries_checked"`
	ConcurrentQueriesMatch         bool   `json:"concurrent_queries_match"`
	SharedSequenceAllocationUnique bool   `json:"shared_sequence_allocation_unique"`
	CrossRepliesObserved           bool   `json:"cross_replies_observed"`
}

type characterizationReport struct {
	Status                  string       `json:"status"`
	ReadOnly                bool         `json:"read_only"`
	PayloadPacketsSent      bool         `json:"payload_packets_sent"`
	UDPSocketsOpened        bool         `json:"udp_sockets_opened"`
	RouteMutations          bool         `json:"route_mutations"`
	PFMutations             bool         `json:"pf_mutations"`
	DNSQueries              bool         `json:"dns_queries"`
	NetworkMetadataExported bool         `json:"network_metadata_exported"`
	PhysicalHardwareTested  bool         `json:"physical_hardware_tested"`
	HighSierraTested        bool         `json:"high_sierra_tested"`
	IPv4                    egressReport `json:"ipv4"`
	IPv6                    egressReport `json:"ipv6"`
}

func TestNativeReadOnlyEgressCharacterization(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("LEGACYWG_READONLY_ROUTE_CHARACTERIZATION") != "1" {
		t.Skip("read-only CI characterization requires explicit opt-in")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	report := characterizationReport{Status: "COMPLETE", ReadOnly: true}
	var failed4, failed6 bool
	report.IPv4, failed4 = characterizeEgress(ctx, egressDestinations[0])
	report.IPv6, failed6 = characterizeEgress(ctx, egressDestinations[1])
	if failed4 || failed6 || ctx.Err() != nil {
		report.Status = "FAILED"
	}
	blob, err := json.Marshal(report)
	if err != nil {
		t.Fatal("sanitized characterization encoding failed")
	}
	fmt.Println("LEGACYWG_ROUTE_CHARACTERIZATION=" + string(blob))
	if report.Status != "COMPLETE" {
		t.Fatal("read-only characterization invariant failed or path changed")
	}
}

func characterizeEgress(ctx context.Context, destination netip.Addr) (egressReport, bool) {
	report := egressReport{Status: "QUERY_ERROR", StrictScopedSnapshot: "NOT_RUN", ConcurrentStatus: "NOT_RUN"}
	before, err := EndpointRoute(ctx, destination)
	if err != nil {
		if errors.Is(err, ErrNoRoute) {
			report.Status = "NO_ROUTE"
			_, again := EndpointRoute(ctx, destination)
			report.BaselineUnchanged = errors.Is(again, ErrNoRoute)
			if again == nil {
				report.Status = "PATH_CHANGED"
				return report, true
			}
			if !errors.Is(again, ErrNoRoute) {
				report.Status = "QUERY_ERROR"
			}
		}
		return report, false
	}
	report.UnscopedQuerySucceeded = true
	readEgressMetadata(before, &report)
	observed, observationError := query(ctx, destination, before.InterfaceIndex, false)
	if observationError == nil {
		report.ScopedQuerySucceeded = true
		report.ScopeMatchesEgress = observed.InterfaceIndex == before.InterfaceIndex && observed.InterfaceName == before.InterfaceName
		report.PathMatchesUnscoped = observed.Path == before
		report.ExplicitScopedFlag = observed.Flags&unix.RTF_IFSCOPE != 0
		report.SelectedRouteIsDefault = observed.Prefix.IsValid() && observed.Prefix.Bits() == 0
		checkConcurrentQueries(ctx, destination, before, observed, &report)
	}
	strict, strictError := ScopedRoute(ctx, destination, before.InterfaceIndex)
	report.StrictScopedSnapshot = "REFUSED"
	switch {
	case !report.ENInterfaceName || !report.EthernetType || !report.InterfaceIdentityCurrent:
		report.Status = "NOT_EN_ETHERNET"
	case !report.SourceAssigned:
		report.Status = "SOURCE_UNASSIGNED"
	case observationError != nil:
		report.Status = "STRICT_QUERY_REFUSED"
	case !report.ScopeMatchesEgress || !report.PathMatchesUnscoped:
		report.Status = "PATH_CHANGED"
	case !report.ExplicitScopedFlag && strictError != nil:
		report.Status = "REFUSED_UNSCOPED_ROUTE"
		if report.SelectedRouteIsDefault {
			report.Status = "REFUSED_IMPLICIT_PRIMARY"
		}
	case strictError != nil:
		report.Status = "STRICT_QUERY_REFUSED"
	case strict.Path != before || strict.Flags != observed.Flags || strict.Prefix != observed.Prefix:
		report.Status = "PATH_CHANGED"
	default:
		report.Status = "SCOPED_SNAPSHOT_PASS"
		report.StrictScopedSnapshot = "PASS"
		report.SelectedRouteIsDefault = strict.Prefix.Bits() == 0
	}
	// Metadata and both route observations must still match after stress. No
	// assignment is inferred solely from RTAX_IFA or an interface name pattern.
	after, afterError := EndpointRoute(ctx, destination)
	metadata := egressReport{}
	if afterError == nil {
		readEgressMetadata(after, &metadata)
	}
	observedAfter, observedAfterError := query(ctx, destination, before.InterfaceIndex, false)
	scopedStable := observationError == nil && observedAfterError == nil && observedAfter == observed
	if errors.Is(observationError, ErrNoRoute) && errors.Is(observedAfterError, ErrNoRoute) {
		scopedStable = true
	}
	report.BaselineUnchanged = afterError == nil && after == before &&
		metadata.InterfaceIdentityCurrent == report.InterfaceIdentityCurrent &&
		metadata.SourceAssigned == report.SourceAssigned && metadata.EthernetType == report.EthernetType &&
		scopedStable
	if !report.BaselineUnchanged {
		report.Status = "PATH_CHANGED"
		report.StrictScopedSnapshot = "REFUSED"
	}
	failed := report.Status == "PATH_CHANGED" || report.ConcurrentStatus == "FAILED_OR_CHANGED"
	// If strict decoding ever accepts an observed implicit route, do not label
	// it a working physical path; surface the inconsistent observation instead.
	if observationError == nil && !report.ExplicitScopedFlag && strictError == nil {
		report.Status, report.StrictScopedSnapshot = "PATH_CHANGED", "REFUSED"
		failed = true
	}
	return report, failed
}

func readEgressMetadata(path Path, report *egressReport) {
	report.ENInterfaceName = enName.MatchString(path.InterfaceName)
	iface, err := net.InterfaceByIndex(path.InterfaceIndex)
	if err != nil || iface.Name != path.InterfaceName || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
		return
	}
	byName, err := net.InterfaceByName(path.InterfaceName)
	if err != nil || byName.Index != path.InterfaceIndex || byName.Flags&net.FlagUp == 0 {
		return
	}
	report.InterfaceIdentityCurrent = true
	addresses, err := iface.Addrs()
	if err == nil && path.Source.IsValid() && !path.Source.IsUnspecified() && !path.Source.IsMulticast() && !path.Source.Is4In6() {
		for _, address := range addresses {
			value, ok := address.(*net.IPNet)
			if !ok {
				continue
			}
			actual, ok := netip.AddrFromSlice(value.IP)
			if ok && actual.Unmap() == path.Source {
				report.SourceAssigned = true
			}
		}
	}
	// This is NET_RT_IFLIST for the exact captured index, NOT NET_RT_DUMP or
	// a routing-table enumeration. Only interface type is retained in report.
	data, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeInterface, path.InterfaceIndex)
	if err != nil || len(data) == 0 || len(data) > 128*1024 {
		return
	}
	messages, err := route.ParseRIB(route.RIBTypeInterface, data)
	if err != nil || len(messages) > 256 {
		return
	}
	found := false
	for _, message := range messages {
		info, ok := message.(*route.InterfaceMessage)
		if !ok {
			continue
		}
		if info.Index != path.InterfaceIndex || found {
			report.EthernetType = false
			return
		}
		found = true
		for _, extra := range info.Sys() {
			if metrics, ok := extra.(*route.InterfaceMetrics); ok {
				report.EthernetType = metrics.Type == unix.IFT_ETHER
			}
		}
	}
}

func checkConcurrentQueries(ctx context.Context, destination netip.Addr, unscoped Path, scoped ScopedPath, report *egressReport) {
	const count = 32
	beforeSequence, beforeOther := sequence.Load(), otherQueryReplies.Load()
	start := make(chan struct{})
	results := make(chan bool, count)
	var workers sync.WaitGroup
	for i := 0; i < count; i++ {
		workers.Add(1)
		go func(useScope bool) {
			defer workers.Done()
			<-start
			if useScope {
				value, err := query(ctx, destination, scoped.InterfaceIndex, false)
				results <- err == nil && value == scoped
			} else {
				value, err := EndpointRoute(ctx, destination)
				results <- err == nil && value == unscoped
			}
		}(i%2 != 0)
	}
	close(start)
	workers.Wait()
	close(results)
	report.ConcurrentQueriesChecked, report.ConcurrentQueriesMatch = true, true
	completed := 0
	for matched := range results {
		completed++
		report.ConcurrentQueriesMatch = report.ConcurrentQueriesMatch && matched
	}
	report.ConcurrentQueriesMatch = report.ConcurrentQueriesMatch && completed == count
	report.SharedSequenceAllocationUnique = sequence.Load()-beforeSequence == count
	report.CrossRepliesObserved = otherQueryReplies.Load() > beforeOther
	switch {
	case !report.ConcurrentQueriesMatch || !report.SharedSequenceAllocationUnique:
		report.ConcurrentStatus = "FAILED_OR_CHANGED"
	case report.CrossRepliesObserved:
		report.ConcurrentStatus = "PASS_WITH_CROSS_REPLIES"
	default:
		report.ConcurrentStatus = "PASS_WITHOUT_OBSERVED_CROSS_REPLIES"
	}
}
