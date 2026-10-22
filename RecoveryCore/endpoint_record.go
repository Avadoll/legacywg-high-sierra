package recoverycore

import (
	"bytes"
	"encoding/json"
	"io"
	"net/netip"
)

const maxEndpointRecordBytes = 16384
const maxEndpointRoutes = 16

type endpointRoutePhase string

const (
	endpointPlanned      endpointRoutePhase = "planned"
	endpointAddIntent    endpointRoutePhase = "add_intent"
	endpointInstalled    endpointRoutePhase = "installed"
	endpointRemoveIntent endpointRoutePhase = "remove_intent"
	endpointRemoved      endpointRoutePhase = "removed"
)

// Fixed host-only effects, not commands, route text, keys or arbitrary paths.
// Addresses are sensitive private metadata; never include a record in a
// diagnostic/CI report. Source is the route IFA, not a chosen socket source.
type endpointRouteSpec struct {
	Destination netip.Addr `json:"destination"`
	Interface   string     `json:"interface"`
	Index       int        `json:"index"`
	Source      netip.Addr `json:"source"`
	SourceZone  int        `json:"source_zone"`
	Gateway     netip.Addr `json:"gateway"`
	GatewayZone int        `json:"gateway_zone"`
	Direct      bool       `json:"direct"`
}

type endpointRouteEntry struct {
	Spec  endpointRouteSpec  `json:"spec"`
	Phase endpointRoutePhase `json:"phase"`
}

type endpointRouteRecord struct {
	Version int                  `json:"version"`
	ID      string               `json:"id"`
	Boot    string               `json:"boot"`
	PID     int                  `json:"pid"`
	PFID    string               `json:"pf_id"`
	Routes  []endpointRouteEntry `json:"routes"`
}

func (spec endpointRouteSpec) valid() bool {
	dst := spec.Destination
	if !pfNumericAddress(dst) || dst.IsLinkLocalUnicast() || dst.IsLoopback() ||
		!pfInterfaceName.MatchString(spec.Interface) || spec.Index < 1 || spec.Index > 65535 || !pfNumericAddress(spec.Source) {
		return false
	}
	for _, value := range []struct {
		address netip.Addr
		zone    int
	}{{spec.Source, spec.SourceZone}, {spec.Gateway, spec.GatewayZone}} {
		if !value.address.IsValid() {
			if value.zone != 0 {
				return false
			}
			continue
		}
		if !pfNumericAddress(value.address) || value.address.BitLen() != dst.BitLen() || value.zone < 0 {
			return false
		}
		if value.address.IsLinkLocalUnicast() {
			if value.zone != spec.Index {
				return false
			}
		} else if value.zone != 0 {
			return false
		}
	}
	return spec.Direct == !spec.Gateway.IsValid()
}

func newEndpointRouteRecord(boot, pfID string, specs []endpointRouteSpec) (endpointRouteRecord, error) {
	owner, err := NewRecord(boot)
	if err != nil {
		return endpointRouteRecord{}, ErrRecoveryRequired
	}
	record := endpointRouteRecord{Version: 1, ID: owner.ID, Boot: boot, PID: owner.PID, PFID: pfID}
	for _, spec := range specs {
		record.Routes = append(record.Routes, endpointRouteEntry{spec, endpointPlanned})
	}
	if record.valid() != nil {
		return endpointRouteRecord{}, ErrRecoveryRequired
	}
	return record, nil
}

func (record endpointRouteRecord) valid() error {
	if record.Version != 1 || !hexID.MatchString(record.ID) || !hexID.MatchString(record.PFID) || !bootID.MatchString(record.Boot) || record.PID < 1 || record.PID > 2147483647 || len(record.Routes) < 1 || len(record.Routes) > maxEndpointRoutes {
		return ErrRecoveryRequired
	}
	seen := make(map[netip.Addr]bool)
	for _, entry := range record.Routes {
		if !entry.Spec.valid() || seen[entry.Spec.Destination] {
			return ErrRecoveryRequired
		}
		seen[entry.Spec.Destination] = true
		switch entry.Phase {
		case endpointPlanned, endpointAddIntent, endpointInstalled, endpointRemoveIntent, endpointRemoved:
		default:
			return ErrRecoveryRequired
		}
	}
	return nil
}

func (record endpointRouteRecord) advance(index int, phase endpointRoutePhase) (endpointRouteRecord, error) {
	if record.valid() != nil || index < 0 || index >= len(record.Routes) {
		return endpointRouteRecord{}, ErrRecoveryRequired
	}
	before := record.Routes[index].Phase
	if !((before == endpointPlanned && (phase == endpointAddIntent || phase == endpointRemoved)) ||
		(before == endpointAddIntent && (phase == endpointInstalled || phase == endpointRemoved)) ||
		(before == endpointInstalled && phase == endpointRemoveIntent) ||
		(before == endpointRemoveIntent && phase == endpointRemoved)) {
		return endpointRouteRecord{}, ErrRecoveryRequired
	}
	next := record
	next.Routes = append([]endpointRouteEntry(nil), record.Routes...)
	next.Routes[index].Phase = phase
	return next, nil
}

func endpointTransition(before, next endpointRouteRecord) bool {
	if before.valid() != nil || next.valid() != nil || before.Version != next.Version || before.ID != next.ID || before.Boot != next.Boot || before.PID != next.PID || before.PFID != next.PFID || len(before.Routes) != len(next.Routes) {
		return false
	}
	changed := -1
	for i, entry := range before.Routes {
		if entry.Spec != next.Routes[i].Spec {
			return false
		}
		if entry.Phase != next.Routes[i].Phase {
			if changed != -1 {
				return false
			}
			changed = i
		}
	}
	if changed == -1 {
		return false
	}
	_, err := before.advance(changed, next.Routes[changed].Phase)
	return err == nil
}

func encodeEndpointRoutes(record endpointRouteRecord) ([]byte, error) {
	if record.valid() != nil {
		return nil, ErrRecoveryRequired
	}
	data, err := json.Marshal(record)
	if err != nil || len(data)+1 > maxEndpointRecordBytes {
		return nil, ErrRecoveryRequired
	}
	return append(data, '\n'), nil
}

func decodeEndpointRoutes(data []byte) (endpointRouteRecord, error) {
	if len(data) < 1 || len(data) > maxEndpointRecordBytes {
		return endpointRouteRecord{}, ErrRecoveryRequired
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var record endpointRouteRecord
	if decoder.Decode(&record) != nil || record.valid() != nil {
		return endpointRouteRecord{}, ErrRecoveryRequired
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return endpointRouteRecord{}, ErrRecoveryRequired
	}
	canonical, err := encodeEndpointRoutes(record)
	if err != nil || !bytes.Equal(bytes.TrimSuffix(data, []byte{'\n'}), bytes.TrimSuffix(canonical, []byte{'\n'})) {
		return endpointRouteRecord{}, ErrRecoveryRequired
	}
	return record, nil
}
