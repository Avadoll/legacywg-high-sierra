package recoverycore

import (
	"bytes"
	"context"
	"encoding/binary"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Fixed private Intel LP64 ABI, compiler-checked against primary declarations.
// One FILTER entry only; no NAT/global ruleset/state/reference operation here.
// BEGINADDRS still uses PF's shared pool staging: privileged-writer atomicity
// is not provided. In-flight kernel ioctls cannot be forcibly canceled.
const (
	pfFilterBegin    = uintptr(0xc0104451)
	pfFilterCommit   = uintptr(0xc0104452)
	pfFilterRollback = uintptr(0xc0104453)
	pfFilterAdd      = uintptr(0xcc204404)
	pfFilterGet      = uintptr(0xcc204406)
	pfFilterPool     = uintptr(0xc4704433)
)

func pfFilterIoctl(ctx context.Context, fd int, operation uintptr, data []byte) error {
	if ctx.Err() != nil || fd < 0 || runtime.GOARCH != "amd64" || unsafe.Sizeof(uintptr(0)) != 8 {
		return ErrRecoveryRequired
	}
	size := 0
	switch operation {
	case pfFilterBegin, pfFilterCommit, pfFilterRollback:
		size = 16
	case pfFilterAdd, pfFilterGet:
		size = pfFilterFrameSize
	case pfFilterPool:
		size = 1136
	default:
		return ErrRecoveryRequired
	}
	if len(data) != size {
		return ErrRecoveryRequired
	}
	_, _, errno := syscall.Syscall(unix.SYS_IOCTL, uintptr(fd), operation, uintptr(unsafe.Pointer(&data[0])))
	runtime.KeepAlive(data)
	if errno != 0 {
		return errno
	}
	// Do not turn a successful COMMIT into an ambiguous cancellation error.
	// The caller knows it committed and retains durable intent on later failure.
	return nil
}

// Called only by the locked, journal-bound coordinator (or explicit native
// test fixture authority). The guard is mandatory before BEGIN and COMMIT.
func performOwnedPFFilter(ctx context.Context, anchor string, desired *pfPolicy, requireAbsent, abandon bool, guard func() error, mark func(string)) error {
	if guard == nil || ctx.Err() != nil || !strings.HasPrefix(anchor, "com.apple/legacywg-") || !hexID.MatchString(strings.TrimPrefix(anchor, "com.apple/legacywg-")) || (abandon && desired != nil) {
		return ErrRecoveryRequired
	}
	var frames []pfFilterFrame
	var err error
	if desired != nil {
		frames, err = compiledPFFilterFrames(anchor, *desired)
		if err != nil {
			return ErrRecoveryRequired
		}
	}
	if guard() != nil {
		return ErrRecoveryRequired
	}
	fd, err := openPFReferences(ctx)
	if err != nil {
		return ErrRecoveryRequired
	}
	defer unix.Close(fd)
	query := make([]byte, pfFilterFrameSize)
	copy(query[16:1040], anchor)
	expectedAnchor := append([]byte(nil), query[16:1040]...)
	err = pfFilterIoctl(ctx, fd, pfFilterGet, query)
	if err == unix.EINVAL {
		if desired == nil && !requireAbsent {
			return nil // missing cleanup/abandon leaf: never recreate it
		}
	} else if err != nil || requireAbsent || !bytes.Equal(query[16:1040], expectedAnchor) || binary.LittleEndian.Uint32(query[12:16]) > maxPFReferences+3 {
		return ErrRecoveryRequired
	}
	// mmap keeps the ioctl's nested address out of retained Go heap pointers.
	entry, err := unix.Mmap(-1, 0, 1032, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
	if err != nil {
		return ErrRecoveryRequired
	}
	defer unix.Munmap(entry)
	binary.LittleEndian.PutUint32(entry[:4], 1) // PF_RULESET_FILTER
	copy(entry[4:1028], anchor)
	header := make([]byte, 16)
	binary.LittleEndian.PutUint32(header[:4], 1) // exactly one entry
	binary.LittleEndian.PutUint32(header[4:8], 1032)
	binary.LittleEndian.PutUint64(header[8:], uint64(uintptr(unsafe.Pointer(&entry[0]))))
	if pfFilterIoctl(ctx, fd, pfFilterBegin, header) != nil {
		return ErrRecoveryRequired
	}
	if binary.LittleEndian.Uint32(entry[:4]) != 1 || !bytes.Equal(entry[4:1028], expectedAnchor) || binary.LittleEndian.Uint32(entry[1028:]) == 0 {
		return ErrRecoveryRequired // unknown returned identity is preserved
	}
	settled := false
	defer func() {
		if !settled {
			rollback, stop := context.WithTimeout(context.Background(), 2*time.Second)
			defer stop()
			_ = pfFilterIoctl(rollback, fd, pfFilterRollback, header)
			// Failure keeps the journal; no foreign/global fallback.
		}
	}()
	if mark != nil {
		mark("pf_filter_transaction_begin_kernel")
	}
	for _, frame := range frames {
		pool := make([]byte, 1136)
		copy(pool[19:1043], anchor)
		if pfFilterIoctl(ctx, fd, pfFilterPool, pool) != nil || binary.LittleEndian.Uint32(pool[4:8]) == 0 {
			return ErrRecoveryRequired
		}
		binary.LittleEndian.PutUint32(frame[4:8], binary.LittleEndian.Uint32(entry[1028:]))
		binary.LittleEndian.PutUint32(frame[8:12], binary.LittleEndian.Uint32(pool[4:8]))
		if pfFilterIoctl(ctx, fd, pfFilterAdd, frame[:]) != nil {
			return ErrRecoveryRequired
		}
	}
	if mark != nil {
		mark("pf_filter_rules_staged_kernel")
	}
	if guard() != nil {
		return ErrRecoveryRequired
	}
	operation := pfFilterCommit
	if abandon {
		operation = pfFilterRollback
	}
	if pfFilterIoctl(ctx, fd, operation, header) != nil {
		return ErrRecoveryRequired
	}
	settled = true
	if mark != nil {
		if abandon {
			mark("pf_filter_transaction_rolled_back_kernel")
		} else {
			mark("pf_filter_transaction_committed_kernel")
		}
	}
	return nil
}

// Store mutex/flock remain held by callers. Exact full record and current PF
// snapshot/reference set are re-observed, not just selected identity fields.
func (store *Store) changePFFilter(ctx context.Context, record PFRecord, before pfPolicySnapshot, references []pfReference, desired *pfPolicy, abandon bool) error {
	phase := record.Phase
	if desired != nil {
		frozen, canonical, err := store.preparePFPolicy(ctx, record, *desired)
		expected := record.RulesSHA256
		if phase == PFRuleUpdateIntent {
			expected = record.NextRulesSHA256
		}
		if err != nil || pfDigest(canonical) != expected {
			return ErrRecoveryRequired
		}
		desired = &frozen
	}
	validOwner := func() bool {
		if desired != nil {
			knownBefore := phase == PFInstallIntent && before.rules == pfDigest("") || phase == PFRuleUpdateIntent && before.rules == record.RulesSHA256
			return !abandon && knownBefore && record.PID == syscall.Getpid() && store.pfJournalOwner(record)
		}
		if abandon {
			return phase == PFRuleUpdateIntent && store.pfJournalOwner(record) && before.rules == record.RulesSHA256
		}
		return phase == PFAnchorRemovalIntent && store.pfRemovalOwner(record) && (before.rules == record.RulesSHA256 || before.rules == pfDigest(""))
	}
	guard := func() error {
		if ctx.Err() != nil || !validOwner() {
			return ErrRecoveryRequired
		}
		actual, err := store.readPF(pfJournalFile)
		pending, pendingErr := store.readPF(pfTemporaryFile)
		if err != nil || actual == nil || *actual != record || pendingErr != nil || pending != nil {
			return ErrRecoveryRequired
		}
		fd, err := openPFReferences(ctx)
		if err != nil {
			return ErrRecoveryRequired
		}
		defer unix.Close(fd)
		current, err := readPFReferences(ctx, fd)
		if err != nil || !samePFReferences(current, references) {
			return ErrRecoveryRequired
		}
		if phase == PFRuleUpdateIntent || record.ReferenceAfter > 0 {
			owned, err := selectPFReference(record, current)
			if err != nil || (phase == PFRuleUpdateIntent && owned == nil) || (phase == PFAnchorRemovalIntent && owned != nil) {
				return ErrRecoveryRequired
			}
		} else if len(current) != 0 {
			return ErrRecoveryRequired
		}
		observed, err := readPFPolicy(ctx, record.Anchor, len(current) > 0)
		check, checkErr := readPFReferences(ctx, fd)
		if err != nil || observed != before || !observed.matches(record) || checkErr != nil || !samePFReferences(current, check) || (desired != nil && store.validatePFPaths(ctx, *desired) != nil) {
			return ErrRecoveryRequired
		}
		return nil
	}
	return performOwnedPFFilter(ctx, record.Anchor, desired, phase == PFInstallIntent, abandon, guard, store.mark)
}
