package recoverycore

import (
	"io"
	"os"

	"golang.org/x/sys/unix"
)

const pfJournalFile = "pf.json"
const pfTemporaryFile = "pf.new"

// Used only by the future guard coordinator under the existing exclusive
// Store lock. No runtime request supplies paths or bypasses fixed ownership.
// Until kernel PF reconciliation exists, any PF document blocks ordinary
// utun/DNS recovery and remains untouched, even on another boot.
func (store *Store) pfResidue() bool {
	for _, name := range []string{pfJournalFile, pfTemporaryFile} {
		var status unix.Stat_t
		if err := unix.Fstatat(store.directory, name, &status, unix.AT_SYMLINK_NOFOLLOW); err != unix.ENOENT {
			return true
		}
	}
	return false
}

func (store *Store) readPF(name string) (*PFRecord, error) {
	if store.closed || (name != pfJournalFile && name != pfTemporaryFile) {
		return nil, ErrRecoveryRequired
	}
	fd, err := unix.Openat(store.directory, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err == unix.ENOENT {
		return nil, nil
	}
	if err != nil {
		return nil, ErrRecoveryRequired
	}
	file := os.NewFile(uintptr(fd), "owned PF recovery record")
	defer file.Close()
	var status unix.Stat_t
	if !ownedFile(fd) || unix.Fstat(fd, &status) != nil || status.Size < 1 || status.Size > MaxRecordBytes {
		return nil, ErrRecoveryRequired
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxRecordBytes+1))
	if err != nil || int64(len(data)) != status.Size {
		return nil, ErrRecoveryRequired
	}
	record, err := DecodePF(data)
	if err != nil {
		return nil, ErrRecoveryRequired
	}
	return &record, nil
}

// Private storage primitive; it does not install/enable/remove PF policy.
// Future guard integration must verify the external effect before choosing
// its phase. Failed or partial commits are retained for explicit attention.
func (store *Store) writePF(record PFRecord) error {
	if store.closed || record.Boot != store.boot || record.PID != os.Getpid() {
		return ErrRecoveryRequired
	}
	data, err := EncodePF(record)
	if err != nil {
		return ErrRecoveryRequired
	}
	before, err := store.readPF(pfJournalFile)
	if err != nil {
		return ErrRecoveryRequired
	}
	if before == nil {
		if record.Phase != PFInstallIntent {
			return ErrRecoveryRequired
		}
	} else {
		if validatePFTransition(*before, record) != nil {
			return ErrRecoveryRequired
		}
	}
	fd, err := unix.Openat(store.directory, pfTemporaryFile, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return ErrRecoveryRequired
	}
	file := os.NewFile(uintptr(fd), "owned PF recovery temporary")
	defer file.Close()
	if !ownedFile(fd) {
		return ErrRecoveryRequired
	}
	store.mark("pf_temporary_created")
	if n, err := file.Write(data); err != nil || n != len(data) || fullSync(fd) != nil {
		return ErrRecoveryRequired
	}
	store.mark("pf_temporary_synced")
	if unix.Renameat(store.directory, pfTemporaryFile, store.directory, pfJournalFile) != nil {
		return ErrRecoveryRequired
	}
	store.mark("pf_renamed")
	if unix.Fsync(store.directory) != nil || fullSync(fd) != nil {
		return ErrRecoveryRequired
	}
	store.mark("pf_directory_synced")
	return nil
}
