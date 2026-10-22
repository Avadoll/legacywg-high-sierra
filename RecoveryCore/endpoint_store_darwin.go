package recoverycore

import (
	"io"
	"os"

	"golang.org/x/sys/unix"
)

const endpointJournalFile = "endpoint-routes.json"
const endpointTemporaryFile = "endpoint-routes.new"

func (store *Store) endpointResidue() bool {
	for _, name := range []string{endpointJournalFile, endpointTemporaryFile} {
		var status unix.Stat_t
		if unix.Fstatat(store.directory, name, &status, unix.AT_SYMLINK_NOFOLLOW) != unix.ENOENT {
			return true
		}
	}
	return false
}

func (store *Store) readEndpointRoutes(name string) (*endpointRouteRecord, error) {
	if store.closed || (name != endpointJournalFile && name != endpointTemporaryFile) {
		return nil, ErrRecoveryRequired
	}
	fd, err := unix.Openat(store.directory, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err == unix.ENOENT {
		return nil, nil
	}
	if err != nil {
		return nil, ErrRecoveryRequired
	}
	file := os.NewFile(uintptr(fd), "owned endpoint route record")
	defer file.Close()
	var status unix.Stat_t
	if !ownedFile(fd) || unix.Fstat(fd, &status) != nil || status.Size < 1 || status.Size > maxEndpointRecordBytes {
		return nil, ErrRecoveryRequired
	}
	data, err := io.ReadAll(io.LimitReader(file, maxEndpointRecordBytes+1))
	if err != nil || int64(len(data)) != status.Size {
		return nil, ErrRecoveryRequired
	}
	record, err := decodeEndpointRoutes(data)
	if err != nil {
		return nil, ErrRecoveryRequired
	}
	return &record, nil
}

func (store *Store) writeEndpointRoutes(record endpointRouteRecord) error {
	if store.closed || record.Boot != store.boot || (record.PID != os.Getpid() && processAlive(record.PID)) {
		return ErrRecoveryRequired
	}
	data, err := encodeEndpointRoutes(record)
	if err != nil {
		return ErrRecoveryRequired
	}
	before, err := store.readEndpointRoutes(endpointJournalFile)
	if err != nil {
		return ErrRecoveryRequired
	}
	if before == nil {
		if record.PID != os.Getpid() {
			return ErrRecoveryRequired
		}
		for _, entry := range record.Routes {
			if entry.Phase != endpointPlanned {
				return ErrRecoveryRequired
			}
		}
	} else if !endpointTransition(*before, record) {
		return ErrRecoveryRequired
	}
	fd, err := unix.Openat(store.directory, endpointTemporaryFile, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return ErrRecoveryRequired
	}
	file := os.NewFile(uintptr(fd), "owned endpoint route temporary")
	defer file.Close()
	if !ownedFile(fd) {
		return ErrRecoveryRequired
	}
	store.mark("endpoint_temporary_created")
	if n, err := file.Write(data); err != nil || n != len(data) || fullSync(fd) != nil {
		return ErrRecoveryRequired
	}
	store.mark("endpoint_temporary_synced")
	if unix.Renameat(store.directory, endpointTemporaryFile, store.directory, endpointJournalFile) != nil {
		return ErrRecoveryRequired
	}
	store.mark("endpoint_renamed")
	if unix.Fsync(store.directory) != nil || fullSync(fd) != nil {
		return ErrRecoveryRequired
	}
	store.mark("endpoint_directory_synced")
	return nil
}
