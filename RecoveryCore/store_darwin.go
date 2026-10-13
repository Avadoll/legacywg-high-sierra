package recoverycore

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const journalFile = "utun.json"
const temporaryFile = "utun.new"
const lockFile = "lock"

// Fixed verified component in production. Only native Go tests override this
// private variable with their compiled probe; no runtime setting exposes it.
var aclProbePath = "/Library/Application Support/LegacyWG/legacywg-network"

type Store struct {
	directory int
	lock      int
	boot      string
	record    Record
	closed    bool
	// Only compiled native tests install a checkpoint callback; no callback
	// or crash-injection operation is reachable from a production request.
	checkpoint func(string)
}

// Begin opens the fixed root-owned directory, exclusively locks it, refuses
// ambiguous recovery and durably saves an intent before utun creation.
func Begin() (*Store, error) {
	store, err := openFixedStore(true)
	if err != nil {
		return nil, ErrRecoveryRequired
	}
	if err = store.begin(); err != nil {
		store.Close()
		return nil, ErrRecoveryRequired
	}
	return store, nil
}

// Reconcile examines the fixed owned journal without creating a connection
// intent. Missing State is a clean result. It only removes verified stale
// documents, never kernel interfaces/routes, DNS preferences or PF state.
func Reconcile() error {
	store, err := openFixedStore(false)
	if err != nil {
		return ErrRecoveryRequired
	}
	if store == nil {
		return nil
	}
	defer store.Close()
	return store.reconcile()
}

func (store *Store) reconcile() error {
	if store.closed || store.recover() != nil || fullSync(store.lock) != nil {
		return ErrRecoveryRequired
	}
	return nil
}

func openFixedStore(create bool) (*Store, error) {
	if os.Geteuid() != 0 {
		return nil, ErrRecoveryRequired
	}
	boot, err := unix.Sysctl("kern.bootsessionuuid")
	if err != nil {
		return nil, ErrRecoveryRequired
	}
	boot = strings.ToLower(strings.TrimSpace(strings.TrimRight(boot, "\x00")))
	if !bootID.MatchString(boot) {
		return nil, ErrRecoveryRequired
	}
	parent, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrRecoveryRequired
	}
	for _, part := range []string{"Library", "Application Support", "LegacyWG"} {
		child, err := unix.Openat(parent, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(parent)
		if err != nil {
			return nil, ErrRecoveryRequired
		}
		parent = child
		var status unix.Stat_t
		if unix.Fstat(parent, &status) != nil || status.Uid != 0 || status.Mode&0022 != 0 || !noExtendedACL(parent) {
			unix.Close(parent)
			return nil, ErrRecoveryRequired
		}
	}
	if create {
		if err = unix.Mkdirat(parent, "State", 0700); err != nil && err != unix.EEXIST {
			unix.Close(parent)
			return nil, ErrRecoveryRequired
		}
	}
	directory, err := unix.Openat(parent, "State", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	unix.Close(parent)
	if !create && err == unix.ENOENT {
		return nil, nil
	}
	if err != nil {
		return nil, ErrRecoveryRequired
	}
	store, err := openDirectory(directory, boot)
	if err != nil {
		unix.Close(directory)
		return nil, ErrRecoveryRequired
	}
	return store, nil
}

// The private constructor takes an already open directory FD. Native tests
// use their own root-owned TempDir; production accepts no caller-supplied path.
func openDirectory(directory int, boot string) (*Store, error) {
	var status unix.Stat_t
	if !bootID.MatchString(boot) || unix.Fstat(directory, &status) != nil || status.Uid != 0 || status.Mode&unix.S_IFMT != unix.S_IFDIR || status.Mode&0777 != 0700 || !noExtendedACL(directory) {
		return nil, ErrRecoveryRequired
	}
	lock, err := unix.Openat(directory, lockFile, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, ErrRecoveryRequired
	}
	if !ownedFile(lock) || unix.Flock(lock, unix.LOCK_EX|unix.LOCK_NB) != nil {
		unix.Close(lock)
		return nil, ErrRecoveryRequired
	}
	return &Store{directory: directory, lock: lock, boot: boot}, nil
}

func ownedFile(fd int) bool {
	var status unix.Stat_t
	return unix.Fstat(fd, &status) == nil && status.Uid == 0 && status.Nlink == 1 && status.Mode&unix.S_IFMT == unix.S_IFREG && status.Mode&0777 == 0600 && noExtendedACL(fd)
}

// BSD mode bits alone do not describe extended ACL grants. The verified native
// component calls fstatx_np on our inherited descriptor. Any ACL or API
// failure is refused; /dev/fd metadata listings do not expose inode ACLs.
func noExtendedACL(fd int) bool {
	duplicate, err := unix.Dup(fd)
	if err != nil {
		return false
	}
	unix.CloseOnExec(duplicate)
	file := os.NewFile(uintptr(duplicate), "owned recovery metadata")
	defer file.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, aclProbePath, "--check-no-acl")
	command.ExtraFiles = []*os.File{file}
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	return command.Run() == nil
}

func (store *Store) read(name string) (*Record, error) {
	fd, err := unix.Openat(store.directory, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err == unix.ENOENT {
		return nil, nil
	}
	if err != nil {
		return nil, ErrRecoveryRequired
	}
	file := os.NewFile(uintptr(fd), "owned recovery record")
	defer file.Close()
	if !ownedFile(fd) {
		return nil, ErrRecoveryRequired
	}
	var status unix.Stat_t
	if unix.Fstat(fd, &status) != nil || status.Size <= 0 || status.Size > MaxRecordBytes {
		return nil, ErrRecoveryRequired
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxRecordBytes+1))
	if err != nil || int64(len(data)) != status.Size {
		return nil, ErrRecoveryRequired
	}
	record, err := Decode(data)
	if err != nil {
		return nil, ErrRecoveryRequired
	}
	return &record, nil
}

func processAlive(pid int) bool {
	err := unix.Kill(pid, 0)
	return err == nil || !errors.Is(err, unix.ESRCH)
}

func interfaceGone(record Record) bool {
	if record.Interface == "" {
		return true
	}
	iface, err := net.InterfaceByName(record.Interface)
	if err != nil {
		// Distinguish a failed enumeration from a genuinely absent name.
		interfaces, err := net.Interfaces()
		if err != nil {
			return false
		}
		for _, iface := range interfaces {
			if iface.Name == record.Interface {
				return false
			}
		}
		return true
	}
	// A different interface instance belongs to someone else. Never delete it.
	return iface.Index != record.InterfaceIndex
}

func (store *Store) recover() error {
	if store.pfResidue() {
		return ErrRecoveryRequired
	}
	records := make(map[string]*Record)
	for _, name := range []string{journalFile, temporaryFile} {
		record, err := store.read(name)
		if err != nil {
			return ErrRecoveryRequired
		}
		if record == nil {
			continue
		}
		if record.Boot == store.boot && (processAlive(record.PID) || !interfaceGone(*record)) {
			return ErrRecoveryRequired
		}
		records[name] = record
	}
	if main, temp := records[journalFile], records[temporaryFile]; main != nil && temp != nil && (main.ID != temp.ID || main.Boot != temp.Boot || main.PID != temp.PID) {
		return ErrRecoveryRequired
	}
	for _, name := range []string{journalFile, temporaryFile} {
		if records[name] == nil {
			continue
		}
		// Only our regular, root-only record is removed. No kernel route,
		// process, DNS preference or foreign interface is touched by recovery.
		if unix.Unlinkat(store.directory, name, 0) != nil {
			return ErrRecoveryRequired
		}
	}
	if unix.Fsync(store.directory) != nil {
		return ErrRecoveryRequired
	}
	return nil
}

func (store *Store) begin() error {
	if store.closed || store.recover() != nil {
		return ErrRecoveryRequired
	}
	record, err := NewRecord(store.boot)
	if err != nil {
		return ErrRecoveryRequired
	}
	store.record = record
	return store.write(record)
}

func (store *Store) mark(checkpoint string) {
	if store.checkpoint != nil {
		store.checkpoint(checkpoint)
	}
}

func fullSync(fd int) error {
	if unix.Fsync(fd) != nil {
		return ErrRecoveryRequired
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_FULLFSYNC, 0); err != nil {
		return ErrRecoveryRequired
	}
	return nil
}

func (store *Store) write(record Record) error {
	if store.closed {
		return ErrRecoveryRequired
	}
	data, err := Encode(record)
	if err != nil {
		return ErrRecoveryRequired
	}
	before, err := store.read(journalFile)
	if err != nil || (before == nil && record.Phase != Intent) || (before != nil && (before.ID != record.ID || before.Boot != record.Boot || before.PID != record.PID)) {
		return ErrRecoveryRequired
	}
	fd, err := unix.Openat(store.directory, temporaryFile, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return ErrRecoveryRequired
	}
	file := os.NewFile(uintptr(fd), "owned recovery temporary record")
	defer file.Close()
	if !ownedFile(fd) {
		return ErrRecoveryRequired
	}
	store.mark("temporary_created")
	if n, err := file.Write(data); err != nil || n != len(data) || fullSync(fd) != nil {
		return ErrRecoveryRequired
	}
	store.mark("temporary_synced")
	if unix.Renameat(store.directory, temporaryFile, store.directory, journalFile) != nil {
		return ErrRecoveryRequired
	}
	store.record = record
	store.mark("renamed")
	if unix.Fsync(store.directory) != nil || fullSync(fd) != nil {
		return ErrRecoveryRequired
	}
	store.mark("directory_synced")
	return nil
}

func (store *Store) MarkInterface(name string, index int) error {
	record, err := store.record.Advance(InterfaceCreated, name, index, false)
	if err != nil {
		return ErrRecoveryRequired
	}
	return store.write(record)
}

func (store *Store) MarkConfigured(dns bool) error {
	record, err := store.record.Advance(Configured, store.record.Interface, store.record.InterfaceIndex, dns)
	if err != nil {
		return ErrRecoveryRequired
	}
	return store.write(record)
}

// Finish is idempotent for the same store and only succeeds once its original
// utun has disappeared. The lock inode stays fixed to avoid split-lock races.
func (store *Store) Finish() error {
	if store.closed {
		return nil
	}
	if store.pfResidue() {
		return ErrRecoveryRequired
	}
	if !interfaceGone(store.record) {
		return ErrRecoveryRequired
	}
	remove := []string{}
	for _, name := range []string{journalFile, temporaryFile} {
		record, err := store.read(name)
		if err != nil {
			return ErrRecoveryRequired
		}
		if record != nil {
			if record.ID != store.record.ID || record.Boot != store.boot || !interfaceGone(*record) {
				return ErrRecoveryRequired
			}
			remove = append(remove, name)
		}
	}
	for _, name := range remove {
		if unix.Unlinkat(store.directory, name, 0) != nil {
			return ErrRecoveryRequired
		}
	}
	if unix.Fsync(store.directory) != nil || fullSync(store.lock) != nil {
		return ErrRecoveryRequired
	}
	store.Close()
	return nil
}

func (store *Store) Close() {
	if store.closed {
		return
	}
	store.closed = true
	unix.Close(store.lock)
	unix.Close(store.directory)
}
