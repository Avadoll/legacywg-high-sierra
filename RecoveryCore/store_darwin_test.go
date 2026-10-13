package recoverycore

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

func TestMain(m *testing.M) {
	if probe := os.Getenv("LEGACYWG_ACL_TEST_HELPER"); probe != "" {
		aclProbePath = probe
	}
	os.Exit(m.Run())
}

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("separate native privileged test invocation required")
	}
}

func directoryStore(t *testing.T, path string) (*Store, error) {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal("test directory open failed")
	}
	store, err := openDirectory(fd, testBoot)
	if err != nil {
		unix.Close(fd)
	}
	return store, err
}

func ownedTestDirectory(t *testing.T) string {
	t.Helper()
	requireRoot(t)
	path := t.TempDir()
	if os.Chmod(path, 0700) != nil {
		t.Fatal("test directory permissions failed")
	}
	return path
}

func TestRootACLDescriptor(t *testing.T) {
	path := ownedTestDirectory(t)
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal("metadata fixture open failed")
	}
	defer unix.Close(fd)
	if !noExtendedACL(fd) {
		t.Fatal("ACL-free inode rejected")
	}
	if exec.Command(aclProbePath, "--check-no-acl").Run() == nil {
		t.Fatal("missing inherited descriptor accepted")
	}
	if exec.Command("/bin/chmod", "+a", "everyone allow read", path).Run() != nil {
		t.Fatal("metadata ACL fixture failed")
	}
	if noExtendedACL(fd) {
		t.Fatal("ACL grant accepted")
	}
	if exec.Command("/bin/chmod", "-N", path).Run() != nil || !noExtendedACL(fd) {
		t.Fatal("ACL removal on owned fixture not observed")
	}
}

func TestRootJournalDurabilityAndExclusiveLock(t *testing.T) {
	path := ownedTestDirectory(t)
	store, err := directoryStore(t, path)
	if err != nil {
		t.Fatal("store open failed")
	}
	defer store.Close()
	if store.begin() != nil {
		t.Fatal("durable intent failed")
	}
	if other, err := directoryStore(t, path); err == nil {
		other.Close()
		t.Fatal("concurrent writer accepted")
	}
	data, err := os.ReadFile(filepath.Join(path, journalFile))
	if err != nil {
		t.Fatal("intent not persisted")
	}
	if _, err = Decode(data); err != nil {
		t.Fatal("persisted intent invalid")
	}
	for _, name := range []string{journalFile, lockFile} {
		info, err := os.Lstat(filepath.Join(path, name))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("private file permissions incorrect")
		}
	}
	lock, directory := store.lock, store.directory
	if store.Finish() != nil || store.Finish() != nil {
		t.Fatal("finish not idempotent")
	}
	if _, err := unix.FcntlInt(uintptr(lock), unix.F_GETFD, 0); err != unix.EBADF {
		t.Fatal("lock FD leaked")
	}
	if _, err := unix.FcntlInt(uintptr(directory), unix.F_GETFD, 0); err != unix.EBADF {
		t.Fatal("directory FD leaked")
	}
	if _, err := os.Lstat(filepath.Join(path, journalFile)); !os.IsNotExist(err) {
		t.Fatal("completed record remains")
	}
	store, err = directoryStore(t, path)
	if err != nil {
		t.Fatal("new transaction cannot lock")
	}
	defer store.Close()
	if store.begin() != nil || store.Finish() != nil {
		t.Fatal("new transaction failed")
	}
}

func TestRootJournalRejectsUntrustedFiles(t *testing.T) {
	for _, kind := range []string{"directory_mode", "directory_acl", "lock_acl", "lock_symlink", "lock_hardlink", "record_acl", "record_symlink", "record_hardlink", "record_fifo", "record_mode", "record_partial", "unknown_schema", "mismatched_records"} {
		t.Run(kind, func(t *testing.T) {
			path := ownedTestDirectory(t)
			foreign := filepath.Join(t.TempDir(), "foreign")
			marker := []byte("unchanged foreign file")
			if os.WriteFile(foreign, marker, 0600) != nil {
				t.Fatal("foreign fixture write failed")
			}
			if kind == "directory_mode" {
				os.Chmod(path, 0755)
			}
			if kind == "directory_acl" {
				if exec.Command("/bin/chmod", "+a", "everyone allow read", path).Run() != nil {
					t.Fatal("directory ACL fixture failed")
				}
			}
			if kind == "lock_acl" {
				lock := filepath.Join(path, lockFile)
				if os.WriteFile(lock, marker, 0600) != nil || exec.Command("/bin/chmod", "+a", "everyone allow read", lock).Run() != nil {
					t.Fatal("lock ACL fixture failed")
				}
			}
			if kind == "lock_symlink" {
				if os.Symlink(foreign, filepath.Join(path, lockFile)) != nil {
					t.Fatal("symlink fixture failed")
				}
			}
			if kind == "lock_hardlink" {
				if os.Link(foreign, filepath.Join(path, lockFile)) != nil {
					t.Fatal("hardlink fixture failed")
				}
			}
			store, err := directoryStore(t, path)
			if strings.HasPrefix(kind, "lock_") || strings.HasPrefix(kind, "directory_") {
				if err == nil {
					store.Close()
					t.Fatal("untrusted directory/lock accepted")
				}
			} else {
				if err != nil {
					t.Fatal("store fixture failed")
				}
				defer store.Close()
				recordPath := filepath.Join(path, journalFile)
				switch kind {
				case "record_acl":
					record, _ := NewRecord(testBoot)
					record.PID = 2147483647
					data, _ := Encode(record)
					err = os.WriteFile(recordPath, data, 0600)
					if err == nil {
						err = exec.Command("/bin/chmod", "+a", "everyone allow read", recordPath).Run()
					}
				case "record_symlink":
					err = os.Symlink(foreign, recordPath)
				case "record_hardlink":
					err = os.Link(foreign, recordPath)
				case "record_fifo":
					err = unix.Mkfifo(recordPath, 0600)
				case "record_mode":
					err = os.WriteFile(recordPath, marker, 0644)
				case "record_partial":
					err = os.WriteFile(recordPath, []byte(`{"version":`), 0600)
				case "unknown_schema":
					err = os.WriteFile(recordPath, []byte(`{"version":2,"private_marker":"not exportable"}`), 0600)
				case "mismatched_records":
					record, _ := NewRecord(testBoot)
					record.PID = 2147483647
					data, _ := Encode(record)
					err = os.WriteFile(recordPath, data, 0600)
					other, _ := NewRecord(testBoot)
					other.PID = 2147483647
					data, _ = Encode(other)
					if err == nil {
						err = os.WriteFile(filepath.Join(path, temporaryFile), data, 0600)
					}
				}
				if err != nil {
					t.Fatal("untrusted record fixture failed")
				}
				if store.begin() == nil {
					t.Fatal("unsafe recovery accepted")
				}
				if _, err := os.Lstat(recordPath); err != nil {
					t.Fatal("ambiguous record removed")
				}
			}
			after, err := os.ReadFile(foreign)
			if err != nil || string(after) != string(marker) {
				t.Fatal("foreign file modified")
			}
		})
	}
}

func TestRootJournalLiveAndReusedInterface(t *testing.T) {
	path := ownedTestDirectory(t)
	device, err := tun.CreateTUN("utun", 1420)
	if err != nil {
		t.Fatal("owned native fixture failed")
	}
	defer device.Close()
	name, err := device.Name()
	if err != nil {
		t.Fatal("native name unavailable")
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatal("native index unavailable")
	}
	record, _ := NewRecord(testBoot)
	record.PID = 2147483647
	record, err = record.Advance(InterfaceCreated, name, iface.Index, false)
	if err != nil {
		t.Fatal("fixture record failed")
	}
	data, _ := Encode(record)
	if os.WriteFile(filepath.Join(path, journalFile), data, 0600) != nil {
		t.Fatal("fixture journal failed")
	}
	store, err := directoryStore(t, path)
	if err != nil {
		t.Fatal("store open failed")
	}
	if store.begin() == nil {
		store.Close()
		t.Fatal("existing interface treated as owned stale state")
	}
	store.Close()
	// A same-name, different-index interface is foreign. Recovery may discard
	// the old document but must not issue a kernel deletion against that name.
	record.InterfaceIndex++
	data, _ = Encode(record)
	if os.WriteFile(filepath.Join(path, journalFile), data, 0600) != nil {
		t.Fatal("reused identity fixture failed")
	}
	store, err = directoryStore(t, path)
	if err != nil {
		t.Fatal("store reopen failed")
	}
	defer store.Close()
	if store.begin() != nil || store.Finish() != nil {
		t.Fatal("stale identity record not recoverable")
	}
	current, err := net.InterfaceByName(name)
	if err != nil || current.Index != iface.Index {
		t.Fatal("foreign interface changed")
	}
}

func TestRootCrashChild(t *testing.T) {
	path, stage := os.Getenv("LEGACYWG_JOURNAL_TEST_DIR"), os.Getenv("LEGACYWG_JOURNAL_TEST_STAGE")
	if path == "" || stage == "" {
		t.Skip("subprocess crash fixture only")
	}
	requireRoot(t)
	store, err := directoryStore(t, path)
	if err != nil {
		t.Fatal("child store failed")
	}
	defer store.Close()
	ready := func() {
		fmt.Fprintln(os.Stdout, "READY")
		for {
			time.Sleep(time.Minute)
		}
	}
	if stage != "live_utun" {
		store.checkpoint = func(current string) {
			if current == stage {
				ready()
			}
		}
	}
	if store.begin() != nil {
		t.Fatal("child intent failed")
	}
	if stage == "live_utun" {
		device, err := tun.CreateTUN("utun", 1420)
		if err != nil {
			t.Fatal("child native interface failed")
		}
		defer device.Close()
		name, err := device.Name()
		if err != nil {
			t.Fatal("child interface name failed")
		}
		iface, err := net.InterfaceByName(name)
		if err != nil || store.MarkInterface(name, iface.Index) != nil {
			t.Fatal("child interface checkpoint failed")
		}
		ready()
	}
	t.Fatal("requested crash checkpoint was not reached")
}

func TestRootCrashRecovery(t *testing.T) {
	for _, stage := range []string{"temporary_created", "temporary_synced", "renamed", "directory_synced", "live_utun"} {
		t.Run(stage, func(t *testing.T) {
			path := ownedTestDirectory(t)
			executable, err := os.Executable()
			if err != nil {
				t.Fatal("test executable unavailable")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, executable, "-test.run=^TestRootCrashChild$", "-test.v")
			command.Env = append(os.Environ(), "LEGACYWG_JOURNAL_TEST_DIR="+path, "LEGACYWG_JOURNAL_TEST_STAGE="+stage)
			output, err := command.StdoutPipe()
			if err != nil {
				t.Fatal("child pipe failed")
			}
			if command.Start() != nil {
				t.Fatal("child start failed")
			}
			scanner := bufio.NewScanner(output)
			ready := false
			for scanner.Scan() {
				if scanner.Text() == "READY" {
					ready = true
					break
				}
			}
			if !ready {
				command.Wait()
				t.Fatal("child did not reach durable checkpoint")
			}
			if command.Process.Kill() != nil {
				command.Wait()
				t.Fatal("controlled SIGKILL failed")
			}
			if command.Wait() == nil {
				t.Fatal("child was not interrupted")
			}
			store, err := directoryStore(t, path)
			if err != nil {
				t.Fatal("crash recovery cannot lock")
			}
			defer store.Close()
			err = store.begin()
			if stage == "temporary_created" {
				if err == nil {
					t.Fatal("partial unknown record silently discarded")
				}
				if _, err := os.Lstat(filepath.Join(path, temporaryFile)); err != nil {
					t.Fatal("partial record not preserved")
				}
			} else if err != nil || store.Finish() != nil {
				t.Fatal("complete own stale checkpoint not recovered")
			}
		})
	}
}
