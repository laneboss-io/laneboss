//go:build linux && laneboss_root_canary

package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

type credentialWalkInput struct {
	Record leaseRecord
	View   string
}

var credentialWalkStage = "input"

func init() {
	if len(os.Args) == 3 && os.Args[1] == "admin-credential-walk-canary" {
		if err := credentialWalkCanary(os.Args[2]); err != nil {
			if _, writeErr := os.Stdout.WriteString(credentialWalkStage); writeErr != nil {
				os.Exit(65)
			}
			os.Exit(63)
		}
		os.Exit(0)
	}
}

func credentialWalkCanary(input string) error {
	data, err := os.ReadFile(input)
	if err != nil {
		return err
	}
	var selected credentialWalkInput
	if err := json.Unmarshal(data, &selected); err != nil {
		return err
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return err
	}
	if err := denyOpenat2(); err != nil {
		return err
	}
	credentialWalkStage = "filter"
	fd, err := unix.Openat2(unix.AT_FDCWD, "/", &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC})
	if fd >= 0 {
		unix.Close(fd)
	}
	if !errors.Is(err, unix.EPERM) {
		return unix.EINVAL
	}
	record := selected.Record
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return err
	}
	manager := newLeaseManager(testBinding(), strings.TrimSpace(string(boot)), nil, nil)
	if err := manager.requireActive(record, storageReady); err != nil {
		return err
	}
	credentialWalkStage = "storage-recheck"
	if err := manager.syncLaunchStorage(context.Background(), &record, false); err != nil {
		return err
	}
	runtime := &credentialRuntime{manager: manager}
	request := api.CredentialProjectionRequest{Home: record.Storage.Binding.Home}
	credentialWalkStage = "parent"
	home, err := runtime.home(record, request)
	if err != nil {
		return err
	}
	defer home.Close()
	credentialWalkStage = "mode-control"
	base := storageBase(manager.binding, record)
	if err := os.Chmod(base, 0711); err != nil {
		return err
	}
	refused, modeErr := runtime.home(record, request)
	if refused != nil {
		refused.Close()
	}
	if modeErr == nil || refused != nil {
		return unix.EIO
	}
	if err := os.Chmod(base, 0710); err != nil {
		return err
	}
	if err := os.Chown(base, 0, int(record.Lease.GID)+1); err != nil {
		return err
	}
	credentialWalkStage = "owner-control"
	refused, ownerErr := runtime.home(record, request)
	if refused != nil {
		refused.Close()
	}
	if ownerErr == nil || refused != nil {
		return unix.EIO
	}
	if err := os.Chown(base, 0, int(record.Lease.GID)); err != nil {
		return err
	}
	credentialWalkStage = "destination-parent"
	parent, name, err := credentialParent(home, ".codex/auth.json", record.Lease.UID, record.Lease.GID, 0700)
	if err != nil {
		return err
	}
	defer parent.Close()
	credentialWalkStage = "destination"
	fd, err = reserveCredentialFile(parent, name, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "credential-walk-destination")
	const value = "ordinary credential path canary"
	if n, err := file.WriteString(value); err != nil || n != len(value) {
		file.Close()
		return unix.EIO
	}
	if err := errors.Join(file.Chown(int(record.Lease.UID), int(record.Lease.GID)), file.Chmod(0600), file.Close()); err != nil {
		return err
	}
	projected := filepath.Join(selected.View, "home/lane")
	credentialWalkStage = "view-setup"
	if err := unix.Mount(dataFD(home), projected, "", unix.MS_BIND, ""); err != nil {
		return err
	}
	defer unix.Unmount(projected, 0)
	root, err := os.Open(selected.View)
	if err != nil {
		return err
	}
	defer root.Close()
	credentialWalkStage = "view"
	view, leaf, err := credentialParentInView(root, ".codex/auth.json")
	if err != nil {
		return err
	}
	defer view.Close()
	var actual, expected unix.Stat_t
	if unix.Fstat(int(view.Fd()), &actual) != nil || unix.Fstat(int(parent.Fd()), &expected) != nil ||
		actual.Dev != expected.Dev || actual.Ino != expected.Ino || leaf != name {
		return unix.EIO
	}
	opened, err := dataFile(view, leaf, false)
	if err != nil {
		return err
	}
	got, readErr := io.ReadAll(opened)
	if err := errors.Join(readErr, opened.Close()); err != nil || string(got) != value {
		return unix.EIO
	}
	if err := unix.Symlinkat(".codex", int(home.Fd()), "linked"); err != nil {
		return err
	}
	credentialWalkStage = "link-control"
	linked, _, err := credentialParentInView(root, "linked/auth.json")
	if linked != nil {
		linked.Close()
	}
	if err == nil || linked != nil {
		return unix.EIO
	}
	return errors.Join(unix.Unlinkat(int(home.Fd()), "linked", 0), unix.Unlinkat(int(parent.Fd()), name, 0),
		unix.Unlinkat(int(home.Fd()), ".codex", unix.AT_REMOVEDIR))
}

func TestCredStagedWalk(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("credential stage canary requires disposable Linux root")
	}
	_, record, _ := storageFixture(t)
	binding := testBinding()
	id, err := randomID("credential-walk-")
	if err != nil {
		t.Fatal(err)
	}
	record.Lease.ID, record.Lease.UID, record.Lease.GID = id, binding.Lanes[0].UID, binding.Lanes[0].GID
	record.Storage.Binding.LeaseID = id
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	record.BootID = strings.TrimSpace(string(boot))
	journal, err := os.OpenRoot(privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := journal.Close(); err != nil {
			t.Error(err)
		}
	})
	store := &fileLeaseStore{root: journal, owner: uint32(os.Geteuid())}
	manager := newLeaseManager(binding, record.BootID, store, nil)
	if err := manager.save(record); err != nil {
		t.Fatal("credential stage could not retain its current-boot lease", err)
	}
	record, err = manager.findActive(id, storageInitializing)
	if err != nil {
		t.Fatal("credential stage did not acquire its actual active lease", err)
	}
	if err := os.MkdirAll(filepath.Dir(storageBase(binding, record)), 0700); err != nil {
		t.Fatal(err)
	}
	if err := manager.syncLaunchStorage(context.Background(), &record, true); err != nil {
		t.Fatal("credential stage prerequisite could not retain its actual storage", err)
	}
	if err := manager.save(record); err != nil {
		t.Fatal(err)
	}
	record, err = manager.findActive(id, storageReady)
	if err != nil {
		t.Fatal("credential stage did not retain ready active storage", err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			return // Preserve failed source/storage evidence for the supervisor.
		}
		base := storageBase(binding, record)
		for _, item := range record.Storage.Directories {
			if err := os.Remove(filepath.Join(base, string(item.ID))); err != nil {
				t.Error(err)
				return
			}
		}
		if err := os.Remove(base); err != nil {
			t.Error(err)
		}
	})
	view := filepath.Join(privateTestDir(t), "view")
	if err := os.MkdirAll(filepath.Join(view, "home/lane"), 0700); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(credentialWalkInput{Record: record, View: view})
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(privateTestDir(t), "credential-walk.json")
	if err := os.WriteFile(input, raw, 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(readAheadContext(t), "/proc/self/exe", "admin-credential-walk-canary", input)
	command.Env = []string{}
	command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS}
	if observed, err := command.Output(); err != nil {
		stage := string(observed)
		switch stage {
		case "input", "filter", "storage-recheck", "parent", "mode-control", "owner-control", "destination-parent", "destination", "view-setup", "view", "link-control":
		default:
			stage = "unobserved"
		}
		t.Fatalf("acceptance: staged credential paths failed under actual openat2 EPERM: stage=%s err=%v", stage, err)
	}
}
