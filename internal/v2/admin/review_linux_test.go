//go:build linux

package admin

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// These are component controls with actual pipes/files/native wait statuses.
// They do not substitute for the installed cgroup or authenticated drain row.
func TestCaptureEOF(t *testing.T) {
	for _, fault := range []string{"clean", "missing", "failure", "exit"} {
		t.Run(fault, func(t *testing.T) {
			root, binding, writes, finished := spoolFixture(t, 1024)
			for _, file := range writes {
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if err := waitSpool(t, finished); err != nil {
				t.Fatal(err)
			}
			program := "/usr/bin/true"
			if fault == "exit" {
				program = "/usr/bin/false"
			}
			cmd := exec.Command(program)
			err := cmd.Run()
			var exited *exec.ExitError
			if err != nil && !errors.As(err, &exited) {
				t.Fatal(err)
			}
			done := make(chan struct{})
			close(done)
			binding.ProducerGeneration = "component-wait"
			gate := &nativeGate{done: done, state: cmd.ProcessState, waitErr: err, innerGeneration: binding.ProducerGeneration}
			capture := &nativeCapture{gate: gate, spool: root, binding: binding}
			if fault == "missing" || fault == "failure" {
				marker, err := readSpool(root, binding)
				if err != nil {
					t.Fatal(err)
				}
				if fault == "missing" {
					marker.Positions[1].PipeEOF = false
				} else {
					marker.Failure = "pipe_read"
				}
				raw, err := json.Marshal(marker)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root.Name(), "marker"), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			stopped := false
			capture.producerEnded(context.Background(), func() error { stopped = true; return nil })
			if fault == "clean" {
				if stopped || capture.Observe(context.Background()) != nil {
					t.Fatal("acceptance: clean pipe EOF stopped or invalidated capture")
				}
				manager := &leaseManager{captures: map[api.ID]ownedCapture{binding.ID: capture}}
				jobs, err := manager.captureJobs(context.Background(), leaseRecord{Captures: []captureJournal{{Binding: binding, Native: &captureNativeJournal{}}}})
				if jobs != 1 || err == nil || !strings.Contains(err.Error(), "no authenticated service drain acknowledgement") {
					t.Fatal("acceptance: clean EOF fabricated a drain acknowledgement")
				}
			} else if !stopped || capture.Observe(context.Background()) == nil {
				t.Fatal("acceptance: failed capture producer escaped stop")
			}
		})
	}
}

func TestDataParent(t *testing.T) {
	base, outside := privateTestDir(t), privateTestDir(t)
	if err := os.Mkdir(filepath.Join(base, "d"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(base, "d"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(".", filepath.Join(base, "d", "link")); err != nil {
		t.Fatal(err)
	}
	root, err := os.Open(base)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	manifest := api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{{Path: "d/link", Kind: "symlink", Mode: 0777, LinkTarget: "."}}}
	if err := dataReturn(context.Background(), root, manifest, uint32(os.Geteuid()), uint32(os.Getegid())); err != nil {
		t.Fatalf("safe nested baseline: %v", err)
	}
	if err := os.Symlink(".", filepath.Join(outside, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(base, "d"), filepath.Join(base, "old")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(base, "d")); err != nil {
		t.Fatal(err)
	}
	var before, after unix.Stat_t
	if err := unix.Lstat(filepath.Join(outside, "link"), &before); err != nil {
		t.Fatal(err)
	}
	watch, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(watch)
	if _, err := unix.InotifyAddWatch(watch, filepath.Join(outside, "link"), unix.IN_ATTRIB|unix.IN_DONT_FOLLOW); err != nil {
		t.Fatal(err)
	}
	err = dataReturn(context.Background(), root, manifest, uint32(os.Geteuid()), uint32(os.Getegid()))
	if statErr := unix.Lstat(filepath.Join(outside, "link"), &after); statErr != nil {
		t.Fatal(statErr)
	}
	// Inotify observes even a chown to the existing UID/GID on a filesystem
	// whose coarse ctime clock would otherwise hide the mutation.
	var events [4096]byte
	n, watchErr := unix.Read(watch, events[:])
	if watchErr != nil && !errors.Is(watchErr, unix.EAGAIN) {
		t.Fatal(watchErr)
	}
	if err == nil || n > 0 || before.Uid != after.Uid || before.Gid != after.Gid || before.Ctim != after.Ctim {
		t.Fatal("acceptance: intermediate symlink reached ownership mutation")
	}
}

func TestDataAtParent(t *testing.T) {
	for _, operation := range []string{"mkdir", "link", "stat"} {
		t.Run(operation, func(t *testing.T) {
			base, outside := privateTestDir(t), privateTestDir(t)
			if err := os.Symlink(outside, filepath.Join(base, "d")); err != nil {
				t.Fatal(err)
			}
			root, err := os.Open(base)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			called := false
			err = dataAt(root, "d/leaf", func(fd int, base string) error {
				called = true
				switch operation {
				case "mkdir":
					return unix.Mkdirat(fd, base, 0700)
				case "link":
					return unix.Symlinkat(".", fd, base)
				default:
					var stat unix.Stat_t
					return unix.Fstatat(fd, base, &stat, unix.AT_SYMLINK_NOFOLLOW)
				}
			})
			if err == nil || called {
				t.Fatal("acceptance: intermediate symlink reached root syscall")
			}
		})
	}
}

func registryFixture(t *testing.T) (*Service, containmentTicket) {
	t.Helper()
	service := &Service{containments: map[api.ID]*containmentEntry{}}
	ticket := containmentTicket{Kind: api.EndpointWorker, Lease: api.HelperLease{ID: "lease-a", ContainmentID: "cg-a"}, LaunchID: "launch-a", WorkerLeaseID: "worker-a", StageID: "stage-a", ParentLeaseID: "parent-a", ParentLaunchID: "parent-launch"}
	for _, key := range []api.ID{"cg-a", "cg-b"} {
		file, err := os.Open(privateTestDir(t))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { file.Close() })
		copy := ticket
		copy.Lease.ContainmentID = key
		service.containments[key] = &containmentEntry{Binding: api.ContainmentBinding{Directory: file, Lease: copy.Lease}, Ticket: copy}
	}
	return service, ticket
}

func TestRevokeRegistry(t *testing.T) {
	for _, selector := range []string{"stage-a", "parent-a", "parent-launch", "launch-a", "worker-a"} {
		t.Run(selector, func(t *testing.T) {
			service, _ := registryFixture(t)
			if err := service.finishRevocation(api.ID(selector), true, nil); err != nil {
				t.Fatal(err)
			}
			for _, entry := range service.containments {
				_, err := entry.Binding.Directory.Stat()
				if !entry.Binding.Revoked || !errors.Is(err, os.ErrClosed) {
					t.Fatal("acceptance: revocation left a matching registry owner")
				}
			}
			if err := service.finishRevocation(api.ID(selector), true, nil); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRevokeErrors(t *testing.T) {
	service, _ := registryFixture(t)
	want := failure(api.CodeContainmentUnknown, "injected helper stop failure")
	if err := service.finishRevocation("stage-a", true, want); !errors.Is(err, want) {
		t.Fatal("acceptance: revocation swallowed helper error")
	}
	if err := service.finishRevocation("unknown", false, nil); err == nil {
		t.Fatal("acceptance: unmatched revocation reported success")
	}
}

func TestResolveRefresh(t *testing.T) {
	for _, fault := range []string{"valid", "revoked", "ticket", "helper"} {
		t.Run(fault, func(t *testing.T) {
			service, ticket := registryFixture(t)
			helperErr := errors.New("injected helper resolution failure")
			binding, _, err := service.refreshContainment("cg-a", func(query containmentQuery) (containmentTicket, error) {
				if !service.registryMu.TryLock() {
					t.Fatal("acceptance: registry lock held across helper call")
				}
				service.registryMu.Unlock()
				if !query.Opened || query.LeaseID != ticket.Lease.ID {
					t.Fatal("acceptance: resolution did not require an opened gate")
				}
				switch fault {
				case "revoked":
					if err := service.revokeEntries("stage-a"); err != nil {
						t.Fatal(err)
					}
				case "ticket":
					ticket.LaunchID = "changed-launch"
				case "helper":
					return containmentTicket{}, helperErr
				}
				return ticket, nil
			})
			if fault == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				if err := binding.Directory.Close(); err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("acceptance: changed or revoked containment resolved")
			} else if fault == "helper" && !errors.Is(err, helperErr) {
				t.Fatal(err)
			}
		})
	}
}

func TestContainmentClass(t *testing.T) {
	ticket := containmentTicket{Kind: api.EndpointWorker, WorkerLeaseID: "worker-a"}
	endpoint := api.InstalledBinding{Class: api.EndpointWorker, WorkerLeaseID: "worker-a"}
	if !ticket.endpointMatches(endpoint) {
		t.Fatal("valid worker endpoint refused")
	}
	// Isolate each predicate. A class counterexample with an empty worker ID
	// would still be refused by the lease check after removing the class check.
	wrongClass := endpoint
	wrongClass.Class = api.EndpointLane
	if ticket.endpointMatches(wrongClass) {
		t.Fatal("acceptance: worker endpoint borrowed a class")
	}
	wrongLease := endpoint
	wrongLease.WorkerLeaseID = "other-worker"
	if ticket.endpointMatches(wrongLease) {
		t.Fatal("acceptance: worker endpoint borrowed a lease")
	}
}

func TestContainmentGate(t *testing.T) {
	record := leaseRecord{Gate: &gateJournal{State: "opened", Permit: &api.LaunchPermit{}}}
	if !openedContainment(record) {
		t.Fatal("opened gate refused")
	}
	for _, state := range []string{"prepared", "opening", "ended", "aborted"} {
		record.Gate.State = state
		if openedContainment(record) {
			t.Fatal("acceptance: unopened or ended gate authenticated")
		}
	}
	record.Gate.State, record.Gate.Permit = "opened", nil
	if openedContainment(record) {
		t.Fatal("acceptance: gate without consumed permit authenticated")
	}
}

func TestPrivateMappedReference(t *testing.T) {
	file, err := os.CreateTemp(privateTestDir(t), "mapped-")
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(int64(os.Getpagesize())); err != nil {
		t.Fatal(err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	mapping, err := unix.Mmap(int(file.Fd()), 0, os.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if mapping != nil {
			unix.Munmap(mapping)
		}
	}()
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	inventory := []storageInode{{Device: uint64(stat.Dev), Inode: stat.Ino}}
	count, _, err := descriptorReferences(context.Background(), os.Getpid(), inventory)
	if err != nil || count == 0 {
		t.Fatal("acceptance: mapped private inode was measured as zero")
	}
	if err := unix.Munmap(mapping); err != nil {
		t.Fatal(err)
	}
	mapping = nil
	count, _, err = descriptorReferences(context.Background(), os.Getpid(), inventory)
	if err != nil || count != 0 {
		t.Fatalf("unmapped control retained a reference: %v", err)
	}
}

func TestPrivateCwdReference(t *testing.T) {
	// A real child holds only cwd. No fixture descriptor points into its cwd.
	base := privateTestDir(t)
	var stat unix.Stat_t
	if err := unix.Stat(base, &stat); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/usr/bin/sleep", "30")
	cmd.Dir = base
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := cmd.Process.Kill(); err != nil {
			t.Error(err)
		}
		var exited *exec.ExitError
		if err := cmd.Wait(); err != nil && !errors.As(err, &exited) {
			t.Error(err)
		}
	}()
	count, _, err := descriptorReferences(context.Background(), cmd.Process.Pid, []storageInode{{Device: uint64(stat.Dev), Inode: stat.Ino}})
	if err != nil || count == 0 {
		t.Fatal("acceptance: private cwd was measured as zero")
	}
}

func TestPrivateLinkInventory(t *testing.T) {
	for _, kind := range []string{"symlink", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			root, record, _ := storageFixture(t)
			if err := syncStorageDirectories(context.Background(), root, &record, uint32(os.Geteuid()), true); err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(root.Name(), string(record.Storage.Binding.WorkspaceID), "entry")
			if kind == "symlink" {
				if err := os.Symlink(".", name); err != nil {
					t.Fatal(err)
				}
			} else if err := unix.Mkfifo(name, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := inventoryStorage(context.Background(), root, record); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(name, name+"-alias"); err != nil {
				t.Fatal(err)
			}
			if _, err := inventoryStorage(context.Background(), root, record); err == nil {
				t.Fatal("acceptance: linked nonregular inode entered collection")
			}
		})
	}
}

func TestCgroupEventDeadline(t *testing.T) {
	root, err := os.OpenRoot(privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.WriteFile(filepath.Join(root.Name(), "cgroup.events"), []byte("populated 1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := waitCgroupEvent(ctx, root, "populated", "0"); err == nil {
		t.Fatal("acceptance: populated cgroup event was reported empty")
	}
	if err := os.WriteFile(filepath.Join(root.Name(), "cgroup.events"), []byte("populated 0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := waitCgroupEvent(context.Background(), root, "populated", "0"); err != nil {
		t.Fatal(err)
	}
}

func TestStopWait(t *testing.T) {
	cmd := exec.Command("/usr/bin/true")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	close(done)
	gate := &nativeGate{done: done, state: cmd.ProcessState}
	want := errors.New("injected populated descendant barrier")
	called := false
	err := stopAndWait(context.Background(), gate, api.ProcessHandle{}, func() error { called = true; return want })
	if !called || !errors.Is(err, want) {
		t.Fatal("acceptance: reaped supervisor bypassed population wait")
	}
}

func TestPrivateRootReference(t *testing.T) {
	var stat unix.Stat_t
	if err := unix.Stat("/", &stat); err != nil {
		t.Fatal(err)
	}
	count, _, err := descriptorReferences(context.Background(), os.Getpid(), []storageInode{{Device: uint64(stat.Dev), Inode: stat.Ino}})
	if err != nil || count == 0 {
		t.Fatal("acceptance: native root reference was measured as zero")
	}
}

func TestPrivateNamespaceFD(t *testing.T) {
	file, err := os.Open("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/usr/bin/sleep", "30")
	cmd.ExtraFiles = []*os.File{file}
	if err := cmd.Start(); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := cmd.Process.Kill(); err != nil {
			t.Error(err)
		}
		var exited *exec.ExitError
		if err := cmd.Wait(); err != nil && !errors.As(err, &exited) {
			t.Error(err)
		}
	}()
	_, held, err := descriptorReferences(context.Background(), cmd.Process.Pid, nil)
	if err != nil || !held {
		t.Fatal("acceptance: foreign namespace descriptor was ignored")
	}
}

func TestDataParentQuiet(t *testing.T) {
	m, parent, job, query, observation := dataTestResult(t)
	want := failure(api.CodeContainmentUnknown, "injected live parent UID")
	resources := &observedResources{quietErr: want}
	m.resources = resources
	if _, err := m.readQuiescentData(context.Background(), parent, job, query, observation); !errors.Is(err, want) || len(resources.quiet) != 1 || resources.quiet[0] != parent.Lease.ID {
		t.Fatal("acceptance: live parent reached data ownership return")
	}
	resources.quietErr = nil
	if _, err := m.readQuiescentData(context.Background(), parent, job, query, observation); err != nil {
		t.Fatal(err)
	}
}

func TestHelperCapabilities(t *testing.T) {
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := helperUnitFixture(directory)
	if err != nil {
		t.Fatal(err)
	}
	var capabilities []string
	sets := 0
	var users, nnp, suid int
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		name, value, found := strings.Cut(line, "=")
		if found {
			switch strings.TrimSpace(name) {
			case "User":
				users++
			case "NoNewPrivileges":
				nnp++
				if strings.TrimSpace(value) != "yes" {
					t.Fatal("acceptance: helper unit lost NoNewPrivileges=yes or RestrictSUIDSGID=yes")
				}
			case "RestrictSUIDSGID":
				suid++
				if strings.TrimSpace(value) != "yes" {
					t.Fatal("acceptance: helper unit lost NoNewPrivileges=yes or RestrictSUIDSGID=yes")
				}
			}
		}
		if strings.HasPrefix(line, "CapabilityBoundingSet=") {
			sets++
			capabilities = strings.Fields(strings.TrimPrefix(line, "CapabilityBoundingSet="))
		}
	}
	if sets != 1 {
		t.Fatal("helper unit fixture must contain one capability bounding set")
	}
	found := map[string]bool{}
	for _, name := range capabilities {
		found[name] = true
	}
	if !found["CAP_SYS_ADMIN"] || !found["CAP_KILL"] {
		t.Fatal("helper unit fixture lacks namespace or cross-UID stop capability")
	}
	if !found["CAP_SETUID"] || !found["CAP_SETGID"] {
		t.Fatal("acceptance: helper unit lacks required credential-drop capabilities")
	}
	if strings.Join(capabilities, " ") != strings.TrimPrefix(helperCapsLine, "CapabilityBoundingSet=") {
		t.Fatal("acceptance: helper capability set differs from the exact ordered controlled-egress policy")
	}
	if nnp != 1 || suid != 1 {
		t.Fatal("acceptance: helper unit lost NoNewPrivileges=yes or RestrictSUIDSGID=yes")
	}
	if users != 0 {
		t.Fatal("acceptance: helper unit combines User= with NoNewPrivileges=yes")
	}
}

// go test runs from the package; the mutation harness runs the compiled test
// from the copied source root. Use the nearest module and never fall through
// to an ancestor unit when that module's fixture is missing.
func helperUnitFixture(start string) ([]byte, error) {
	directory, err := filepath.Abs(start)
	if err != nil {
		return nil, err
	}
	for {
		info, err := os.Lstat(filepath.Join(directory, "go.mod"))
		if err == nil {
			if !info.Mode().IsRegular() {
				return nil, errors.New("helper unit fixture module file is not regular")
			}
			return os.ReadFile(filepath.Join(directory, "packaging", "v2", "linux", "laneboss-helper.service.in"))
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return nil, errors.New("helper unit fixture has no enclosing module")
		}
		directory = parent
	}
}

func TestHelperUnitFixture(t *testing.T) {
	module := privateTestDir(t)
	packageDir := filepath.Join(module, "internal", "v2", "admin")
	unitDir := filepath.Join(module, "packaging", "v2", "linux")
	for _, directory := range []string{packageDir, unitDir} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(module, "go.mod"), []byte("module example.invalid/fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	id, err := randomID("unit-fixture-")
	if err != nil {
		t.Fatal(err)
	}
	contents := []byte(string(id) + "\n")
	if err := os.WriteFile(filepath.Join(unitDir, "laneboss-helper.service.in"), contents, 0600); err != nil {
		t.Fatal(err)
	}
	for _, entry := range []struct{ name, directory string }{{"root", module}, {"package", packageDir}} {
		t.Run(entry.name, func(t *testing.T) {
			raw, err := helperUnitFixture(entry.directory)
			if err != nil || string(raw) != string(contents) {
				t.Fatal("acceptance: helper unit fixture did not follow module root")
			}
		})
	}
	t.Run("missing", func(t *testing.T) {
		nested := filepath.Join(module, "nested")
		if err := os.Mkdir(nested, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(nested, "go.mod"), []byte("module example.invalid/nested\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := helperUnitFixture(nested); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("acceptance: missing module unit used an ancestor fixture")
		}
	})
}

func TestRevokeLaneJournal(t *testing.T) {
	m, store, _ := testManager()
	lease, err := m.allocate(context.Background(), testAllocation())
	if err != nil {
		t.Fatal(err)
	}
	// Injected nonnative resources cannot attest a stop. Durable invalidation
	// must precede that refusal, which must remain visible to the caller.
	matched, err := m.revokeNativeContainment(context.Background(), lease.ID)
	if !matched || err == nil || !store.records[0].Revoked {
		t.Fatal("acceptance: failed lane stop lost durable revocation")
	}
	if _, err := m.activate(context.Background(), store.records[0]); err == nil {
		t.Fatal("acceptance: revoked lane allocation reactivated")
	}
}

func TestDataUIDCollision(t *testing.T) {
	parent, a, binding := dataTestReg(t)
	binding.Lanes = append(binding.Lanes, account{Name: "lb-lane-c", UID: 61003, GID: 61003})
	b := a
	b.Reg.Worker.ID, b.Reg.Request.WorkerLeaseID, b.Reg.Worker.EffectID = "worker-b", "worker-b", "effect-b"
	b.Reg.Request.StageID, b.Reg.LaunchID = "stage-b", "launch-b"
	b.Reg.Plan.Argv = append([]string{}, a.Reg.Plan.Argv...)
	b.Reg.Plan.Argv[len(b.Reg.Plan.Argv)-1] = string(b.Reg.Worker.ID)
	b.Lease.ID, b.Lease.ContainmentID, b.Lease.UID, b.Lease.GID = "lease-b", "cg-b", 61003, 61003
	parent.DataJobs = []dataJob{a, b}
	store := &memoryLeases{records: []leaseRecord{parent}}
	m := &leaseManager{store: store, binding: binding}
	if _, err := m.records(); err != nil {
		t.Fatalf("distinct worker baseline: %v", err)
	}
	store.records[0].DataJobs[1].Lease.UID, store.records[0].DataJobs[1].Lease.GID = a.Lease.UID, a.Lease.GID
	if _, err := m.records(); err == nil {
		t.Fatal("acceptance: simultaneous workers share a native UID")
	}
}
