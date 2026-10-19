//go:build linux && laneboss_root_canary && laneboss_gate_integration

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

// The external broker's authority is component input. Its source descriptor is
// real, and completion accepts only the production receiver's measured cleanup.
// This fixture does not claim authenticated broker enrollment or vendor login.
type stoppedArchiveBroker struct {
	api.CredentialProjectionBroker
	record    api.CredentialProjectionRecord
	source    *os.File
	refreshes []*os.File
}

func (b *stoppedArchiveBroker) BeginCredentialWithdrawal(_ context.Context, q api.CredentialWithdrawalRequest) (api.CredentialProjectionRecord, error) {
	if err := api.ValidateCredentialWithdrawalRequest(b.record, q); err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	if err := b.source.Close(); err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	b.record.State, b.record.Generation, b.record.Fence = "withdrawing", b.record.Generation+1, &q
	return b.record, nil
}

func (b *stoppedArchiveBroker) FinishCredentialWithdrawal(_ context.Context, p api.CredentialProjectionRecord, receipt api.CredentialWithdrawalReceipt) (api.CredentialProjectionRecord, error) {
	if !reflect.DeepEqual(p, b.record) {
		return api.CredentialProjectionRecord{}, failure(api.CodeConflict, "component broker lost its exact withdrawal fence")
	}
	if err := api.ValidateCredentialWithdrawalHelper(p, receipt); err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	// Census the component's actual owned source and refresh descriptors; the
	// production validator refuses any nonzero or unavailable observation.
	var counts [2]uint64
	for i, files := range [][]*os.File{{b.source}, b.refreshes} {
		for _, file := range files {
			if _, err := file.Stat(); err == nil {
				counts[i]++
			} else if !errors.Is(err, os.ErrClosed) {
				return api.CredentialProjectionRecord{}, err
			}
		}
	}
	receipt.BrokerDescriptors, receipt.RefreshLeases = &counts[0], &counts[1]
	if err := api.ValidateCredentialWithdrawal(p, receipt); err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	b.record.State, b.record.Generation, b.record.Withdrawal = "withdrawn", receipt.Generation, &receipt
	return b.record, nil
}

func TestArchiveStoppedNative(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("stopped archive canary requires disposable Linux root")
	}
	if os.Args[len(os.Args)-1] != "archive-stopped-root" {
		config := testBinding().Config
		directory, err := os.MkdirTemp("/run", "lb-v2-archive-stopped-")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(directory)
		self, err := os.ReadFile("/proc/self/exe")
		if err != nil {
			t.Fatal(err)
		}
		binary := filepath.Join(directory, "canary")
		workerCanaryWrite(t, binary, self, 0555)
		args := []string{"--quiet", "--wait", "--pipe", "--collect", "--unit=laneboss-helper@" + config + ".service"}
		args = append(args, workerCanaryProperties(t, config)...)
		args = append(args, "--property=RuntimeMaxSec=80s", "--property=WorkingDirectory="+directory,
			binary, "-test.run=^TestArchiveStoppedNative$", "-test.v", "--", "archive-stopped-root")
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, "/usr/bin/systemd-run", args...)
		command.Env, command.WaitDelay = []string{}, 3*time.Second
		output, err := command.CombinedOutput()
		if err != nil || !bytes.Contains(output, []byte("--- PASS: TestArchiveStoppedNative ")) {
			t.Fatalf("shipped-unit stopped archive canary failed: %v\n%s", err, output)
		}
		t.Log(string(output))
		return
	}
	workerCanaryMounts(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	uid := uint32(100000 + os.Getpid())
	if err := uidQuiescent(ctx, uid); err != nil {
		t.Fatal("stopped archive canary needs its own unused UID", err)
	}
	m, registration, live, store, _, _, oldFile := stopCredentialFixture(t, true, [2]uint32{uid, uid})
	record, err := m.find(registration.Binding.Record.UIDLeaseID)
	if err != nil {
		t.Fatal(err)
	}
	group := cleanupCgroup(t, m.binding, record.Lease.ContainmentID)
	t.Cleanup(func() {
		select {
		case <-live.done:
			return
		default:
		}
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		resources := &linuxResources{binding: m.binding}
		if err := resources.KillContainment(cleanup, record); err != nil {
			t.Error(err)
		}
		if err := stopAndWait(cleanup, live, gateHandle(record), func() error { return resources.WaitContainmentEmpty(cleanup, record) }); err != nil {
			t.Error(err)
		}
	})
	cgroup, err := os.OpenRoot(group)
	if err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(writeControl(cgroup, "cgroup.procs", strconv.Itoa(live.PID())), cgroup.Close()); err != nil {
		t.Fatal("cannot enroll the real process in its native containment", err)
	}
	base := storageBase(m.binding, record)
	if err := os.MkdirAll(filepath.Dir(base), 0755); err != nil {
		t.Fatal(err)
	}
	if err := createLaneStage(base, uid); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(base); err != nil {
			t.Error(err)
		}
	})
	root, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	for i := range record.Storage.Directories {
		record.Storage.Directories[i].Device, record.Storage.Directories[i].Inode = "", ""
	}
	record.Storage.Ready = false
	if err := errors.Join(syncStorageDirectories(ctx, root, &record, 0, true), root.Close()); err != nil {
		t.Fatal(err)
	}
	homePath := filepath.Join(base, string(record.Storage.Binding.Home.RootID))
	home, err := os.Open(homePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := home.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			t.Error(err)
		}
	})
	projection := *record.Credentials.Record
	target := projection.Authority.Targets[0]
	name := filepath.Join(homePath, target.RelativePath)
	if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(filepath.Dir(name), int(uid), int(uid)); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(oldFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(name, int(uid), int(uid)); err != nil {
		t.Fatal(err)
	}
	if err := oldFile.Close(); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			t.Error(err)
		}
	})
	fact, err := credentialDescriptor(file, false)
	if err != nil {
		t.Fatal(err)
	}
	_, native, err := credentialObject(file)
	if err != nil {
		t.Fatal(err)
	}
	source, _ := credentialCanary(t)
	sourceID, _, err := credentialObject(source)
	if err != nil {
		t.Fatal(err)
	}
	projection.Receipt.Targets[0].ObjectID = fact.ObjectID
	projection.Receipt.Targets[0].SourceObjectID = sourceID
	record.Credentials.Record = &projection
	held := m.credentials.held[projection.Authority.ID]
	held.record, held.home, held.files = projection, home, []*os.File{file}
	held.destinations = []storageInode{{Device: uint64(native.Dev), Inode: native.Ino}}
	m.credentials.broker = &stoppedArchiveBroker{record: projection, source: source}
	record.Gate.NativeProfile = "offline-private-v1"
	if err := m.save(record); err != nil {
		t.Fatal(err)
	}
	resources := &linuxResources{binding: m.binding, manager: m}
	m.resources = resources
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	control := os.NewFile(uintptr(pair[0]), "stopped-archive-readiness")
	connection, err := net.FileConn(control)
	if err := errors.Join(err, control.Close(), unix.Close(pair[1])); err != nil {
		t.Fatal(err)
	}
	live.control = connection.(*net.UnixConn)
	t.Cleanup(func() {
		if err := connection.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
	})
	workspaceFile := filepath.Join(base, string(record.Storage.Binding.WorkspaceID), "current")
	want := []byte("current stopped workspace bytes\n")
	if err := os.WriteFile(workspaceFile, want, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(workspaceFile, int(uid), int(uid)); err != nil {
		t.Fatal(err)
	}
	stopCause := testCause(api.InternalHelperStop, record.Request.LifeID)
	// The actual lifecycle advances the cancellation epoch on stop, and its
	// later abandoned/merged decision advances it again before archive.
	stopCause.CancellationEpoch = record.LaunchAllocations[0].Reservation.CancellationEpoch + 1
	observed, err := m.stopGate(ctx, api.HelperStopRequest{Cause: stopCause, Target: api.HelperObserveRequest{LeaseID: record.Lease.ID, Handle: gateHandle(record)},
		OperationID: stopCause.CauseOperationID, EffectID: stopCause.EffectID, Reason: "stopped archive canary"})
	if err != nil || observed.Signal == nil || *observed.Signal != 9 || observed.Survivors == nil || *observed.Survivors != 0 {
		t.Fatal("actual credential-bearing stop did not measure the killed containment", err)
	}
	if _, err := os.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("native credential withdrawal retained its projected path", err)
	}
	record, err = m.find(record.Lease.ID)
	if err != nil || !record.Revoked || record.Credentials.State != "withdrawn" || record.Credentials.Record.Withdrawal == nil {
		t.Fatal("native stop lost revocation or its measured withdrawal", err)
	}
	intent := archivejob.Intent{OperationID: "stopped-archive-operation", Request: api.ArchiveRequest{Target: observed.Handle.Target, ExpectedGeneration: 3},
		CancellationEpoch: stopCause.CancellationEpoch + 1, EndEventID: "retained-stopped-end", EndSeq: 9}
	lane := api.Lane{LifeID: intent.Request.Target.LifeID, Run: intent.Request.Target.Run, Generation: intent.Request.ExpectedGeneration,
		CancellationEpoch: intent.CancellationEpoch, LaunchID: observed.Handle.ID, Workspace: api.Workspace{ID: record.Storage.Binding.WorkspaceID}}
	if _, err := m.freezeArchive(ctx, archiveQuery{Intent: intent, Lane: lane}); err == nil {
		t.Fatal("archive accepted a revoked allocation before its measured release")
	}
	request := testRelease(record.Lease, observed)
	request.Cause.CancellationEpoch = stopCause.CancellationEpoch
	receipt, err := m.release(ctx, request)
	if err != nil || api.ValidateReleaseReceipt(receipt) != nil {
		t.Fatal("actual stopped allocation did not complete native release", err)
	}
	if _, err := os.Lstat(group); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("release retained the original cgroup", err)
	}
	if _, err := m.observeGate(ctx, api.HelperObserveRequest{LeaseID: record.Lease.ID, Handle: observed.Handle}); err != nil {
		t.Fatal("released run lost its actual terminal re-observation", err)
	}
	header, err := m.freezeArchive(ctx, archiveQuery{Intent: intent, Lane: lane})
	if err != nil {
		t.Fatal("site 8: measured stopped allocation could not enter read-only archive", err)
	}
	query := archiveQuery{Intent: intent, Freeze: header.Freeze, Limit: api.MaxChunkBytes}
	if _, err := m.checkArchive(ctx, query); err != nil {
		t.Fatal("stopped archive could not recheck its original freeze", err)
	}
	again, err := m.freezeArchive(ctx, archiveQuery{Intent: intent, Lane: lane})
	if err != nil || !reflect.DeepEqual(again, header) {
		t.Fatal("stopped archive retry replaced its original freeze", err)
	}
	record, err = m.find(record.Lease.ID)
	if err != nil || !record.Revoked || record.Phase != "released" || !reflect.DeepEqual(record.Receipt, &receipt) {
		t.Fatal("archive restored launch authority or changed release evidence", err)
	}
	reg := archiveClaimFixture()
	reg.Job.Intent, reg.Job.Lease.Target, reg.Job.Freeze = intent, intent.Request.Target, freezeRef(t, header.Freeze)
	reg.Job.Plan.Budget = record.Request.Budget
	reg.Claim.Record.Effect.Worker = &reg.Job.Plan
	reg.Job.Lease.OperationID, reg.Claim.Record.Effect.OperationID = intent.OperationID, intent.OperationID
	reg.Claim.Record.Effect.Context.Target = intent.Request.Target
	reg.Claim.Record.Effect.Context.CauseOperationID = intent.OperationID
	reg.Claim.Record.Effect.Context.CancellationEpoch = intent.CancellationEpoch
	if _, err := m.archiveWorker(ctx, reg); err != nil {
		t.Fatal("stopped archive worker lost the same read-only parent", err)
	}
	found := false
	for i, ref := range header.Objects {
		query.Index = i
		chunk, err := m.archiveBytes(ctx, query)
		if err != nil || chunk.ObjectID != ref.ID || digestBytes(chunk.Data) != chunk.SHA256 || int64(len(chunk.Data)) != ref.Bytes || digestBytes(chunk.Data) != ref.SHA256 {
			t.Fatal("stopped archive byte read-back changed its measured inventory", err)
		}
		found = found || bytes.Equal(chunk.Data, want)
	}
	if !found {
		t.Fatal("stopped archive omitted current workspace bytes")
	}
	if _, err := m.findActive(record.Lease.ID, storageReady); err == nil {
		t.Fatal("stopped archive regained writable launch authority")
	}
	if _, err := m.allocate(ctx, record.Request); err == nil {
		t.Fatal("stopped archive reacquired its revoked allocation")
	}
	for _, mode := range []string{"boot", "release", "withdrawal", "storage", "stop", "projection-revoked", "authority-revoked", "run", "epoch", "end", "end-sequence", "operation", "withdrawal-end", "gate-end", "release-epoch", "stale-epoch"} {
		t.Run(mode, func(t *testing.T) {
			raw, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			var changed leaseRecord
			if err := decodeStrict(raw, &changed); err != nil {
				t.Fatal(err)
			}
			q, worker := query, reg
			switch mode {
			case "boot":
				changed.BootID = "other-boot"
			case "release":
				changed.Receipt = nil
			case "withdrawal":
				changed.Credentials.State = "held"
			case "storage":
				changed.Storage.Withdrawn = false
			case "stop":
				changed.Credentials.Stop = nil
			case "projection-revoked":
				changed.Credentials.Record.Revoked = true
			case "authority-revoked":
				changed.Credentials.Record.Authority.Revoked = true
			case "run":
				q.Intent.Request.Target.Run++
			case "epoch":
				q.Intent.CancellationEpoch++
			case "end":
				q.Intent.EndEventID = "foreign-end"
			case "end-sequence":
				q.Intent.EndSeq++
			case "operation":
				q.Intent.OperationID = "foreign-operation"
			case "withdrawal-end":
				code := 0
				changed.Credentials.Record.Withdrawal.Observation.Signal = nil
				changed.Credentials.Record.Withdrawal.Observation.ExitCode = &code
			case "gate-end":
				code := 0
				changed.Gate.Observation.Signal = nil
				changed.Gate.Observation.ExitCode = &code
			case "release-epoch":
				changed.Release.Cause.CancellationEpoch++
			case "stale-epoch":
				q.Intent.CancellationEpoch = record.LaunchAllocations[0].Reservation.CancellationEpoch
			}
			// Raw persistence deliberately retains invalid controls so the real
			// journal reader and every archive-parent consumer must reject them.
			if err := store.Save(changed); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := store.Save(record); err != nil {
					t.Error(err)
				}
			}()
			worker.Job.Intent = q.Intent
			if _, err := m.freezeArchive(ctx, archiveQuery{Intent: q.Intent, Lane: lane}); err == nil {
				t.Fatal("foreign stopped allocation entered freeze")
			}
			if _, err := m.checkArchive(ctx, q); err == nil {
				t.Fatal("foreign stopped allocation passed freeze read-back")
			}
			if _, err := m.archiveBytes(ctx, q); err == nil {
				t.Fatal("foreign stopped allocation exposed archived bytes")
			}
			if _, err := m.archiveWorker(ctx, worker); err == nil {
				t.Fatal("foreign stopped allocation became a worker parent")
			}
		})
	}
	file, err = os.Open(workspaceFile)
	if err != nil {
		t.Fatal(err)
	}
	denied := archiveWriteAttempt(t, file, uid)
	if err := file.Close(); err != nil || denied != "denied" {
		t.Fatal("original stopped UID regained writable access", err)
	}
	t.Log("site 8: real credential stop, withdrawal, release, frozen bytes, retry and worker parent passed under shipped helper properties")
}
