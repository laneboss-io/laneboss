//go:build linux && laneboss_root_canary && laneboss_gate_integration

package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

// This measures normal agent release with the actual cgroup, UID census,
// original native wait, readiness socket and file-backed helper journal. The
// store/reconciler regression lives in service/run_release_linux_test.go.
// Workspace and authenticated capture ingestion remain separate prerequisites;
// this canary has no workspace or outside capture producer to collect.
func TestNormalReleaseNative(t *testing.T) {
	normalReleaseNative(t, false)
}

func TestArchiveNaturalEpoch(t *testing.T) {
	normalReleaseNative(t, true)
}

func normalReleaseNative(t *testing.T, archiveAfterDecision bool, crashRemoval ...bool) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("normal release canary requires disposable Linux root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// This numeric identity is private to this test process. The production
	// UID census must first prove it unused; a shared fixture UID is not a
	// reservation against other native canaries on the disposable host.
	uid := uint32(100000 + os.Getpid())
	if err := uidQuiescent(ctx, uid); err != nil {
		t.Fatal("normal release canary has no independently unused UID", err)
	}
	fixture, registration, live, reader, _ := retainedGateFixture(t, [2]uint32{uid, uid})
	record, err := fixture.find(registration.Binding.Record.UIDLeaseID)
	if err != nil {
		t.Fatal(err)
	}
	group := cleanupCgroup(t, fixture.binding, record.Lease.ContainmentID)
	root, err := os.OpenRoot(group)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeControl(root, "cgroup.procs", strconv.Itoa(live.PID())); err != nil {
		root.Close()
		t.Fatal("native child could not enter its measured cgroup", err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	// Enroll the closed gate before any vendor instruction or descendant can
	// run, then use the actual native containment stop and population barrier.
	handle, err := fixture.openGate(ctx, registration)
	if err != nil {
		t.Fatal("native release fixture could not open its actual gate", err)
	}
	if err := reader.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	canary := make([]byte, len(live.token))
	if _, err := io.ReadFull(reader, canary); err != nil || string(canary) != live.token {
		t.Fatal("normal release fixture did not execute its native child", err)
	}
	record, err = fixture.find(record.Lease.ID)
	if err != nil {
		t.Fatal(err)
	}
	resources := &linuxResources{binding: fixture.binding}
	if err := resources.KillContainment(ctx, record); err != nil {
		t.Fatal("native containment could not be stopped", err)
	}
	select {
	case <-live.done:
	case <-ctx.Done():
		t.Fatal("native child wait did not complete")
	}
	if err := resources.WaitContainmentEmpty(ctx, record); err != nil {
		t.Fatal("native containment and UID did not become quiescent", err)
	}
	// Start an independent component helper journal for this storage-free
	// release. Its process/permit/spec are the exact gate just executed above.
	if !archiveAfterDecision {
		record.Storage = nil
	} else {
		base := storageBase(fixture.binding, record)
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
		storageRoot, err := os.OpenRoot(base)
		if err != nil {
			t.Fatal(err)
		}
		for i := range record.Storage.Directories {
			record.Storage.Directories[i].Device, record.Storage.Directories[i].Inode = "", ""
		}
		record.Storage.Ready = false
		if err := errors.Join(syncStorageDirectories(ctx, storageRoot, &record, 0, true), storageRoot.Close()); err != nil {
			t.Fatal(err)
		}
		name := filepath.Join(base, string(record.Storage.Binding.WorkspaceID), "current")
		if err := os.WriteFile(name, []byte("naturally ended workspace bytes\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(name, int(uid), int(uid)); err != nil {
			t.Fatal(err)
		}
	}
	// This is the component's protected profile enrollment, not an isolation
	// availability result. All release counts below come from native owners.
	record.Gate.NativeProfile = "offline-private-v1"
	journalRoot, err := os.OpenRoot(privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := journalRoot.Close(); err != nil {
			t.Error(err)
		}
	})
	m := newLeaseManager(fixture.binding, fixture.bootID, &fileLeaseStore{root: journalRoot, owner: 0}, resources)
	resources.manager = m
	m.gates = map[api.ID]ownedGate{record.Lease.ID: live}
	if err := m.save(record); err != nil {
		t.Fatal("native release input did not validate in the real helper journal", err)
	}
	observation, err := m.observeGate(ctx, api.HelperObserveRequest{LeaseID: record.Lease.ID, Handle: handle})
	if err != nil || observation.Survivors == nil || *observation.Survivors != 0 {
		t.Fatal("native release did not measure terminal zero survivors", err)
	}
	request := testRelease(record.Lease, observation)
	request.Cause.Target, request.Cause.CancellationEpoch = record.Gate.Prepared.Target, record.Request.Cause.CancellationEpoch
	// Missing socket inventory cannot be substituted by the caller's zero.
	if receipt, err := m.release(ctx, request); err == nil || receipt.ID != "" {
		t.Fatal("normal release invented an unknown readiness connection count")
	} else {
		requireCode(t, err, api.CodeContainmentUnknown)
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(pair[0]), "release-readiness")
	connection, err := net.FileConn(file)
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		unix.Close(pair[1])
		t.Fatal("native readiness socket could not be retained", errors.Join(err, closeErr))
	}
	live.control = connection.(*net.UnixConn)
	t.Cleanup(func() {
		if err := connection.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
		if err := unix.Close(pair[1]); err != nil {
			t.Error(err)
		}
	})
	if receipt, err := m.release(ctx, request); err == nil || receipt.ID != "" {
		t.Fatal("normal release ignored an actual live readiness socket")
	} else {
		requireCode(t, err, api.CodeContainmentUnknown)
	}
	if _, err := os.Stat(group); err != nil {
		t.Fatal("refused release removed the retained cgroup", err)
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	var restarted *leaseManager
	if len(crashRemoval) == 1 && crashRemoval[0] {
		fault := &endRemoveFault{leaseResources: resources, store: m.store, err: errors.New("crash before cgroup removal")}
		m.resources = fault
		if _, err := m.release(ctx, request); !errors.Is(err, fault.err) || !fault.hit {
			t.Fatal("release did not reach its post-commit removal boundary", err)
		}
		if _, err := os.Stat(group); err != nil {
			t.Fatal("interrupted removal discarded the actual cgroup", err)
		}
		root, err := os.OpenRoot(journalRoot.Name())
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		restartedResources := &linuxResources{binding: m.binding}
		restarted = newLeaseManager(m.binding, m.bootID, &fileLeaseStore{root: root, owner: 0}, restartedResources)
		restartedResources.manager = restarted
		observed, err := restarted.observeGate(ctx, api.HelperObserveRequest{LeaseID: record.Lease.ID, Handle: handle})
		if err != nil || observed.State != "exited" || observed.Survivors == nil || *observed.Survivors != 0 || len(restarted.gates) != 0 {
			t.Fatal("restart lost its durable native exit before removal", err)
		}
		retained, err := restarted.find(record.Lease.ID)
		if err != nil || !committedExit(retained) || retained.Revoked || stopWithdrawalReason(retained) != "release" {
			t.Fatal("restart quarantined the original terminal release", err)
		}
		_, err = restarted.containment(ctx, containmentQuery{LeaseID: record.Lease.ID, Opened: true})
		requireCode(t, err, api.CodeContainmentUnknown)
	}
	receipt, err := m.release(ctx, request)
	if err != nil || api.ValidateReleaseReceipt(receipt) != nil || receipt.ID == "" || receipt.Quiescence.Handle != handle ||
		receipt.Quiescence.Signal == nil || *receipt.Quiescence.Signal != 9 || receipt.OperationID != request.Cause.CauseOperationID || receipt.EffectID != request.Cause.EffectID {
		t.Fatal("normal release did not return the actual native measurement", err)
	}
	if _, err := os.Stat(group); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("normal release did not remove its actual empty cgroup", err)
	}
	if restarted != nil {
		observed, err := restarted.observeGate(ctx, api.HelperObserveRequest{LeaseID: record.Lease.ID, Handle: handle})
		if err != nil || observed.Handle != receipt.Quiescence.Handle || observed.State != "exited" ||
			observed.Survivors == nil || *observed.Survivors != 0 {
			t.Fatal("cgroup removal lost the retained terminal record", err)
		}
	}
	retained, err := m.find(record.Lease.ID)
	if err != nil || retained.Phase != "released" || retained.Receipt == nil || !reflect.DeepEqual(*retained.Receipt, receipt) {
		t.Fatal("normal release lost its measured helper journal receipt", err)
	}
	again, err := m.release(ctx, request)
	if err != nil || !reflect.DeepEqual(again, receipt) {
		t.Fatal("native release replay replaced its measured receipt", err)
	}
	if archiveAfterDecision {
		baseEpoch := retained.LaunchAllocations[len(retained.LaunchAllocations)-1].Reservation.CancellationEpoch
		intent := archivejob.Intent{OperationID: "natural-archive-operation", Request: api.ArchiveRequest{Target: handle.Target, ExpectedGeneration: 4},
			CancellationEpoch: baseEpoch + 1, EndEventID: "natural-committed-end", EndSeq: 10}
		lane := api.Lane{LifeID: handle.Target.LifeID, Run: handle.Target.Run, LaunchID: handle.ID, State: "abandoned", Generation: 4,
			CancellationEpoch: intent.CancellationEpoch, Workspace: api.Workspace{ID: retained.Storage.Binding.WorkspaceID}}
		t.Logf("native natural archive: allocation_epoch=%d released_epoch=%d decision_epoch=%d revoked=%t", baseEpoch, retained.Release.Cause.CancellationEpoch, lane.CancellationEpoch, retained.Revoked)
		decision, err := json.Marshal(api.StateEvent{From: "verifying", To: lane.State, Generation: lane.Generation})
		if err != nil {
			t.Fatal(err)
		}
		fence := &archivejob.EpochFence{Intent: intent, LaunchID: lane.LaunchID, LaunchEpoch: baseEpoch,
			End:      api.RunEndEvent{LaunchID: lane.LaunchID, Reason: "exit", Observation: receipt.Quiescence, BudgetRemaining: record.Request.Budget},
			Decision: api.Event{Schema: api.SchemaVersion, Config: m.binding.Config, ID: "natural-terminal-decision", Kind: "lane.state", Origin: "service", LifeID: lane.LifeID, Run: lane.Run, Seq: 11, StarterChain: []api.ID{}, Payload: decision}}
		if _, err := m.freezeArchive(ctx, archiveQuery{Intent: intent, Lane: lane}); err == nil {
			t.Fatal("natural archive accepted the advanced epoch without its writer handoff")
		}
		for _, field := range []string{"base", "epoch", "generation", "decision", "run", "launch", "end"} {
			changed := *fence
			switch field {
			case "base":
				changed.LaunchEpoch++
			case "epoch":
				changed.Intent.CancellationEpoch++
			case "generation":
				changed.Intent.Request.ExpectedGeneration++
			case "decision":
				changed.Decision.Seq = intent.EndSeq
			case "run":
				changed.Intent.Request.Target.Run++
			case "launch":
				changed.LaunchID = "foreign-natural-launch"
			case "end":
				changed.End.Reason = "service_lost"
			}
			if _, err := m.freezeArchive(ctx, archiveQuery{Intent: intent, Lane: lane, Epoch: &changed}); err == nil {
				t.Error("native archive accepted a foreign terminal epoch handoff", field)
			}
		}
		header, err := m.freezeArchive(ctx, archiveQuery{Intent: intent, Lane: lane, Epoch: fence})
		if err != nil {
			t.Fatal("released natural run could not freeze after its terminal decision", err)
		}
		query := archiveQuery{Intent: intent, Freeze: header.Freeze, Limit: api.MaxChunkBytes}
		if _, err := m.checkArchive(ctx, query); err != nil {
			t.Fatal("natural archive could not recheck its exact frozen fence", err)
		}
		found := false
		for index, ref := range header.Objects {
			query.Index = index
			chunk, err := m.archiveBytes(ctx, query)
			if err != nil || chunk.ObjectID != ref.ID || digestBytes(chunk.Data) != ref.SHA256 {
				t.Fatal("natural archive read-back changed actual current bytes", err)
			}
			found = found || string(chunk.Data) == "naturally ended workspace bytes\n"
		}
		if !found {
			t.Fatal("natural archive lost its current workspace bytes")
		}
		changed := query
		changed.Intent.CancellationEpoch++
		if _, err := m.checkArchive(ctx, changed); err == nil {
			t.Error("native archive read-back accepted a changed cancellation epoch")
		}
		if chunk, err := m.archiveBytes(ctx, changed); err == nil || len(chunk.Data) != 0 {
			t.Error("native archive exported bytes under a changed cancellation epoch")
		}
		retained, err = m.find(record.Lease.ID)
		if err != nil || retained.ArchiveEpoch == nil || retained.ArchiveEpoch.Intent != intent ||
			retained.LaunchAllocations[len(retained.LaunchAllocations)-1].Reservation.CancellationEpoch != baseEpoch ||
			retained.Release.Cause.CancellationEpoch != baseEpoch {
			t.Fatal("native archive replaced an original epoch instead of retaining its decision fence", err)
		}
		if err := m.collectPrivateStorage(ctx, &retained); err != nil {
			t.Fatal("natural archive could not collect its actual private storage", err)
		}
		collected, err := m.find(record.Lease.ID)
		if err != nil || !collected.Storage.Collected {
			t.Fatal("natural archive collection was not durably retained", err)
		}
		for _, directory := range collected.Storage.Directories {
			if _, err := os.Lstat(filepath.Join(storageBase(m.binding, collected), string(directory.ID))); !errors.Is(err, os.ErrNotExist) {
				t.Error("natural archive left a collected private root", err)
			}
		}
		t.Log("natural archive: exact epoch pinned, native freeze/read-back verified, actual private storage collected")
	}
}
