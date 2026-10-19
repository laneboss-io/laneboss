//go:build linux && laneboss_root_canary && laneboss_gate_integration

package admin

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func init() {
	if len(os.Args) != 2 || os.Args[1] != "capture-drain-spool-canary" {
		return
	}
	payload, err := readBootstrapInput()
	if err != nil || payload.Capture == nil {
		os.Exit(81)
	}
	ready := os.NewFile(9, "capture-ready")
	err = spoolPipesReady(*payload.Capture, [2]*os.File{os.NewFile(4, "stdout-pipe"), os.NewFile(5, "stderr-pipe")},
		[2]*os.File{os.NewFile(6, "stdout-spool"), os.NewFile(7, "stderr-spool")}, os.NewFile(8, "capture-marker"), func() error {
			_, err := ready.Write([]byte{1})
			return errors.Join(err, ready.Close())
		})
	if err != nil {
		os.Exit(82)
	}
	os.Exit(0)
}

// The original lane/release claim is a protocol fixture. The helper file
// journal, separate-UID producer, inherited pipes, spool algorithm, native
// wait/pidfd, cgroup and UID inventory and containment removal are real.
func nativeCaptureDrainFixture(t *testing.T) (*leaseManager, captureDrainQuery, *nativeGate, [2]*os.File, [][]byte) {
	return nativeCaptureDrainFixtureFor(t, nil)
}

func nativeCaptureDrainFixtureFor(t *testing.T, supplied *api.CaptureBinding) (*leaseManager, captureDrainQuery, *nativeGate, [2]*os.File, [][]byte) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("capture drain canary requires disposable Linux root")
	}
	_, p, reservation := storageFixture(t)
	b := testBinding()
	producerExecutable := "/proc/self/exe"
	var producerFile *os.File
	if supplied != nil {
		b.Config = supplied.Config
		actual, err := os.ReadFile("/proc/self/exe")
		if err != nil {
			t.Fatal(err)
		}
		producerExecutable = filepath.Join(privateTestDir(t), "capture-producer")
		if err := os.WriteFile(producerExecutable, actual, 0555); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(producerExecutable, 0555); err != nil {
			t.Fatal(err)
		}
		b.Artifact.Bytes, b.Artifact.SHA256 = int64(len(actual)), digestBytes(actual)
		producerFile, err = os.Open(producerExecutable)
		if err != nil {
			t.Fatal(err)
		}
		defer producerFile.Close()
		producerExecutable = "/proc/self/fd/10"
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	p.BootID = strings.TrimSpace(string(boot))
	p.IssuedAt = api.Timestamp(time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano))
	p.Lease.UID, p.Lease.GID = b.Lanes[0].UID, b.Lanes[0].GID
	id, err := randomID("capture-drain-")
	if err != nil {
		t.Fatal(err)
	}
	if supplied != nil {
		id = supplied.ID
	}
	p.Lease.ContainmentID = api.ID(string(id) + "-agent")
	cleanupCgroup(t, b, p.Lease.ContainmentID)
	outside := api.HelperLease{ID: id, UID: b.Lanes[1].UID, GID: b.Lanes[1].GID, ContainmentID: api.ID(string(id) + "-producer"), EndpointGeneration: 1}
	group := cleanupCgroup(t, b, outside.ContainmentID)
	if supplied != nil {
		for _, path := range []string{filepath.Dir(b.cgroupPath()), b.cgroupPath()} {
			root, err := os.OpenRoot(path)
			if err != nil {
				t.Fatal(err)
			}
			enableErr, closeErr := enableControllers(root), root.Close()
			if enableErr != nil || closeErr != nil {
				t.Fatal("native canary controller delegation failed", errors.Join(enableErr, closeErr))
			}
		}
	}
	for _, name := range []string{"/var/lib/laneboss-v2", "/var/lib/laneboss-v2/helper", b.statePath()} {
		if err := os.Mkdir(name, 0700); err == nil {
			t.Cleanup(func() {
				if err := os.Remove(name); err != nil {
					t.Error(err)
				}
			})
		} else if !errors.Is(err, os.ErrExist) {
			t.Fatal(err)
		}
	}
	spoolParent := filepath.Join(b.statePath(), "spools")
	if err := os.Mkdir(spoolParent, 0700); err == nil {
		t.Cleanup(func() {
			if err := os.Remove(spoolParent); err != nil {
				t.Error(err)
			}
		})
	} else if !errors.Is(err, os.ErrExist) {
		t.Fatal(err)
	}
	spool, files, err := createCaptureSpool(b, id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		spool.Close()
		if err := os.RemoveAll(filepath.Join(b.statePath(), "spools", string(id))); err != nil {
			t.Error(err)
		}
	})
	journal, err := os.OpenRoot(privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := journal.Close(); err != nil {
			t.Error(err)
		}
	})
	m := newLeaseManager(b, p.BootID, &fileLeaseStore{root: journal, owner: 0}, nil)
	m.resources = &linuxResources{binding: b, manager: m}
	binding := api.CaptureBinding{ID: id, Config: b.Config, ReservationID: reservation.ID, Target: reservation.Target, LaunchID: reservation.LaunchID, HelperLeaseID: p.Lease.ID,
		OperationID: reservation.OperationID, RequestID: reservation.RequestID, RequestedBy: reservation.RequestedBy, Generation: 1, Status: "registered", WorkerLeaseID: api.ID(string(id) + "-worker"), EffectID: api.ID(string(id) + "-capture-effect"),
		ProducerID: api.ID(string(id) + "-principal"), BootID: p.BootID, Supervisor: &api.Executable{ID: "capture-spool", SHA256: b.Artifact.SHA256, Version: b.Release.Version},
		Streams: []api.CaptureStreamBinding{{ID: api.ID(string(id) + "-out"), PipeID: api.ID(string(id) + "-out-pipe"), Stream: "stdout"}, {ID: api.ID(string(id) + "-err"), PipeID: api.ID(string(id) + "-err-pipe"), Stream: "stderr"}}}
	if supplied != nil {
		binding = *supplied
		binding.BootID = p.BootID
	}
	var reads, writes [2]*os.File
	for i := range reads {
		reads[i], writes[i], err = os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
	}
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readyRead.Close()
	input, err := sealedBootstrap(gatePayload{Argv: []string{}, Environment: []string{}, Paths: []bootstrapPath{}, Capture: &spoolInput{BindingID: id, Streams: binding.Streams, MaxBytes: 4096}})
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	cgroup, err := os.Open(group)
	if err != nil {
		t.Fatal(err)
	}
	defer cgroup.Close()
	command := exec.Command(producerExecutable, "capture-drain-spool-canary")
	command.Env = []string{}
	command.ExtraFiles = []*os.File{input, reads[0], reads[1], files[0], files[1], files[2], readyWrite}
	if producerFile != nil {
		command.ExtraFiles = append(command.ExtraFiles, producerFile)
	}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: outside.UID, Gid: outside.GID, Groups: []uint32{}}, UseCgroupFD: true, CgroupFD: int(cgroup.Fd())}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	for _, file := range append(reads[:], files...) {
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := readyWrite.Close(); err != nil {
		t.Fatal(err)
	}
	if err := readyRead.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var ready [1]byte
	if _, err := io.ReadFull(readyRead, ready[:]); err != nil || ready[0] != 1 {
		t.Fatal("native capture spool did not retain its initial pipe marker", err)
	}
	generation, err := processGeneration(command.Process.Pid, p.BootID)
	if err != nil {
		t.Fatal(err)
	}
	pidfd, err := unix.PidfdOpen(command.Process.Pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	binding.ProducerGeneration = generation
	if err := api.ValidateCaptureBinding(binding); err != nil {
		t.Fatal(err)
	}
	g := &nativeGate{command: command, pidfd: pidfd, generation: generation, innerPID: command.Process.Pid, innerFD: pidfd, innerGeneration: generation, done: make(chan struct{}), released: true}
	go func() {
		err := command.Wait()
		g.mu.Lock()
		g.waitErr, g.state = err, command.ProcessState
		close(g.done)
		g.mu.Unlock()
	}()
	t.Cleanup(func() {
		for _, w := range writes {
			w.Close()
		}
		select {
		case <-g.done:
		default:
			if err := command.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				t.Error(err)
			}
			select {
			case <-g.done:
			case <-time.After(5 * time.Second):
				t.Error("capture canary did not reap its actual producer")
			}
		}
		if err := unix.Close(pidfd); err != nil {
			t.Error(err)
		}
	})
	m.captures = map[api.ID]ownedCapture{id: &nativeCapture{gate: g, spool: spool, binding: binding, lease: outside, taken: true}}
	if supplied != nil {
		return m, captureDrainQuery{}, g, writes, nil
	}
	registration, _ := capturePlanFixture()
	registration.Reservation = reservation
	registration.Policy = p.LaunchAllocations[0].Policy
	registration.Request.ReservationID, registration.Request.HelperLeaseID, registration.Request.WorkerLeaseID = reservation.ID, p.Lease.ID, binding.WorkerLeaseID
	registration.Request.Cause.Target, registration.Request.Cause.CauseOperationID, registration.Request.Cause.CauseRequestID = reservation.Target, reservation.OperationID, reservation.RequestID
	registration.Request.Cause.RequestedBy, registration.Request.Cause.CancellationEpoch, registration.Request.Cause.EffectID = reservation.RequestedBy, reservation.CancellationEpoch, binding.EffectID
	registration.Worker.ID, registration.Worker.Target, registration.Worker.OperationID, registration.Worker.EffectID = binding.WorkerLeaseID, binding.Target, binding.OperationID, binding.EffectID
	registration.Worker.GrantSetID, registration.Worker.RuntimeManifest = reservation.GrantSetID, p.LaunchAllocations[0].Inputs.Sources.Runtime.Manifest
	if err := validateCaptureRegistration(registration); err != nil {
		t.Fatal(err)
	}
	p.Captures = []captureJournal{{Registration: registration, Binding: binding, Native: &captureNativeJournal{Phase: "registered", Lease: outside, PID: command.Process.Pid, BindingID: id}}}
	if err := m.save(p); err != nil {
		t.Fatal(err)
	}
	release := testRelease(p.Lease, testObservation(p.Lease))
	release.Cause.Target, release.Observation.Handle.Target = binding.Target, binding.Target
	effect := api.Effect{ID: release.Cause.EffectID, OperationID: release.Cause.CauseOperationID, Context: &release.Cause, HelperRelease: &release}
	expires := api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))
	claim := api.EffectLease{ClaimID: "native-drain-claim", ExpiresAt: expires, Record: api.EffectRecord{Effect: effect, State: api.EffectClaimed, Generation: 2, ClaimID: "native-drain-claim", ClaimantID: "native-drain-service", ClaimExpiresAt: expires}}
	value, err := randomID("native-capture-bytes-")
	if err != nil {
		t.Fatal(err)
	}
	return m, captureDrainQuery{Release: release, Claim: claim}, g, writes, [][]byte{[]byte(value), []byte("stderr " + string(value))}
}

func TestCaptureDrainNative(t *testing.T) {
	m, q, g, writers, data := nativeCaptureDrainFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// A live producer or local spool alone cannot authorize EOF/discharge.
	if _, err := m.dispatch(ctx, "capture_drain_snapshot", encodeLaunchFixture(t, q)); err == nil {
		t.Fatal("capture drain accepted open native pipes")
	}
	for i, w := range writers {
		if n, err := w.Write(data[i]); err != nil || n != len(data[i]) {
			t.Fatal("native pipe write failed", err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-g.done:
	case <-ctx.Done():
		t.Fatal("capture producer did not finish both actual pipe EOFs")
	}
	value, err := m.dispatch(ctx, "capture_drain_snapshot", encodeLaunchFixture(t, q))
	if err != nil {
		t.Fatal("capture drain could not measure original native spool", err)
	}
	snapshots, ok := value.([]api.CaptureDrainSnapshot)
	if !ok || len(snapshots) != 1 {
		t.Fatal("capture drain lost its native producer inventory")
	}
	snapshot := snapshots[0]
	if actual, err := m.reconcileCapture(ctx, snapshot.Binding); err != nil || !reflect.DeepEqual(actual, snapshot.Binding) {
		t.Fatal("capture monitor lost the terminal spool while service acknowledgement was pending", err)
	}
	q.Snapshot = &snapshot
	for i, s := range snapshot.Streams {
		q.StreamID, q.Offset = s.StreamID, 0
		value, err := m.dispatch(ctx, "capture_drain_read", encodeLaunchFixture(t, q))
		chunk, ok := value.(api.BlobChunk)
		if err != nil || !ok || !bytes.Equal(chunk.Data, data[i]) || chunk.SHA256 != digestBytes(data[i]) {
			t.Fatal("helper drain changed actual outside pipe bytes", err)
		}
	}
	q.StreamID = ""
	p, err := m.find(q.Release.LeaseID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.captureJobs(ctx, p); err == nil {
		t.Fatal("native local EOF discharged an unacknowledged service job")
	}
	pin, err := api.CaptureDrainDigest(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	// Explicit service-side comparison input: native acknowledgement validation
	// does not manufacture this receipt. The service/store regression supplies
	// the real writer-issued receipt through the authenticated helper client.
	receipt := api.CaptureDrainReceipt{EffectID: q.Release.Cause.EffectID, LeaseID: q.Release.LeaseID, SnapshotSHA256: pin, State: api.CaptureState{Binding: snapshot.Binding, Generation: 5, LastSeq: 9, Positions: []api.CapturePosition{}}}
	for _, s := range snapshot.Streams {
		receipt.State.Positions = append(receipt.State.Positions, api.CapturePosition{StreamID: s.StreamID, NextOffset: s.Bytes, EOF: true})
	}
	for _, mode := range []string{"foreign", "stale", "changed-range"} {
		bad := q
		bad.Receipt = &receipt
		switch mode {
		case "foreign":
			copy := snapshot
			copy.SpoolIdentity += "-changed"
			bad.Snapshot = &copy
		case "stale":
			bad.Claim.ClaimID = "stale-native-claim"
		case "changed-range":
			copy := receipt
			copy.State.Positions = append([]api.CapturePosition{}, receipt.State.Positions...)
			copy.State.Positions[0].NextOffset++
			bad.Receipt = &copy
		}
		if _, err := m.dispatch(ctx, "capture_drain_ack", encodeLaunchFixture(t, bad)); err == nil {
			t.Fatal("native capture drain accepted " + mode)
		}
	}
	q.Receipt = &receipt
	outside := p.Captures[0].Native.Lease
	survivorGroup := cleanupCgroup(t, m.binding, api.ID(string(outside.ID)+"-survivor"))
	survivor, releaseSurvivor, _ := cleanupHolder(t, survivorGroup, outside, m.bootID)
	if _, err := m.dispatch(ctx, "capture_drain_ack", encodeLaunchFixture(t, q)); err == nil {
		t.Fatal("capture drain discharged a UID with a live native survivor")
	}
	if err := releaseSurvivor.Close(); err != nil {
		t.Fatal(err)
	}
	if err := survivor.Wait(); err != nil {
		t.Fatal(err)
	}
	value, err = m.dispatch(ctx, "capture_drain_ack", encodeLaunchFixture(t, q))
	if err != nil || value != true {
		t.Fatal("native capture job did not acknowledge its measured discharge", err)
	}
	after, err := m.find(q.Release.LeaseID)
	if err != nil {
		t.Fatal(err)
	}
	jobs, err := m.captureJobs(ctx, after)
	if err != nil || jobs != 0 || !after.Captures[0].Native.Drain.Discharged {
		t.Fatal("acknowledged native capture remained queued", err)
	}
	if _, err := os.Lstat(filepath.Join(m.binding.cgroupPath(), string(after.Captures[0].Native.Lease.ContainmentID))); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("capture job discharged before real containment removal")
	}
	if !reflect.DeepEqual(*after.Captures[0].Native.Drain.Receipt, receipt) {
		t.Fatal("native discharge changed its service acknowledgement")
	}
	if captureReservesUID(after.Captures[0]) {
		t.Fatal("native discharge did not return its capture UID to the pool")
	}
	// An unrelated new job may reuse that UID. Archival still measures the
	// original removed containment and pinned spool, never that new process.
	reused, releaseReused, _ := cleanupHolder(t, survivorGroup, outside, m.bootID)
	if err := m.retainArchiveCaptures(ctx, &after); err != nil {
		t.Fatal("capture archive confused a discharged job with a reused UID", err)
	}
	if err := releaseReused.Close(); err != nil {
		t.Fatal(err)
	}
	if err := reused.Wait(); err != nil {
		t.Fatal(err)
	}
	// Reconnect/retry reads the durable helper journal after live ownership has
	// closed; it cannot replace the producer or count a missing owner as zero.
	restarted := newLeaseManager(m.binding, m.bootID, m.store, nil)
	restarted.resources = &linuxResources{binding: m.binding, manager: restarted}
	if value, err := restarted.dispatch(ctx, "capture_drain_ack", encodeLaunchFixture(t, q)); err != nil || value != true {
		t.Fatal("native drain replay lost its durable discharge", err)
	}
}

func TestCaptureDrainAbortNative(t *testing.T) {
	m, q, g, writers, _ := nativeCaptureDrainFixture(t)
	p, err := m.find(q.Release.LeaseID)
	if err != nil {
		t.Fatal(err)
	}
	live := m.captures[p.Captures[0].Binding.ID].(*nativeCapture)
	live.writers, live.taken = writers, false
	cause := q.Release.Cause
	cause.Kind = api.InternalHelperAbort
	abort := api.HelperAbortRequest{Cause: cause, LeaseID: q.Release.LeaseID, OperationID: cause.CauseOperationID, EffectID: cause.EffectID}
	claim := q.Claim
	claim.Record.Effect.HelperRelease = nil
	claim.Record.Effect.Context = &cause
	claim.Record.Effect.HelperAbort = &abort
	// This narrow interface is implemented by the installed helper only after
	// authenticating that exact nonexecuting stage; no agent exit is supplied.
	control, ok := any(m).(interface {
		captureAbortDrains(context.Context, api.HelperAbortRequest, api.EffectLease) ([]api.CaptureDrainSnapshot, error)
	})
	if !ok {
		t.Fatal("native helper has no nonexecuting capture drain stage")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stale := claim
	stale.ClaimID = "stale-abort-drain"
	if _, err := control.captureAbortDrains(ctx, abort, stale); err == nil {
		t.Fatal("stale abort claim closed native capture pipes")
	}
	snapshots, err := control.captureAbortDrains(ctx, abort, claim)
	if err != nil || len(snapshots) != 1 || snapshots[0].Abort == nil || !reflect.DeepEqual(*snapshots[0].Abort, abort) {
		t.Fatal("unopened allocation did not drain its original capture pipes", err)
	}
	select {
	case <-g.done:
	default:
		t.Fatal("capture abort returned before the actual producer wait")
	}
	for _, stream := range snapshots[0].Streams {
		if !stream.EOF || stream.Bytes != 0 || stream.SHA256 != digestBytes(nil) {
			t.Fatal("capture abort invented stdout or EOF")
		}
	}
	if _, err := m.captureJobs(ctx, p); err == nil {
		t.Fatal("local abort EOF replaced an authenticated service acknowledgement")
	}
	var pin api.CaptureDrainSnapshot
	if err := decodeStrict(encodeLaunchFixture(t, snapshots[0]), &pin); err != nil || !reflect.DeepEqual(pin, snapshots[0]) {
		t.Fatal("nonexecuting capture drain lost its exact helper wire pin", err)
	}
	digest, err := api.CaptureDrainDigest(pin)
	if err != nil {
		t.Fatal(err)
	}
	receipt := api.CaptureDrainReceipt{EffectID: abort.Cause.EffectID, LeaseID: abort.LeaseID, SnapshotSHA256: digest, State: api.CaptureState{Binding: pin.Binding, Generation: api.Generation(1 + len(pin.Streams)), LastSeq: api.Sequence(len(pin.Streams)), Positions: []api.CapturePosition{}}}
	for _, stream := range pin.Streams {
		receipt.State.Positions = append(receipt.State.Positions, api.CapturePosition{StreamID: stream.StreamID, NextOffset: stream.Bytes, EOF: true})
	}
	query := captureDrainQuery{Abort: &abort, Claim: claim, Snapshot: &pin, Receipt: &receipt}
	value, err := m.dispatch(ctx, "capture_drain_ack", encodeLaunchFixture(t, query))
	if err != nil || value != true {
		t.Fatal("nonexecuting capture job did not discharge after service acknowledgement", err)
	}
	after, err := m.find(abort.LeaseID)
	if err != nil {
		t.Fatal(err)
	}
	if jobs, err := m.captureJobs(ctx, after); err != nil || jobs != 0 {
		t.Fatal("nonexecuting capture remained queued after native discharge", err)
	}
}
