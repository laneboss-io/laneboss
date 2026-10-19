//go:build linux && laneboss_root_canary && laneboss_gate_integration

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// NaturalReleaseNative is test transport around the actual native helper.
// All counts, process generations, EOFs, receipts and removal come from its
// file journal and kernel owners, while the child owns the real SQLite store.
type NaturalReleaseNative struct {
	t        *testing.T
	m        *leaseManager
	main     *nativeGate
	producer *nativeGate
	writers  [2]*os.File
	finish   *os.File
	lease    api.ID
	uid      uint32
	config   string
}

// Use the same transient delegated-unit harness as TestWorkerLaunchNative.
// The native helper's controller prerequisites remain enforced unchanged.
func RunNaturalReleaseUnit(t *testing.T) {
	runReleaseUnit(t, "TestNaturalReleaseCanary", true)
}

func RunStoppedCaptureUnit(t *testing.T) {
	runReleaseUnit(t, "TestStoppedCaptureMonitorNative", true)
}

func RunCaptureLifetimeUnit(t *testing.T) {
	runReleaseUnit(t, "TestCapturePlanningDeadlineNative", true)
}

func runReleaseUnit(t *testing.T, name string, shipped bool) {
	t.Helper()
	self, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	id, err := randomID("release-")
	if err != nil {
		t.Fatal(err)
	}
	config := string(id[:23])
	directory, err := os.MkdirTemp("/run", "lb-v2-release-canary-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	binary := filepath.Join(directory, "canary")
	workerCanaryWrite(t, binary, self, 0555)
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	args := []string{"--quiet", "--wait", "--pipe", "--collect", "--unit=laneboss-helper@" + config + ".service"}
	if shipped {
		args = append(args, workerCanaryProperties(t, config)...)
		// ProtectHome hides the checkout. This fixture consumes only its
		// staged executable and protected runtime files, not source paths.
		cwd = directory
	} else {
		args = append(args, "--property=Slice=system.slice", "--property=Delegate=cpu memory pids", "--property=PrivateMounts=yes", "--property=NoNewPrivileges=yes", "--property=ProtectKernelTunables=yes", "--property=RestrictSUIDSGID=yes")
	}
	args = append(args, "--property=RuntimeMaxSec=80s", "--property=WorkingDirectory="+cwd, binary, "-test.run=^"+name+"$", "-test.v", "--", config, "natural-release-root")
	command := exec.CommandContext(ctx, "/usr/bin/systemd-run", args...)
	command.Env = []string{}
	command.WaitDelay = 3 * time.Second
	output, err := command.CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte("--- PASS: "+name+" ")) {
		t.Fatalf("delegated natural release canary failed: %v\n%s", err, output)
	}
	t.Log(string(output))
}

func NewNaturalReleaseNative(t *testing.T) *NaturalReleaseNative {
	t.Helper()
	config := os.Args[len(os.Args)-2]
	binding := testBinding()
	binding.Config = config
	membership, err := cgroupMembership(os.Getpid())
	unitMembership := strings.TrimPrefix(filepath.Dir(binding.cgroupPath()), "/sys/fs/cgroup")
	maintenance := len(os.Args) >= 4 && os.Args[len(os.Args)-3] == "installed-canary-root" && os.Args[len(os.Args)-1] == "agent-open-root"
	if err != nil || (membership != unitMembership && (!maintenance || membership != unitMembership+"/control")) {
		t.Fatal("natural release canary is outside its own delegated helper unit", err)
	}
	workerCanaryMounts(t)
	if err := setupCgroups(binding); err != nil {
		t.Fatal(err)
	}
	uid := uint32(100000 + os.Getpid())
	if err := uidQuiescent(context.Background(), uid); err != nil {
		t.Fatal("natural release needs an independently unused UID", err)
	}
	return &NaturalReleaseNative{t: t, uid: uid, config: config}
}

func (n *NaturalReleaseNative) Exchange(method string, raw json.RawMessage) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	switch method {
	case "identity":
		return struct {
			UID    uint32
			Config string
		}{n.uid, n.config}, nil
	case "capture":
		var binding api.CaptureBinding
		if err := decodeStrict(raw, &binding); err != nil {
			return nil, err
		}
		n.m, _, n.producer, n.writers, _ = nativeCaptureDrainFixtureFor(n.t, &binding)
		return n.m.captures[binding.ID].(*nativeCapture).binding, nil
	case "capture-lifetime":
		var input struct {
			Request     api.CaptureRegistrationRequest
			Worker      api.WorkerLease
			Reservation api.LaunchReservation
			Lease       api.HelperLease
		}
		if err := decodeStrict(raw, &input); err != nil {
			return nil, err
		}
		r, worker := input.Reservation, input.Worker
		id, err := randomID("capture-lifetime-")
		if err != nil {
			return nil, err
		}
		self, err := os.ReadFile("/proc/self/exe")
		if err != nil {
			return nil, err
		}
		binding := api.CaptureBinding{ID: id, Config: n.config, ReservationID: r.ID, Target: r.Target, LaunchID: r.LaunchID, HelperLeaseID: input.Lease.ID,
			OperationID: r.OperationID, RequestID: r.RequestID, RequestedBy: r.RequestedBy, Generation: 1, Status: "registered", WorkerLeaseID: worker.ID, EffectID: worker.EffectID,
			ProducerID: api.ID(string(id) + "-producer"), ProducerGeneration: "pending", BootID: "pending", Supervisor: &api.Executable{ID: "capture-canary", Version: testBinding().Release.Version, SHA256: digestBytes(self)},
			Streams: []api.CaptureStreamBinding{{ID: api.ID(string(id) + "-out"), PipeID: api.ID(string(id) + "-out-pipe"), Stream: "stdout"}, {ID: api.ID(string(id) + "-err"), PipeID: api.ID(string(id) + "-err-pipe"), Stream: "stderr"}}}
		n.m, _, n.producer, n.writers, _ = nativeCaptureDrainFixtureFor(n.t, &binding)
		live := n.m.captures[id].(*nativeCapture)
		outside := leaseRecord{Lease: live.lease, Request: api.HelperLeaseRequest{Config: n.config}, Phase: "active"}
		n.producer.mu.Lock()
		err = n.m.setCaptureDeadline(n.producer, outside, worker.ExpiresAt)
		if err == nil {
			n.producer.armWallTimerLocked()
		}
		n.producer.mu.Unlock()
		if err != nil {
			return nil, err
		}
		n.t.Cleanup(func() {
			n.producer.mu.Lock()
			if n.producer.wall != nil {
				n.producer.wall.Stop()
			}
			n.producer.mu.Unlock()
		})
		return live.binding, nil
	case "capture-past-planning":
		var input struct {
			ExpiresAt api.Timestamp `json:"expires_at"`
		}
		if err := decodeStrict(raw, &input); err != nil {
			return nil, err
		}
		stamp, err := time.Parse(time.RFC3339Nano, string(input.ExpiresAt))
		if err != nil {
			return nil, err
		}
		timer := time.NewTimer(max(0, time.Until(stamp)+200*time.Millisecond))
		defer timer.Stop()
		<-timer.C
		var live *nativeCapture
		for _, capture := range n.m.captures {
			live = capture.(*nativeCapture)
		}
		if live == nil {
			return nil, errors.New("native capture lifetime lost its original owner")
		}
		return n.producer.Observe(context.Background(), api.ProcessHandle{ID: live.binding.ProducerID, Target: live.binding.Target, ContainmentID: live.lease.ContainmentID, Generation: live.binding.ProducerGeneration})
	case "capture-finish-lifetime":
		var live *nativeCapture
		for _, capture := range n.m.captures {
			live = capture.(*nativeCapture)
		}
		if live == nil {
			return nil, errors.New("native capture finish lost its original owner")
		}
		value, err := randomID("late-capture-bytes-")
		if err != nil {
			return nil, err
		}
		for i, writer := range n.writers {
			data := []byte(string(value) + strconv.Itoa(i))
			if count, err := writer.Write(data); err != nil || count != len(data) {
				return nil, errors.New("native capture could not retain bytes after planner expiry")
			}
			if err := writer.Close(); err != nil {
				return nil, err
			}
		}
		select {
		case <-n.producer.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		observed, err := n.producer.Observe(ctx, api.ProcessHandle{ID: live.binding.ProducerID, Target: live.binding.Target, ContainmentID: live.lease.ContainmentID, Generation: live.binding.ProducerGeneration})
		if err != nil {
			return nil, err
		}
		if err := live.cleanExit(observed); err != nil {
			return nil, err
		}
		marker, err := readSpool(live.spool, live.binding)
		if err != nil {
			return nil, err
		}
		for i, position := range marker.Positions {
			if position.SHA256 != digestBytes([]byte(string(value)+strconv.Itoa(i))) || !position.PipeEOF {
				return nil, errors.New("native capture replaced late bytes or EOF")
			}
		}
		n.producer.mu.Lock()
		if n.producer.wall != nil {
			n.producer.wall.Stop()
		}
		n.producer.mu.Unlock()
		return true, nil
	case "prepare":
		return n.prepare(ctx, raw)
	case "open":
		var binding api.LaunchBindingRequest
		if err := decodeStrict(raw, &binding); err != nil {
			return nil, err
		}
		record, err := n.m.find(n.lease)
		if err != nil {
			return nil, err
		}
		cause := record.Gate.Request.Cause
		cause.Kind = api.InternalHelperOpen
		permit := api.LaunchPermit{LaunchID: binding.Record.ID, PreparedID: binding.Prepared.ID, RecordSHA256: binding.Identity.RecordSHA256, CommittedSeq: binding.Identity.CommittedSeq}
		open := api.HelperOpenRequest{Cause: cause, Prepared: binding.Prepared, Permit: permit, OperationID: cause.CauseOperationID, EffectID: cause.EffectID}
		if _, err := n.m.openGate(ctx, gateOpenRegistration{Request: open, Binding: binding, Policy: record.LaunchAllocations[0].Policy}); err != nil {
			return nil, err
		}
		return n.reconcile(ctx)
	case "end":
		if err := n.finish.Close(); err != nil {
			return nil, err
		}
		select {
		case <-n.main.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return n.reconcile(ctx)
	case "observe":
		var request api.HelperObserveRequest
		if err := decodeStrict(raw, &request); err != nil {
			return nil, err
		}
		return n.m.observeGate(ctx, request)
	case "reconcile_capture":
		var binding api.CaptureBinding
		if err := decodeStrict(raw, &binding); err != nil {
			return nil, err
		}
		return n.m.reconcileCapture(ctx, binding)
	case "reconcile_gate":
		var request api.HelperReconcileRequest
		if err := decodeStrict(raw, &request); err != nil {
			return nil, err
		}
		return n.m.reconcileGate(ctx, request)
	case "capture-stop-fence":
		var request api.HelperStopRequest
		if err := decodeStrict(raw, &request); err != nil {
			return nil, err
		}
		record, err := n.m.find(n.lease)
		if err != nil {
			return nil, err
		}
		// Model an existing in-progress credential projection, not a broker
		// success. The real stop fence and native kill/wait run below.
		record.Credentials = &credentialJournal{State: "receiving"}
		if err := n.m.save(record); err != nil {
			return nil, err
		}
		if err := n.m.killAndWait(ctx, record); err != nil {
			return nil, err
		}
		if err := n.m.fenceStopped(&record, request.Cause, "revoked"); err != nil {
			return nil, err
		}
		return n.m.observeGate(ctx, request.Target)
	case "capture-monitor-controls":
		record, err := n.m.find(n.lease)
		if err != nil {
			return nil, err
		}
		entry := record.Captures[0]
		if !record.Revoked || record.Credentials == nil || record.Credentials.Stop == nil || entry.Native.ArchiveObservation != nil || entry.Native.Drain != nil {
			return nil, errors.New("monitor rewrote revocation or manufactured terminal drain authority")
		}
		if err := n.m.requireActive(record, storageReady); err == nil {
			return nil, errors.New("stopped capture regained writable launch authority")
		}
		if jobs, err := n.m.captureJobs(ctx, record); err == nil || jobs == 0 {
			return nil, errors.New("local EOF discharged an unacknowledged capture")
		}
		foreign := entry.Binding
		foreign.Target.Run++
		if _, err := n.m.reconcileCapture(ctx, foreign); err == nil {
			return nil, errors.New("monitor accepted a foreign stopped run")
		}
		owned := n.m.captures[entry.Binding.ID]
		delete(n.m.captures, entry.Binding.ID)
		_, lostErr := n.m.reconcileCapture(ctx, entry.Binding)
		n.m.captures[entry.Binding.ID] = owned
		if lostErr == nil {
			return nil, errors.New("monitor accepted a missing original pipe owner")
		}
		without := record
		credentials := *record.Credentials
		credentials.Stop = nil
		without.Credentials = &credentials
		if err := n.m.save(without); err != nil {
			return nil, err
		}
		_, uncorrelated := n.m.reconcileCapture(ctx, entry.Binding)
		if err := n.m.save(record); err != nil {
			return nil, err
		}
		if uncorrelated == nil {
			return nil, errors.New("monitor accepted revocation without its retained stop cause")
		}
		live := owned.(*nativeCapture)
		file, err := live.spool.OpenFile("stdout", os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			return nil, err
		}
		value, err := randomID("damaged-capture-")
		if err != nil {
			file.Close()
			return nil, err
		}
		count, writeErr := file.Write([]byte(value))
		syncErr, closeErr := file.Sync(), file.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil || count != len(value) {
			return nil, errors.New("could not establish actual damaged-spool control")
		}
		if _, err := n.m.reconcileCapture(ctx, entry.Binding); err == nil {
			return nil, errors.New("stopped capture monitor accepted changed native spool bytes")
		}
		return true, nil
	case "capture_drain_snapshot", "capture_drain_read", "capture_drain_ack":
		return n.m.dispatch(ctx, method, raw)
	case "unblock":
		for _, writer := range n.writers {
			if err := writer.Close(); err != nil {
				return nil, err
			}
		}
		select {
		case <-n.producer.done:
			return n.producer.state != nil && n.producer.state.Success(), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	case "release":
		var request api.HelperReleaseRequest
		if err := decodeStrict(raw, &request); err != nil {
			return nil, err
		}
		return n.m.release(ctx, request)
	case "verify":
		var receipt api.ReleaseReceipt
		if err := decodeStrict(raw, &receipt); err != nil {
			return nil, err
		}
		record, err := n.m.find(n.lease)
		if err != nil || record.Phase != "released" || record.Receipt == nil || !reflect.DeepEqual(*record.Receipt, receipt) || record.Release == nil {
			return nil, errors.New("native helper did not retain the exact measured release")
		}
		jobs, err := n.m.captureJobs(ctx, record)
		if err != nil || jobs != 0 || len(record.Captures) != 1 || record.Captures[0].Native.Drain == nil || !record.Captures[0].Native.Drain.Discharged || record.Captures[0].Native.Drain.Receipt == nil {
			return nil, errors.New("native helper has no real drain acknowledgement and zero jobs")
		}
		for _, id := range []api.ID{record.Lease.ContainmentID, record.Captures[0].Native.Lease.ContainmentID} {
			if _, err := os.Lstat(filepath.Join(n.m.binding.cgroupPath(), string(id))); !errors.Is(err, os.ErrNotExist) {
				return nil, errors.New("native teardown left an original containment")
			}
		}
		again, err := n.m.release(ctx, *record.Release)
		if err != nil || !reflect.DeepEqual(again, receipt) {
			return nil, errors.New("native helper replay changed the measured receipt")
		}
		return true, nil
	}
	return nil, errors.New("unknown natural release canary transport operation")
}

func (n *NaturalReleaseNative) reconcile(ctx context.Context) (api.LaunchReconciliation, error) {
	record, err := n.m.find(n.lease)
	if err != nil {
		return api.LaunchReconciliation{}, err
	}
	return n.m.reconcileGate(ctx, api.HelperReconcileRequest{LeaseID: n.lease, LaunchID: record.Spec.Handoff.Spec.LaunchID, PreparedID: record.Gate.Prepared.ID, OperationID: record.Spec.Handoff.OperationID})
}

func (n *NaturalReleaseNative) prepare(ctx context.Context, raw json.RawMessage) (api.PreparedLaunch, error) {
	var input struct {
		Plan       api.LaunchPlan
		Handoff    api.PreparedSpecHandoff
		Prepared   api.PreparedLaunch
		Request    api.HelperLaunchRequest
		Allocation api.HelperLeaseRequest
		Worker     api.WorkerLease
		Policy     api.EffectivePolicy
	}
	if err := decodeStrict(raw, &input); err != nil {
		return api.PreparedLaunch{}, err
	}
	p, r := input.Plan, input.Plan.Reservation
	group := cleanupCgroup(n.t, n.m.binding, p.Lease.ContainmentID)
	var boot string
	n.main, _, boot, _, _, n.finish = descriptorGatePipes(n.t, n.writers, [2]uint32{n.uid, n.uid})
	if boot != n.m.bootID || p.Lease.UID != n.uid || p.Capture.BootID != boot {
		return api.PreparedLaunch{}, errors.New("native canary preparation changed its boot or UID")
	}
	input.Prepared.ProcessGeneration = n.main.Generation()
	n.lease = p.Lease.ID
	n.m.binding.Lanes[0].UID, n.m.binding.Lanes[0].GID = n.uid, n.uid
	root, err := os.OpenRoot(group)
	if err != nil {
		return api.PreparedLaunch{}, err
	}
	err = writeControl(root, "cgroup.procs", strconv.Itoa(n.main.PID()))
	closeErr := root.Close()
	if err != nil || closeErr != nil {
		return api.PreparedLaunch{}, errors.Join(err, closeErr)
	}
	allocation := launchAllocation{Request: input.Allocation, Reservation: r, Inputs: p.Inputs, Policy: input.Policy}
	cause := input.Allocation.Cause
	cause.Kind, cause.EffectID = api.InternalLaunchPlan, p.Capture.EffectID
	registration := captureRegistration{Reservation: r, Policy: input.Policy, Worker: input.Worker, Request: api.CaptureRegistrationRequest{Cause: cause, ReservationID: r.ID, HelperLeaseID: p.Lease.ID, WorkerLeaseID: p.Capture.WorkerLeaseID}}
	live := n.m.captures[p.Capture.ID].(*nativeCapture)
	record := leaseRecord{Schema: "laneboss.helper-lease.v2", BootID: boot, Request: input.Allocation, Lease: p.Lease, Phase: "active", IssuedAt: gateTimestamp(), LaunchAllocations: []launchAllocation{allocation},
		Spec:        &specRegistration{Plan: &p, Handoff: input.Handoff, Original: encodeLaunchFixture(n.t, input.Handoff.Spec)},
		SpecReceipt: &api.PreparedSpecReceipt{SpecID: r.SpecID, Config: r.Config, Target: r.Target, LeaseID: p.Lease.ID, SpecSHA256: input.Handoff.SpecSHA256, RuntimeManifest: p.Inputs.Sources.Runtime.Manifest, OperationID: r.OperationID},
		Gate:        &gateJournal{Request: input.Request, Prepared: input.Prepared, State: "prepared", PID: n.main.PID(), NativeProfile: "offline-private-v1"},
		Captures:    []captureJournal{{Registration: registration, Binding: p.Capture, Native: &captureNativeJournal{Phase: "registered", Lease: live.lease, PID: live.gate.PID(), BindingID: p.Capture.ID}}}}
	canonical, err := api.CanonicalJSON(record.Spec.Original)
	if err != nil {
		return api.PreparedLaunch{}, err
	}
	record.Spec.Original = canonical
	record.Storage = &launchStorageRecord{Binding: api.LaunchStorage{ReservationID: r.ID, Target: r.Target, LeaseID: p.Lease.ID, WorkspaceID: p.Data.Workspace.ID, Home: p.Data.Home}, Directories: []storageIdentity{{ID: p.Data.Workspace.ID}, {ID: p.Data.Home.RootID}, {ID: p.Data.Home.Home.HistoryID}}}
	for _, name := range []string{"/var/lib/laneboss-v2/lanes", filepath.Dir(storageBase(n.m.binding, record))} {
		if err := os.Mkdir(name, 0700); err == nil {
			path := name
			n.t.Cleanup(func() {
				if err := os.Remove(path); err != nil {
					n.t.Error(err)
				}
			})
		} else if !errors.Is(err, os.ErrExist) {
			return api.PreparedLaunch{}, err
		}
	}
	stage := storageBase(n.m.binding, record)
	if err := createLaneStage(stage, n.uid); err != nil {
		return api.PreparedLaunch{}, err
	}
	n.t.Cleanup(func() {
		if err := os.RemoveAll(stage); err != nil {
			n.t.Error(err)
		}
	})
	storage, err := os.OpenRoot(stage)
	if err != nil {
		return api.PreparedLaunch{}, err
	}
	err = syncStorageDirectories(ctx, storage, &record, 0, true)
	closeErr = storage.Close()
	if err != nil || closeErr != nil {
		return api.PreparedLaunch{}, errors.Join(err, closeErr)
	}
	// Keep a closed, real socket owner so zero live readiness connections is
	// measured by the normal native inventory rather than supplied by a test.
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return api.PreparedLaunch{}, err
	}
	file := os.NewFile(uintptr(pair[0]), "natural-release-readiness")
	connection, err := net.FileConn(file)
	closeErr = file.Close()
	peerErr := unix.Close(pair[1])
	if err != nil || closeErr != nil || peerErr != nil {
		return api.PreparedLaunch{}, errors.Join(err, closeErr, peerErr)
	}
	n.main.control = connection.(*net.UnixConn)
	if err := connection.Close(); err != nil {
		return api.PreparedLaunch{}, err
	}
	n.m.gates = map[api.ID]ownedGate{p.Lease.ID: n.main}
	if err := n.m.save(record); err != nil {
		return api.PreparedLaunch{}, err
	}
	return input.Prepared, nil
}
