//go:build linux

package admin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// A real re-executed process exercises the production descriptor wait. It has
// no model, service authority or simulated native success. This component
// fixture does not claim bwrap/installed UID confinement; the separately tagged
// installed test exercises that complete native start.
func init() {
	if handled, code := RunBootstrapEntry(context.Background(), os.Args[1:]); handled {
		os.Exit(code)
	}
	if len(os.Args) == 3 && os.Args[1] == "admin-native-restriction-fixture" {
		nativeRestrictionFixture(os.Args[2])
		os.Exit(29)
	}
	if len(os.Args) == 2 && os.Args[1] == "admin-gate-descriptor-fixture" {
		payload, err := readBootstrapInput()
		if err != nil {
			os.Exit(21)
		}
		ready := os.NewFile(5, "fixture-readiness")
		if n, err := ready.WriteString(payload.Token); err != nil || n != len(payload.Token) {
			os.Exit(22)
		}
		err = executePreparedGate(payload)
		runtime.KeepAlive(ready)
		if err != nil {
			os.Exit(23)
		}
		os.Exit(24)
	}
	if len(os.Args) == 3 && os.Args[1] == "admin-gate-descriptor-vendor" {
		if n, err := os.Stdout.WriteString(os.Args[2]); err != nil || n != len(os.Args[2]) {
			os.Exit(24)
		}
		var hold [1]byte
		if n, err := os.Stdin.Read(hold[:]); n != 0 || err != io.EOF {
			os.Exit(28)
		}
		os.Exit(0)
	}
	if len(os.Args) == 6 && os.Args[1] == "internal" && os.Args[2] == "helper" && os.Args[3] == "--config" {
		if err := RunInternal(context.Background(), os.Args[4], os.Args[5:]); err != nil {
			os.Exit(25)
		}
		os.Exit(0)
	}
	if len(os.Args) == 3 && os.Args[1] == "admin-gate-native-canary" {
		if err := os.WriteFile("/work/main/executed", []byte(os.Args[2]), 0600); err != nil {
			os.Exit(26)
		}
		if n, err := os.Stdout.WriteString(os.Args[2]); err != nil || n != len(os.Args[2]) {
			os.Exit(27)
		}
		os.Exit(0)
	}
}

func descriptorGate(t *testing.T, identities ...[2]uint32) (*nativeGate, *os.File, string, uint32, uint32, *os.File) {
	return descriptorGatePipes(t, [2]*os.File{}, identities...)
}

func descriptorGatePipes(t *testing.T, captures [2]*os.File, identities ...[2]uint32) (*nativeGate, *os.File, string, uint32, uint32, *os.File) {
	return descriptorGateAuthentication(t, captures, "", identities...)
}

func descriptorGateAuthentication(t *testing.T, captures [2]*os.File, authentication string, identities ...[2]uint32) (*nativeGate, *os.File, string, uint32, uint32, *os.File) {
	return descriptorGateAuthenticationMode(t, captures, authentication, "before-exec", "", identities...)
}

func descriptorGateAuthenticationMode(t *testing.T, captures [2]*os.File, authentication, mode, binary string, identities ...[2]uint32) (*nativeGate, *os.File, string, uint32, uint32, *os.File) {
	t.Helper()
	token, err := randomID("fixture-release-")
	if err != nil {
		t.Fatal(err)
	}
	input, err := sealedBootstrap(gatePayload{Token: string(token), CredentialRequired: authentication != "", GateID: "gate-release", PreparedID: "gate-prepared",
		Argv: []string{"/proc/self/fd/6", "admin-gate-descriptor-vendor", string(token)}, Environment: []string{}, Paths: []bootstrapPath{}})
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	releaseRead, releaseWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer releaseRead.Close()
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readyRead.Close()
	defer readyWrite.Close()
	if authentication != "" {
		readyRead, readyWrite = authenticationReadiness(t)
		defer readyRead.Close()
		defer readyWrite.Close()
	}
	canaryRead, canaryWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer canaryWrite.Close()
	holdRead, holdWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer holdRead.Close()
	if binary == "" {
		binary = "/proc/self/exe"
	}
	executable, err := os.Open(binary)
	if err != nil {
		t.Fatal(err)
	}
	defer executable.Close()
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	if uid == 0 {
		uid, gid = 61001, 61001
	}
	if len(identities) == 1 {
		uid, gid = identities[0][0], identities[0][1]
	}
	cmd := exec.Command("/proc/self/fd/6", "admin-gate-descriptor-fixture")
	if authentication != "" {
		cmd = exec.Command("/proc/self/fd/6", "admin-gate-authentication-fixture", authentication, mode)
	}
	cmd.Env, cmd.ExtraFiles, cmd.Stdout = []string{}, []*os.File{input, releaseRead, readyWrite, executable}, canaryWrite
	cmd.Stdin = holdRead
	if captures[0] != nil && captures[1] != nil {
		cmd.Stdout, cmd.Stderr = captures[0], captures[1]
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}, NoSetGroups: os.Geteuid() != 0}}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pidfd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	generation, err := processGeneration(cmd.Process.Pid, strings.TrimSpace(string(boot)))
	if err != nil {
		t.Fatal(err)
	}
	g := &nativeGate{command: cmd, pidfd: pidfd, generation: generation, release: releaseWrite, token: string(token), done: make(chan struct{})}
	go func() {
		err := cmd.Wait()
		g.mu.Lock()
		g.waitErr, g.state = err, cmd.ProcessState
		close(g.done)
		g.mu.Unlock()
	}()
	if authentication != "" {
		authenticationGateReady(t, g, readyRead, readyWrite)
	} else {
		if err := readyRead.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		ready := make([]byte, len(token))
		if _, err := io.ReadFull(readyRead, ready); err != nil || string(ready) != string(token) {
			t.Fatalf("real gate readiness failed: %v", err)
		}
	}
	t.Cleanup(func() {
		holdWrite.Close()
		if err := g.Close(); err != nil {
			t.Error(err)
		}
		select {
		case <-g.done:
		case <-time.After(5 * time.Second):
			t.Error("real gate fixture did not stop")
		}
		canaryRead.Close()
		unix.Close(pidfd)
	})
	return g, canaryRead, strings.TrimSpace(string(boot)), uid, gid, holdWrite
}

func assertGateClosed(t *testing.T, reader *os.File, diagnostic string) {
	t.Helper()
	fds := []unix.PollFd{{Fd: int32(reader.Fd()), Events: unix.POLLIN}}
	count, err := unix.Poll(fds, 100)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 || fds[0].Revents != 0 {
		t.Fatal(diagnostic)
	}
}

func TestNativeDescriptorGate(t *testing.T) {
	g, reader, _, _, _, finish := descriptorGate(t)
	assertGateClosed(t, reader, "acceptance: vendor canary executed before gate release")
	if err := g.Release(); err != nil {
		t.Fatal(err)
	}
	if err := reader.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	actual := make([]byte, len(g.token))
	if _, err := io.ReadFull(reader, actual); err != nil || string(actual) != g.token {
		t.Fatalf("released canary bytes differ: %v", err)
	}
	if err := g.Release(); err == nil {
		t.Fatal("acceptance: native gate release was reusable")
	}
	if err := finish.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	observation, err := g.Stop(ctx, api.ProcessHandle{})
	if err != nil || observation.State != "exited" || observation.ExitCode == nil || *observation.ExitCode != 0 {
		t.Fatalf("native wait did not observe actual successful exit: %v", err)
	}
}

func TestNativeGateForeignRelease(t *testing.T) {
	for _, mode := range []string{"foreign", "owner-eof", "extra"} {
		t.Run(mode, func(t *testing.T) {
			g, reader, _, _, _, _ := descriptorGate(t)
			if mode == "foreign" {
				if _, err := g.release.WriteString(strings.Repeat("x", len(g.token))); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "extra" {
				if _, err := g.release.WriteString(g.token + "extra"); err != nil {
					t.Fatal(err)
				}
			}
			if err := g.release.Close(); err != nil {
				t.Fatal(err)
			}
			g.release = nil
			if err := reader.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if n, err := reader.Read(make([]byte, 1)); n != 0 || err != io.EOF {
				t.Fatal("acceptance: refused release produced vendor output")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			observation, err := g.Stop(ctx, api.ProcessHandle{})
			if err != nil || observation.ExitCode == nil || *observation.ExitCode != 23 {
				t.Fatal("acceptance: foreign or missing descriptor release ran the canary")
			}
		})
	}
}

// The retained plan below is comparison input for OpenGate. Its component
// source fixture owns actual bytes. No credential injection, materialization
// job or authenticated vendor is claimed by this gate-journal test.
// The component gate is a single actual re-executed process, without a real
// cgroup. Count its kernel task directory instead of manufacturing a live
// population or weakening the production containment-counter prerequisite.
type retainedGateResources struct {
	observedResources
	gate *nativeGate
}

func (r *retainedGateResources) Survivors(ctx context.Context, record leaseRecord) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if record.Gate == nil || record.Gate.PID != r.gate.PID() || record.Gate.Prepared.ProcessGeneration != r.gate.Generation() {
		return 0, failure(api.CodeContainmentUnknown, "component gate counter lost its actual process")
	}
	generation, err := processGeneration(record.Gate.PID, record.BootID)
	if err != nil || generation != r.gate.Generation() {
		return 0, failure(api.CodeContainmentUnknown, "component gate counter process lifetime changed")
	}
	tasks, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", record.Gate.PID))
	if err != nil {
		return 0, err
	}
	return uint64(len(tasks)), nil
}

func retainedGateFixture(t *testing.T, identities ...[2]uint32) (*leaseManager, gateOpenRegistration, *nativeGate, *os.File, *fileLeaseStore) {
	t.Helper()
	m, registration, g, reader, store, _ := retainedGateFixtureControl(t, identities...)
	return m, registration, g, reader, store
}

func retainedGateFixtureControl(t *testing.T, identities ...[2]uint32) (*leaseManager, gateOpenRegistration, *nativeGate, *os.File, *fileLeaseStore, *os.File) {
	t.Helper()
	g, reader, boot, uid, gid, hold := descriptorGate(t, identities...)
	m, registration, g, reader, store := retainedGateFromNative(t, g, reader, boot, uid, gid, identities...)
	return m, registration, g, reader, store, hold
}

func exitGateFixture(t *testing.T) (*leaseManager, gateOpenRegistration, *nativeGate, *os.File, *fileLeaseStore, *os.File) {
	t.Helper()
	return retainedGateFixtureControl(t)
}

func retainedGateFromNative(t *testing.T, g *nativeGate, reader *os.File, boot string, uid, gid uint32, identities ...[2]uint32) (*leaseManager, gateOpenRegistration, *nativeGate, *os.File, *fileLeaseStore) {
	return retainedGateFromNativeHash(t, g, reader, boot, uid, gid, "", identities...)
}

func retainedGateFromNativeHash(t *testing.T, g *nativeGate, reader *os.File, boot string, uid, gid uint32, expected api.Digest, identities ...[2]uint32) (*leaseManager, gateOpenRegistration, *nativeGate, *os.File, *fileLeaseStore) {
	t.Helper()
	service, retained, _, _ := seedLaunchFiles(t)
	sources, err := service.ResolveLaunchSources(context.Background(), api.LaunchSourceRequest{ReservationID: retained.plan.Reservation.ID, GrantSetID: retained.grants.ID, Claim: fixtureLaunchClaim(retained)})
	if err != nil {
		t.Fatal(err)
	}
	r := retained.plan.Reservation
	if g.execAck != nil {
		self, err := os.ReadFile("/proc/self/exe")
		if err != nil {
			t.Fatal(err)
		}
		sources.Runtime.Executable.SHA256 = digestBytes(self)
	}
	if expected != "" {
		sources.Runtime.Executable.SHA256 = expected
	}
	lease := api.HelperLease{ID: "gate-lease", UID: uid, GID: gid, ContainmentID: "gate-containment", EndpointGeneration: 1}
	if len(identities) == 1 {
		lease.ID, err = randomID("normal-release-")
		if err != nil {
			t.Fatal(err)
		}
		lease.ContainmentID = api.ID(string(lease.ID) + "-cg")
	}
	workspace := api.Workspace{ID: "gate-work", ProjectID: sources.Project.ProjectID, Base: sources.Project.Base, Branch: "lane/" + string(r.Target.LifeID), LogicalCWD: "/work/main",
		Snapshot: retained.retain("gate-snapshot", "manifest", []byte("comparison workspace input"), r.OperationID, r.Target.LifeID)}
	home := api.PrivateHomeBinding{LifeID: r.Target.LifeID, RootID: "gate-home-root", Generation: 1, Home: api.PrivateHome{ID: "gate-home", WorkspaceID: workspace.ID, VendorDirectory: ".codex", HistoryID: "gate-history"}}
	materialization := api.Materialization{GrantSetID: retained.grants.ID, Manifest: retained.retain("gate-materialization", "manifest", []byte("comparison receipt input"), r.OperationID, r.Target.LifeID),
		Objects: []api.MaterializedObject{{GrantID: sources.Project.GrantID, WorkspaceID: workspace.ID, SnapshotSHA256: workspace.Snapshot.SHA256, SourceIdentity: "comparison-source", DestinationIdentity: "comparison-destination"}}}
	slot := api.CredentialSlot{ID: "comparison-slot", ProfileGrantID: "profile-a", ProfileID: "approved-profile", LeaseID: "comparison-credential-lease", Mode: "codex-file", ExpiresAt: retained.grants.ExpiresAt}
	runner := api.RunnerPlan{Driver: api.DriverCodex, Executable: sources.Runtime.Executable, Argv: []string{"/runtime/agent"}, CWD: workspace.LogicalCWD, EnvironmentNames: []string{}, Home: home.Home, Slot: slot,
		Prompt: retained.retain("gate-prompt", "prompt", []byte("comparison prompt input"), r.OperationID, r.Target.LifeID), AdapterVersion: "component-v1",
		Session: api.Session{ID: "gate-session", Driver: api.DriverCodex, VendorVersion: sources.Runtime.Executable.Version, HomeID: home.Home.ID, HistoryID: home.Home.HistoryID, LogicalCWD: workspace.LogicalCWD}}
	registration, _ := capturePlanFixture()
	registration.Request.HelperLeaseID = lease.ID
	registration.Reservation = r
	capture, err := refusedCaptureBinding(registration, lease)
	if err != nil {
		t.Fatal(err)
	}
	policy := registration.Policy
	plan := api.LaunchPlan{Reservation: r, Lease: lease, Inputs: api.LaunchInputs{Grants: retained.grants, Sources: sources},
		Data:   api.LaunchData{ReservationID: r.ID, Target: r.Target, LeaseID: lease.ID, Source: sources.Project, Workspace: workspace, Home: home, Materialization: materialization},
		Runner: runner, Budget: testAllocation().Budget, Capture: capture, CapturePolicy: &policy,
		Injection: api.Injection{Target: r.Target, SlotIDs: []api.ID{slot.ID}, TaskSecretNames: []string{}, TaskSecretFileNames: []string{}, GrantIDs: []api.ID{}, SourceVersions: []string{}, Outcome: "prepared"}}
	if err := api.ValidateLaunchPlan(plan); err != nil {
		t.Fatal(err)
	}
	spec := api.LaunchSpec{Kind: "agent", PlanID: r.ID, Capture: &capture, ID: r.SpecID, Target: r.Target, LaunchID: r.LaunchID, Backend: sources.Runtime.Backend,
		UIDLeaseID: lease.ID, Workspace: workspace, Materialization: materialization, Grants: retained.grants, Runner: &runner, Injection: plan.Injection, Budget: plan.Budget,
		EndpointGeneration: 1, RuntimeManifest: sources.Runtime.Manifest, PolicyGeneration: r.PolicyGeneration}
	encoded := encodeLaunchFixture(t, spec)
	canonical, err := api.CanonicalJSON(encoded)
	if err != nil {
		t.Fatal(err)
	}
	cause := testCause(api.InternalHelperRegister, r.Target.LifeID)
	cause.CancellationEpoch = r.CancellationEpoch
	handoff := api.PreparedSpecHandoff{Cause: cause, Config: r.Config, Spec: spec, Original: api.BlobRef{ID: "gate-spec-bytes", Class: "launch_spec", Bytes: int64(len(canonical)), SHA256: digestBytes(canonical)}, SpecSHA256: digestBytes(canonical), OperationID: r.OperationID, RequestID: r.RequestID}
	prepared := api.PreparedLaunch{ID: "gate-prepared", GateID: "gate-release", SpecSHA256: handoff.SpecSHA256, Target: r.Target, ContainmentID: lease.ContainmentID, ProcessGeneration: g.Generation(), EndpointGeneration: 1}
	record := api.LaunchRecord{Kind: "agent", ID: r.LaunchID, Config: r.Config, Target: r.Target, RootLifeID: r.RootLifeID, StarterChain: r.StarterChain,
		Actor: api.Actor{Kind: "lane", ID: "gate-principal", LifeID: r.Target.LifeID, Level: r.Level, Role: r.Role}, UIDLeaseID: lease.ID, HostUID: uid,
		ProcessGeneration: g.Generation(), ContainmentID: lease.ContainmentID, GrantSetID: retained.grants.ID, GrantsSHA256: retained.grants.SHA256, PolicyGeneration: r.PolicyGeneration, EndpointGeneration: 1}
	recordBytes := encodeLaunchFixture(t, record)
	recordCanonical, err := api.CanonicalJSON(recordBytes)
	if err != nil {
		t.Fatal(err)
	}
	identity := api.IdentityCommit{LaunchID: record.ID, EventID: "gate-identity", CommittedSeq: 7, RecordSHA256: digestBytes(recordCanonical)}
	binding := api.LaunchBindingRequest{Record: record, Prepared: prepared, Identity: identity, Recovery: &api.LaunchRecovery{PlanID: r.ID, OriginalRequest: r.OriginalRequest, Handoff: handoff, Home: home, Capture: capture}}
	if err := api.ValidateLaunchBindingPlan(binding, plan); err != nil {
		t.Fatal(err)
	}
	prepareCause := cause
	prepareCause.Kind = api.InternalHelperPrepare
	allocation := testAllocation()
	allocation.ReservationID, allocation.Cause.CancellationEpoch = r.ID, r.CancellationEpoch
	owned := leaseRecord{Schema: "laneboss.helper-lease.v2", BootID: boot, Request: allocation, Lease: lease, Phase: "active", IssuedAt: gateTimestamp(),
		Spec: &specRegistration{Plan: &plan, Handoff: handoff, Original: canonical}, SpecReceipt: &api.PreparedSpecReceipt{SpecID: spec.ID, Config: r.Config, Target: r.Target, LeaseID: lease.ID, SpecSHA256: handoff.SpecSHA256, RuntimeManifest: spec.RuntimeManifest, OperationID: r.OperationID},
		Gate: &gateJournal{Request: api.HelperLaunchRequest{Cause: prepareCause, LeaseID: lease.ID, PreparedSpecID: spec.ID, SpecSHA256: handoff.SpecSHA256}, Prepared: prepared, State: "prepared", PID: g.PID()}}
	owned.LaunchAllocations = []launchAllocation{{Request: allocation, Reservation: r, Inputs: plan.Inputs, Policy: policy}}
	owned.Captures = []captureJournal{{Registration: registration, Binding: capture}}
	owned.Storage = &launchStorageRecord{Binding: api.LaunchStorage{ReservationID: r.ID, Target: r.Target, LeaseID: lease.ID, WorkspaceID: workspace.ID, Home: home},
		Directories: []storageIdentity{{ID: workspace.ID}, {ID: home.RootID}, {ID: home.Home.HistoryID}}}
	privatePath := privateTestDir(t)
	if err := os.Chown(privatePath, os.Geteuid(), int(gid)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(privatePath, 0710); err != nil {
		t.Fatal(err)
	}
	private, err := os.OpenRoot(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { private.Close() })
	if err := syncStorageDirectories(context.Background(), private, &owned, uint32(os.Geteuid()), true); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	store := &fileLeaseStore{root: root, owner: uint32(os.Geteuid())}
	if err := store.Save(owned); err != nil {
		t.Fatal(err)
	}
	installed := testBinding()
	installed.Lanes[0].UID, installed.Lanes[0].GID = uid, gid
	m := newLeaseManager(installed, boot, store, &retainedGateResources{gate: g})
	m.gates = map[api.ID]ownedGate{lease.ID: g}
	openCause := cause
	openCause.Kind = api.InternalHelperOpen
	request := api.HelperOpenRequest{Cause: openCause, Prepared: prepared, Permit: api.LaunchPermit{LaunchID: record.ID, PreparedID: prepared.ID, RecordSHA256: identity.RecordSHA256, CommittedSeq: identity.CommittedSeq}, OperationID: r.OperationID, EffectID: openCause.EffectID}
	return m, gateOpenRegistration{Request: request, Binding: binding, Policy: policy}, g, reader, store
}

func TestGateCommittedOpen(t *testing.T) {
	m, registration, g, reader, store := retainedGateFixture(t)
	request := registration.Request
	changed := registration
	changed.Request.Permit.RecordSHA256 = testDigest("foreign committed identity")
	if _, err := m.openGate(context.Background(), changed); err == nil {
		t.Fatal("acceptance: native gate accepted a foreign committed permit")
	}
	assertGateClosed(t, reader, "acceptance: refused permit executed the real canary")
	handle, err := m.openGate(context.Background(), registration)
	if err != nil || handle.Generation != g.Generation() {
		t.Fatalf("committed gate did not open: %v", err)
	}
	if _, err := m.openGate(context.Background(), registration); err == nil {
		t.Fatal("acceptance: helper opened a gate twice")
	}
	records, err := store.Records()
	if err != nil || len(records) != 1 || records[0].Gate.State != "opened" || records[0].Gate.Permit == nil || *records[0].Gate.Permit != request.Permit {
		t.Fatal("acceptance: second open rewrote the consumed gate journal")
	}
	if err := reader.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	actual := make([]byte, len(g.token))
	if _, err := io.ReadFull(reader, actual); err != nil || string(actual) != g.token {
		t.Fatalf("opened process did not execute the actual canary: %v", err)
	}
}

func TestFixtureUmask022(t *testing.T) {
	previous := syscall.Umask(0022)
	defer syscall.Umask(previous)
	m, registration, _, reader, store := retainedGateFixture(t)
	records, err := store.Records()
	if err != nil || len(records) != 1 || records[0].Storage == nil || !records[0].Storage.Ready {
		t.Fatal("acceptance: umask 022 fixture lacks ready private storage")
	}
	info, err := store.root.Stat(".")
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("acceptance: umask 022 fixture lacks a private journal parent")
	}
	request := registration.Request
	query := api.HelperReconcileRequest{LeaseID: registration.Binding.Record.UIDLeaseID, LaunchID: request.Permit.LaunchID,
		PreparedID: request.Prepared.ID, OperationID: request.OperationID}
	reconciled, err := m.reconcileGate(context.Background(), query)
	if err != nil || reconciled.Prepared == nil || *reconciled.Prepared != request.Prepared || reconciled.GateState != "prepared" || reconciled.Process != nil || reconciled.ConsumedPermit != nil {
		t.Fatalf("acceptance: umask 022 fixture did not reconcile its closed gate: %v", err)
	}
	assertGateClosed(t, reader, "acceptance: umask 022 fixture released the closed gate")
}

func TestGateRetainedReconciliation(t *testing.T) {
	m, registration, g, reader, store := retainedGateFixture(t)
	request := registration.Request
	query := api.HelperReconcileRequest{LeaseID: "gate-lease", LaunchID: request.Permit.LaunchID, PreparedID: request.Prepared.ID, OperationID: request.OperationID}
	// A service restart reconnects to the same running helper. Its native gate
	// and the mutex protecting that state must retain a single owner.
	serviceRestart := m
	m.credentialLeaseMu.Lock()
	if serviceRestart.credentialLeaseMu.TryLock() {
		serviceRestart.credentialLeaseMu.Unlock()
		m.credentialLeaseMu.Unlock()
		t.Fatal("acceptance: service restart replaced the helper lock owner")
	}
	m.credentialLeaseMu.Unlock()
	reconciled, err := serviceRestart.reconcileGate(context.Background(), query)
	if err != nil || reconciled.Prepared == nil || *reconciled.Prepared != request.Prepared || reconciled.Process != nil || reconciled.GateState != "prepared" || reconciled.ConsumedPermit != nil || reconciled.Observation.State != "running" || reconciled.Observation.Handle.Generation != g.Generation() {
		t.Fatal("acceptance: retained reconciliation changed or released the closed gate")
	}
	// A helper restart reopens the durable bytes through a fresh store and
	// constructs a new owner. No old process descriptor or lock is copied.
	reopened, err := os.OpenRoot(store.root.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Error(err)
		}
	})
	helperRestart := newLeaseManager(m.binding, m.bootID,
		&fileLeaseStore{root: reopened, owner: store.owner}, &observedResources{})
	_, err = helperRestart.reconcileGate(context.Background(), query)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeContainmentUnknown {
		t.Fatal("acceptance: lost gate ownership relaunched or reconciled a replacement")
	}
	if g.PID() != m.gates[query.LeaseID].PID() {
		t.Fatal("retained process PID changed")
	}
	assertGateClosed(t, reader, "acceptance: restart released the real canary")
}

func TestGateCurrentCapturePolicy(t *testing.T) {
	m, registration, _, reader, _ := retainedGateFixture(t)
	registration.Policy.AllowCaptureRefusal = false
	if _, err := m.openGate(context.Background(), registration); err == nil {
		t.Fatal("acceptance: disabled D6 policy released the real gate")
	}
	assertGateClosed(t, reader, "acceptance: disabled capture policy executed the canary")
}

type releaseOrderGate struct {
	ownedGate
	store  leaseStorage
	permit api.LaunchPermit
}

func (g *releaseOrderGate) Release() error {
	records, err := g.store.Records()
	if err != nil {
		return err
	}
	if len(records) != 1 || records[0].Gate == nil || records[0].Gate.State != "opening" || records[0].Gate.Permit == nil || *records[0].Gate.Permit != g.permit {
		return failure(api.CodeIntegrity, "release preceded its actual durable permit journal")
	}
	return g.ownedGate.Release()
}

func TestGateDurableReleaseOrder(t *testing.T) {
	m, registration, g, reader, store := retainedGateFixture(t)
	m.gates["gate-lease"] = &releaseOrderGate{ownedGate: g, store: store, permit: registration.Request.Permit}
	if _, err := m.openGate(context.Background(), registration); err != nil {
		t.Fatalf("acceptance: release preceded its durable permit journal: %v", err)
	}
	if err := reader.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	actual := make([]byte, len(g.token))
	if _, err := io.ReadFull(reader, actual); err != nil || string(actual) != g.token {
		t.Fatal("ordered release did not run the actual canary")
	}
}

type interruptedGateStore struct{ leaseStorage }

func (s *interruptedGateStore) Save(record leaseRecord) error {
	if err := s.leaseStorage.Save(record); err != nil {
		return err
	}
	if record.Gate != nil && record.Gate.State == "opening" {
		return failure(api.CodeIntegrity, "injected lost durable write reply")
	}
	return nil
}

func TestGateUncertainOpening(t *testing.T) {
	m, registration, _, reader, store := retainedGateFixture(t)
	m.store = &interruptedGateStore{leaseStorage: store}
	if _, err := m.openGate(context.Background(), registration); err == nil {
		t.Fatal("lost write reply returned gate success")
	}
	m.store = store
	request := registration.Request
	_, err := m.reconcileGate(context.Background(), api.HelperReconcileRequest{LeaseID: "gate-lease", LaunchID: request.Permit.LaunchID, PreparedID: request.Prepared.ID, OperationID: request.OperationID})
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeContainmentUnknown {
		t.Fatal("acceptance: uncertain opening became a usable gate")
	}
	assertGateClosed(t, reader, "acceptance: uncertain durable write released the canary")
}

func TestNativeBootstrapLifetime(t *testing.T) {
	g, _, boot, _, _, _ := descriptorGate(t)
	fd, err := unix.FcntlInt(uintptr(g.pidfd), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	g.innerPID, g.innerFD, g.innerGeneration = g.PID(), fd, g.Generation()
	if err := g.innerLifetime(boot); err != nil {
		t.Fatal(err)
	}
	g.innerGeneration = boot + ":foreign-generation"
	if err := g.innerLifetime(boot); err == nil {
		t.Fatal("acceptance: actual bootstrap generation mismatch was accepted")
	}
}
