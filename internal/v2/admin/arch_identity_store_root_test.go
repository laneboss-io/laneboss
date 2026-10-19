//go:build linux && laneboss_root_canary

package admin_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime/pprof"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/identity"
	peerlinux "laneboss.io/laneboss/internal/v2/peer/linux"
	"laneboss.io/laneboss/internal/v2/service"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

type archiveNativeMetadata struct {
	Binding      api.InstalledBinding
	Reservation  api.LaunchReservation
	Parent       api.HelperLease
	Storage      api.LaunchStorage
	Runtime      api.BlobRef
	Executable   api.Executable
	Boot         string
	Directory    string
	RuntimeBytes []byte
	Budget       api.Budget
}

type archiveNativeForward struct {
	helper *admin.Service
	checks int
}

// Hold the real worker before authentication while measuring its helper calls.
// Once released, every request uses the actual native identity service.
type archiveAuthHold struct {
	*identity.Service
	release <-chan struct{}
}

func (a archiveAuthHold) Authenticate(ctx context.Context, connection api.ConnectionContext) (api.Scope, error) {
	select {
	case <-a.release:
		return a.Service.Authenticate(ctx, connection)
	case <-ctx.Done():
		return api.Scope{}, ctx.Err()
	}
}

func (n *archiveNativeForward) FreezeArchive(ctx context.Context, intent archivejob.Intent, lane api.Lane) (archivejob.Snapshot, error) {
	if n.helper == nil {
		return archivejob.Snapshot{}, &api.Error{Code: api.CodePrerequisite, Message: "native archive helper has not been bound"}
	}
	return n.helper.FreezeArchive(ctx, intent, lane)
}
func (n *archiveNativeForward) CheckArchiveFreeze(ctx context.Context, intent archivejob.Intent, freeze archivejob.Freeze) error {
	if n.helper == nil {
		return &api.Error{Code: api.CodePrerequisite, Message: "native archive helper has not been bound"}
	}
	if err := n.helper.CheckArchiveFreeze(ctx, intent, freeze); err != nil {
		return err
	}
	n.checks++
	return nil
}

type archiveNativeRecord struct {
	Job            archivejob.Job
	Scope          api.Scope
	Request        api.Request
	Lane           api.Lane
	Input          archivejob.Input
	Grants         api.GrantSet
	Phase          string
	Parts          []api.BlobRef
	WorkerLaunchID api.ID
	WorkerActor    api.Actor
}

func archiveNativeCode(t *testing.T, err error, code api.ErrorCode) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("native archive wanted %s, got %v", code, err)
	}
}

// The ordinary entry also runs the root canary, so this process helper never
// receives a vacuous pass when selected outside its authenticated service child.
func TestArchiveNativeStoreClient(t *testing.T) {
	if os.Args[len(os.Args)-1] != "archive-store-client" {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestArchiveLaunchNative$", "-test.v")
		command.Env = []string{}
		output, err := command.CombinedOutput()
		if err != nil || !bytes.Contains(output, []byte("--- PASS: TestArchiveLaunchNative ")) {
			t.Fatalf("native archive root kit failed: %v\n%s", err, output)
		}
		return
	}
	if os.Geteuid() == 0 {
		t.Fatal("native archive store must use its actual unprivileged service UID")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	input := os.NewFile(3, "archive-native-metadata")
	defer input.Close()
	var meta archiveNativeMetadata
	if err := json.NewDecoder(input).Decode(&meta); err != nil {
		t.Fatal(err)
	}
	if uint32(os.Geteuid()) != meta.Binding.ServiceUID || fx.Digest(meta.RuntimeBytes) != meta.Runtime.SHA256 || int64(len(meta.RuntimeBytes)) != meta.Runtime.Bytes {
		t.Fatal("native store kit changed its installed identity/runtime")
	}
	directory := filepath.Join(meta.Directory, "state")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	native := &archiveNativeForward{}
	deps := store.Dependencies{Config: meta.Binding.Config, Directory: directory, Clock: fx.Clock{}, ArchiveNative: native}
	state, err := store.New(deps)
	if err != nil {
		t.Fatal(err)
	}
	f := fx.NewIn(t, state, deps)
	t.Cleanup(func() {
		if err := f.State.Close(); err != nil {
			t.Error(err)
		}
	})
	f.Start.Budget = meta.Budget
	f.Admit(t, "lane.start", f.Start)
	f.Reserve(t)
	runtimeIntent := f.Intent(t, api.InternalLaunchPlan)
	if _, err := f.State.RetainObject(ctx, f.Execution, api.RetainObjectRequest{Intent: runtimeIntent, Object: api.ObjectWrite{ObjectKey: meta.Runtime.ID, Class: meta.Runtime.Class, Bytes: meta.RuntimeBytes, SHA256: meta.Runtime.SHA256, Origin: "service", ACL: api.ObjectACL{Config: deps.Config, Owner: f.Execution.Actor, Audience: "owner", Generation: 1}}}); err != nil {
		t.Fatal(err)
	}
	sourced := f.SourceTransaction(t)
	sourced.Writes.LaunchPlans[0].Inputs.Sources.Runtime.Manifest = meta.Runtime
	sourced.Writes.LaunchPlans[0].Inputs.Sources.Runtime.Executable = meta.Executable
	if _, err := f.State.Transact(ctx, sourced); err != nil {
		t.Fatal(err)
	}
	f.Record = sourced.Writes.LaunchPlans[0]
	f.BuildPlanForIdentity(t, true, meta.Parent.UID, meta.Parent.GID)
	f.Spec(t)
	f.Bind(t)
	f.Opened(t)
	f.Ended(t)
	ready, ack := os.NewFile(4, "archive-native-ready"), os.NewFile(5, "archive-native-ack")
	defer ready.Close()
	defer ack.Close()
	if err := json.NewEncoder(ready).Encode(f.Lane); err != nil {
		t.Fatal(err)
	}
	var signal [1]byte
	if _, err := io.ReadFull(ack, signal[:]); err != nil || signal[0] != 1 {
		t.Fatal("native archive roots were not enrolled", err)
	}
	page, err := f.State.Events(ctx, f.Execution, api.EventTailRequest{LifeID: f.Lane.LifeID, Run: f.Lane.Run})
	if err != nil {
		t.Fatal(err)
	}
	var ended api.Event
	for _, event := range page.Events {
		if event.Kind == "lane.ended" {
			ended = event
		}
	}
	if ended.ID == "" {
		t.Fatal("native archive has no original committed end")
	}
	archiveStarted := time.Now()
	phase := archiveStarted
	mark := func(name string) {
		t.Logf("archive_phase: %s elapsed_ms: %.3f", name, float64(time.Since(phase).Microseconds())/1000)
		phase = time.Now()
	}
	f.Admit(t, "lane.archive", api.ArchiveRequest{Target: f.Reservation.Target, ExpectedGeneration: f.Lane.Generation})
	mark("admit")
	db, err := sql.Open("sqlite", filepath.Join(directory, "state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	var storeID api.ID
	err = db.QueryRow("SELECT value FROM meta WHERE name='store_id'").Scan(&storeID)
	if closeErr := db.Close(); err != nil || closeErr != nil {
		t.Fatal(errors.Join(err, closeErr))
	}
	expiry := f.Plan.Inputs.Grants.ExpiresAt
	r := archiveNativeRecord{Scope: f.Human, Request: f.Human.Request, Lane: f.Lane, Phase: "freezing", Parts: []api.BlobRef{}, WorkerLaunchID: fx.ID(t), WorkerActor: api.Actor{Kind: "worker", ID: fx.ID(t)}}
	r.Job = archivejob.Job{ID: fx.ID(t), Intent: archivejob.Intent{Request: api.ArchiveRequest{Target: f.Reservation.Target, ExpectedGeneration: f.Lane.Generation}, OperationID: f.Receipt.Operation.ID, CancellationEpoch: f.Lane.CancellationEpoch, EndEventID: ended.ID, EndSeq: ended.Seq}}
	r.Grants = api.GrantSet{ID: fx.ID(t), LifeID: f.Lane.LifeID, Generation: 1, PolicyGeneration: 1, ExpiresAt: expiry, Data: []api.DataGrant{}, Resources: []api.ResourceGrant{}, Secrets: []api.SecretGrant{}, Profiles: []api.ProfileGrant{}, Network: []api.NetworkGrant{}, Channels: []api.ChannelGrant{}}
	r.Grants.SHA256 = fx.Digest(fx.JSON(t, r.Grants))
	r.Job.Lease = api.WorkerLease{ID: fx.ID(t), Kind: "archive", Target: f.Reservation.Target, OperationID: r.Job.Intent.OperationID, EffectID: fx.ID(t), GrantSetID: r.Grants.ID, RuntimeManifest: meta.Runtime, Generation: 1, ExpiresAt: expiry}
	r.Job.Plan = api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: "archive", Executable: meta.Executable, GrantSetID: r.Grants.ID, Budget: f.Plan.Budget, Argv: []string{"laneboss", "internal", "worker", "--binding", "/runtime/laneboss-worker.json", "--lease", string(r.Job.Lease.ID)}}
	r.Input = archivejob.Input{Schema: "laneboss.archive-input.v2", JobID: r.Job.ID, Intent: r.Job.Intent, ReceiptID: fx.ID(t), StoreID: storeID, Budget: f.Plan.Budget}
	f.Replace(t, "archive_job", r.Job.Intent.OperationID, 1, r)
	helper, err := admin.New(admin.Dependencies{Config: deps.Config, Store: f.State, ServiceUID: meta.Binding.ServiceUID, ArtifactSHA256: meta.Binding.ArtifactSHA256, Version: meta.Binding.ServiceVersion, Protocol: api.Protocol, Schema: api.SchemaVersion, RuntimeManifest: meta.Runtime})
	if err != nil {
		t.Fatal(err)
	}
	native.helper = helper
	mark("setup")
	if err := f.State.RecoverArchives(ctx); err != nil {
		t.Fatal("real native archive freeze reconciliation failed", err)
	}
	mark("freeze")
	job, err := f.State.ArchiveJob(ctx, f.Execution, r.Job.Intent.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: job.Lease.EffectID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.State.BeginArchiveAllocation(ctx, f.Execution, claim); err != nil {
		t.Fatal(err)
	}
	allocation, err := helper.ArchiveWorkerLease(ctx, job, claim)
	if err != nil {
		t.Fatal(err)
	}
	mark("archive_lease")
	if err := f.State.RecordArchiveAllocation(ctx, f.Execution, claim, allocation); err != nil {
		t.Fatal(err)
	}
	workerID, err := f.State.ArchiveWorkerID(ctx, f.Execution, claim)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := meta.Binding
	endpoint.Class, endpoint.Socket, endpoint.LaunchID, endpoint.Target, endpoint.WorkerLeaseID = api.EndpointWorker, "/runtime/laneboss-worker.sock", workerID, &job.Lease.Target, job.Lease.ID
	endpoint.EndpointGeneration = allocation.EndpointGeneration
	handoff, err := f.State.ArchiveHandoff(ctx, f.Execution, claim, allocation, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	mark("handoff")
	peers, err := peerlinux.New(helper)
	if err != nil {
		t.Fatal(err)
	}
	defer peers.Close()
	auth, err := identity.New(identity.Dependencies{Peers: peers, Registry: helper, Store: f.State, Clock: deps.Clock, Workers: helper})
	if err != nil {
		t.Fatal(err)
	}
	authWait, releaseAuth := context.WithCancel(ctx)
	defer releaseAuth()
	endpointProbe, err := service.OpenArchiveProbe(ctx, service.Dependencies{Store: f.State, Clock: deps.Clock,
		Binding: meta.Binding, Authenticator: archiveAuthHold{auth, authWait.Done()}}, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := endpointProbe.Close(); err != nil {
			t.Error(err)
		}
	}()
	if _, err := helper.RegisterArchiveWorker(ctx, job, claim, handoff, endpoint); err != nil {
		t.Fatal(err)
	}
	mark("register")
	prepared, err := helper.PrepareArchiveWorker(ctx, job, claim)
	if err != nil {
		t.Fatal(err)
	}
	mark("prepare")
	binding, err := f.State.BindArchiveWorker(ctx, f.Execution, claim, prepared)
	if err != nil {
		t.Fatal(err)
	}
	missing, err := identity.New(identity.Dependencies{Peers: peers, Registry: helper, Store: f.State, Clock: deps.Clock})
	if err != nil {
		t.Fatal(err)
	}
	var process api.ProcessHandle
	var permit api.LaunchPermit
	if err := json.NewEncoder(ready).Encode(f.Lane); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(ack, signal[:]); err != nil || signal[0] != 1 {
		t.Fatal("native prepared-gate observation did not finish", err)
	}
	if err := ready.Close(); err != nil {
		t.Fatal(err)
	}
	mark("bind")
	// A real identity permit alone cannot release a native gate after its
	// source guard was closed. Only the enclosing transaction below can do so.
	var unguarded api.LaunchPermit
	err = helper.WithWorkerLaunch(ctx, prepared, func(held context.Context) error {
		var err error
		unguarded, err = auth.BindLaunch(held, binding)
		return err
	})
	if err != nil {
		t.Fatal("real archive permit could not be issued for the guard control", err)
	}
	openCause := *claim.Record.Effect.Context
	openCause.Kind, openCause.Actor = api.InternalHelperOpen, f.Execution.Actor
	refused, err := helper.OpenArchiveWorker(ctx, job, claim, api.HelperOpenRequest{Cause: openCause, Prepared: prepared, Permit: unguarded, OperationID: job.Lease.OperationID, EffectID: job.Lease.EffectID})
	archiveNativeCode(t, err, api.CodeContainmentUnknown)
	if !reflect.DeepEqual(refused, api.ProcessHandle{}) {
		t.Fatal("unheld archive permit released a native process")
	}
	mark("control_guard")
	workerStarted := time.Now()
	err = helper.WithWorkerLaunch(ctx, prepared, func(held context.Context) error {
		foreign := binding
		foreign.Record.RootLifeID = fx.ID(t)
		_, err := auth.BindLaunch(held, foreign)
		archiveNativeCode(t, err, api.CodeConflict)
		stale := binding
		stale.Identity.CommittedSeq++
		_, err = auth.BindLaunch(held, stale)
		archiveNativeCode(t, err, api.CodeConflict)
		_, err = missing.BindLaunch(held, binding)
		archiveNativeCode(t, err, api.CodeNotImplemented)
		permit, err = auth.BindLaunch(held, binding)
		if err != nil {
			return err
		}
		cause := *claim.Record.Effect.Context
		cause.Kind, cause.Actor = api.InternalHelperOpen, f.Execution.Actor
		process, err = helper.OpenArchiveWorker(held, job, claim, api.HelperOpenRequest{Cause: cause, Prepared: prepared, Permit: permit, OperationID: job.Lease.OperationID, EffectID: job.Lease.EffectID})
		return err
	})
	if err != nil {
		t.Fatal("real identity could not open its original native archive", err)
	}
	if err := f.State.RecordArchiveProcess(ctx, f.Execution, claim, process); err != nil {
		t.Fatal(err)
	}
	mark("worker_launch")
	// The worker cannot finish until its first real request is authenticated.
	// Repeated reads expose scan cost even on the small native canary tree.
	started := time.Now()
	for range 10 {
		callStart := time.Now()
		observed, err := helper.ObserveArchiveWorker(ctx, job, claim)
		elapsed := time.Since(callStart)
		if err != nil || observed.State != "running" || observed.Handle != process || observed.Survivors == nil || *observed.Survivors == 0 {
			t.Fatal("held archive worker lost its actual running lifetime", err)
		}
		if elapsed >= 500*time.Millisecond {
			t.Fatalf("running archive observation took %s; want under 500ms", elapsed)
		}
	}
	if elapsed := time.Since(started); elapsed >= 500*time.Millisecond {
		t.Fatalf("ten running archive observations took %s; want under 500ms", elapsed)
	}
	mark("held_observe")
	releaseAuth()
	running := 0
	observe := func(ctx context.Context) (api.ProcessObservation, error) {
		started := time.Now()
		observed, err := endpointProbe.Observe(ctx, helper, job, claim)
		elapsed := time.Since(started)
		if err == nil && observed.State == "running" {
			running++
			t.Logf("running archive observation: %s", elapsed)
			if elapsed >= 500*time.Millisecond {
				t.Fatalf("running archive observation took %s; want under 500ms", elapsed)
			}
		}
		return observed, err
	}
	if _, err := observe(ctx); err != nil {
		t.Fatal("initial archive observation failed", err)
	}
	actual, err := helper.ReconcileArchiveWorker(ctx, job, claim)
	if err != nil || actual.Process == nil || *actual.Process != process || actual.Prepared == nil || *actual.Prepared != prepared || actual.ConsumedPermit == nil || *actual.ConsumedPermit != permit || actual.GateState != "opened" {
		t.Fatal("native archive lost its real consumed permit/process", err)
	}
	replay, err := auth.BindLaunch(ctx, binding)
	if err == nil || !reflect.DeepEqual(replay, api.LaunchPermit{}) {
		t.Fatal("consumed native archive regained a permit", err)
	}
	_, err = f.State.ArchiveOutcome(ctx, f.Execution, job.Intent.OperationID)
	archiveNativeCode(t, err, api.CodeNotFound)
	waitCtx, stopWait := context.WithTimeout(ctx, 5*time.Second)
	defer stopWait()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		observed, err := observe(waitCtx)
		if err != nil {
			if stackErr := pprof.Lookup("goroutine").WriteTo(os.Stderr, 2); stackErr != nil {
				t.Error(stackErr)
			}
			t.Fatal("archive worker observation failed", err)
		}
		if observed.State == "exited" {
			if observed.ExitCode == nil || *observed.ExitCode != 0 || observed.Signal != nil || observed.Survivors == nil || *observed.Survivors != 0 {
				t.Fatal("archive worker did not exit successfully with zero survivors")
			}
			break
		}
		select {
		case <-waitCtx.Done():
			if err := pprof.Lookup("goroutine").WriteTo(os.Stderr, 2); err != nil {
				t.Error(err)
			}
			t.Fatal("archive worker did not return its result before the deadline")
		case <-ticker.C:
		}
	}
	if running == 0 {
		t.Fatal("archive canary did not observe a running worker")
	}
	mark("worker_conversation")
	db, err = sql.Open("sqlite", filepath.Join(directory, "state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	var receiptBytes []byte
	err = db.QueryRow("SELECT json_extract(data,'$.Ack.Receipt') FROM projections WHERE kind='archive_job' AND id=?", string(job.Intent.OperationID)).Scan(&receiptBytes)
	if closeErr := db.Close(); err != nil || closeErr != nil {
		t.Fatal(errors.Join(err, closeErr))
	}
	var receipt api.WorkerResultReceipt
	if err := api.DecodeObject(receiptBytes, &receipt); err != nil || receipt.LeaseID != job.Lease.ID || receipt.StageID != job.ID || receipt.CommittedSeq == 0 || receipt.Result.Bytes <= 0 {
		t.Fatal("archive worker did not retain its actual result receipt", err)
	}
	checks := native.checks
	outcome, err := endpointProbe.Complete(ctx, helper, f.Execution, claim)
	if err != nil || outcome.Status != "succeeded" || outcome.Output == nil || *outcome.Output != receipt.Result || outcome.Observation == nil || outcome.Observation.ExitCode == nil || *outcome.Observation.ExitCode != 0 || outcome.Observation.Survivors == nil || *outcome.Observation.Survivors != 0 {
		t.Fatal("archive owner did not verify and retain its native completion", err)
	}
	if native.checks <= checks {
		t.Fatal("archive completion skipped the full native storage fence check")
	}
	mark("complete")
	retained, err := f.State.ArchiveOutcome(ctx, f.Execution, job.Intent.OperationID)
	if err != nil || !reflect.DeepEqual(retained, outcome) {
		t.Fatal("archive owner returned an unretained outcome", err)
	}
	verification, err := f.State.Verify(ctx, api.VerifyRequest{Scope: "all"})
	if err != nil || !verification.OK {
		t.Fatal("real native archive state did not verify", err)
	}
	mark("state_verify")
	elapsed := time.Since(archiveStarted)
	workerElapsed := time.Since(workerStarted)
	t.Logf("archive_total: %s; worker_total: %s", elapsed, workerElapsed)
	if elapsed >= 5*time.Second {
		t.Fatalf("full native archive took %s; want under 5s", elapsed)
	}
	if workerElapsed >= 5*time.Second {
		t.Fatalf("native archive execution took %s; want under 5s", workerElapsed)
	}
}
