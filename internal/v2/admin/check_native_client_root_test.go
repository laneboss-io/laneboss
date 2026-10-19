//go:build linux && laneboss_root_canary

package admin_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/identity"
	peerlinux "laneboss.io/laneboss/internal/v2/peer/linux"
	"laneboss.io/laneboss/internal/v2/reviewjob"
	"laneboss.io/laneboss/internal/v2/service"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// Parent/child and the requesting frame are component inputs. Both the test
// worker and following verifier use real separate UIDs, kernel authentication,
// sealed files, identity permits, native wait/retirement and SQLite records.
func TestCheckNativeStoreClient(t *testing.T) {
	if os.Args[len(os.Args)-1] != "check-store-client" {
		ctx, cancel := context.WithTimeout(context.Background(), 110*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestCheckLaunchNative$", "-test.v")
		command.Env = []string{}
		output, err := command.CombinedOutput()
		if err != nil || !bytes.Contains(output, []byte("--- PASS: TestCheckLaunchNative ")) {
			t.Fatalf("native checker root kit failed: %v\n%s", err, output)
		}
		return
	}
	if os.Geteuid() == 0 {
		t.Fatal("native checker writer must use its actual unprivileged service UID")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()
	input := os.NewFile(3, "native-check-metadata")
	defer input.Close()
	var meta archiveNativeMetadata
	if err := json.NewDecoder(input).Decode(&meta); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(meta.Directory, "state")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	deps := store.Dependencies{Config: meta.Binding.Config, Directory: directory, Clock: fx.Clock{}}
	state, err := store.New(deps)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	f := fx.NewIn(t, state, deps)
	state = f.State
	defer func() {
		if err := f.State.Close(); err != nil {
			t.Error(err)
		}
	}()
	// Component upstream input has a real provider init but no terminal result,
	// as can happen when the enclosing run is interrupted. The native test and
	// export must retain partial coverage without inventing provider completion.
	f.Start.Driver, f.Ceiling.Profiles[0].Driver = api.DriverClaudock, api.DriverClaudock
	f.Ceiling.SHA256 = ""
	ceilingBytes, err := api.CanonicalJSON(fx.JSON(t, f.Ceiling))
	if err != nil {
		t.Fatal(err)
	}
	f.Ceiling.SHA256 = fx.Digest(ceilingBytes)
	f.Replace(t, "grants", f.Ceiling.ID, f.Ceiling.Generation, f.Ceiling)
	state = f.State
	f.Start.Budget = meta.Budget
	f.Admit(t, "lane.start", f.Start)
	f.Reserve(t)
	cause := f.Intent(t, api.InternalLaunchPlan)
	if _, err := state.RetainObject(ctx, f.Execution, api.RetainObjectRequest{Intent: cause, Object: api.ObjectWrite{ObjectKey: meta.Runtime.ID, Class: meta.Runtime.Class, Bytes: meta.RuntimeBytes, SHA256: meta.Runtime.SHA256, Origin: "service", ACL: api.ObjectACL{Config: deps.Config, Owner: f.Execution.Actor, Audience: "owner", Generation: 1}}}); err != nil {
		t.Fatal(err)
	}
	source := f.SourceTransaction(t)
	source.Writes.LaunchPlans[0].Inputs.Sources.Runtime.Manifest = meta.Runtime
	source.Writes.LaunchPlans[0].Inputs.Sources.Runtime.Executable = meta.Executable
	if _, err := state.Transact(ctx, source); err != nil {
		t.Fatal(err)
	}
	f.Record = source.Writes.LaunchPlans[0]
	f.BuildPlanForIdentity(t, true, meta.Parent.UID, meta.Parent.GID)
	f.Spec(t)
	f.Bind(t)
	f.Opened(t)
	parent := f.LaneScope(t)
	f.Start.Task = nativeReviewRetainOwned(t, f, "task", []byte("# Native checker child\n"+string(fx.ID(t))), parent.Actor)
	f.Ceiling = f.Plan.Inputs.Grants
	f.Start.Lane = string(fx.ID(t))
	f.Start.Level, f.Start.Role, f.Start.RootTicketID = 3, "executor", ""
	f.Start.Grants.Data[0].ParentGrantID = f.Ceiling.Data[0].ID
	f.Start.Grants.Profiles[0].ParentGrantID = f.Ceiling.Profiles[0].ID
	expiry := api.Timestamp(time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339Nano))
	f.Start.Grants.Data[0].ExpiresAt, f.Start.Grants.Profiles[0].ExpiresAt = expiry, expiry
	f.Start.ProfileGrantID = f.Ceiling.Profiles[0].ID
	f.Human = parent
	f.Admit(t, "lane.start", f.Start)
	f.Reserve(t)
	source = f.SourceTransaction(t)
	source.Writes.LaunchPlans[0].Inputs.Sources.Runtime.Manifest = meta.Runtime
	source.Writes.LaunchPlans[0].Inputs.Sources.Runtime.Executable = meta.Executable
	if _, err := state.Transact(ctx, source); err != nil {
		t.Fatal(err)
	}
	f.Record = source.Writes.LaunchPlans[0]
	f.BuildPlanForIdentity(t, true, meta.Parent.UID, meta.Parent.GID)
	f.Spec(t)
	f.PreparedClaim = api.EffectLease{}
	f.Bind(t)
	f.Opened(t)
	f.Ended(t)
	providerRaw := append(fx.JSON(t, map[string]any{"type": "system", "subtype": "init", "session_id": f.Lane.Session.VendorID, "cwd": f.Lane.Session.LogicalCWD}), '\n')
	provider := f.CaptureData(t, providerRaw)
	appendInput := f.AppendRequest(t, &provider, false)
	appendInput.StreamID = f.Plan.Capture.Streams[0].ID
	if _, err := state.AppendCapture(ctx, f.Worker, appendInput); err != nil {
		t.Fatal("component provider capture input failed", err)
	}
	for i, stream := range f.Plan.Capture.Streams {
		q := f.AppendRequest(t, nil, true)
		q.StreamID = stream.ID
		q.ExpectedGeneration = api.Generation(i + 2)
		if i == 0 {
			q.Offset = int64(len(providerRaw))
		}
		if _, err := state.AppendCapture(ctx, f.Worker, q); err != nil {
			t.Fatal(err)
		}
	}
	// Retain the exact child-owned candidate and bounded declaration as inert
	// input. The test worker will read, hash and measure them independently.
	child := f.Binding.Record.Actor
	candidateRaw := fx.JSON(t, api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{}})
	candidate := nativeReviewRetainOwned(t, f, "manifest", candidateRaw, child)
	budget := api.Budget{WallMS: 30000, CPUSeconds: 10, MemoryBytes: 256 << 20, Processes: 16, DiskBytes: 4 << 20, Currency: "USD"}
	declared := api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: "test", Executable: meta.Executable, Argv: []string{"laneboss", "check", reviewjob.SnapshotIntegrity}, Input: candidate, GrantSetID: f.Lane.GrantSetID, Budget: budget}
	testPlan := nativeReviewRetainOwned(t, f, "manifest", fx.JSON(t, declared), parent.Actor)
	request := api.TestChildRequest{Child: f.Reservation.Target, Candidate: candidate, TestPlan: testPlan, Budget: budget}
	ready, ack := os.NewFile(4, "native-check-ready"), os.NewFile(5, "native-check-ack")
	defer ready.Close()
	defer ack.Close()
	if err := json.NewEncoder(ready).Encode(f.Lane); err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(ready).Encode(struct {
		Reservation api.LaunchReservation
		Inputs      api.LaunchInputs
		Request     api.HelperLeaseRequest
	}{f.Reservation, *f.Record.Inputs, f.Allocation}); err != nil {
		t.Fatal(err)
	}
	var signal [1]byte
	if _, err := io.ReadFull(ack, signal[:]); err != nil || signal[0] != 1 {
		t.Fatal("native check roots were not enrolled", err)
	}
	helper, err := admin.New(admin.Dependencies{Config: deps.Config, Store: state, ServiceUID: meta.Binding.ServiceUID, ArtifactSHA256: meta.Binding.ArtifactSHA256, Version: meta.Binding.ServiceVersion, Protocol: api.Protocol, Schema: api.SchemaVersion, RuntimeManifest: meta.Runtime})
	if err != nil {
		t.Fatal(err)
	}
	sourcePort := any(state).(nativeReviewPort)
	noReplacement := &reviewNativeNoReplacement{}
	if err := sourcePort.BindReviewRuntime(helper, noReplacement); err != nil {
		t.Fatal(err)
	}
	caller := parent
	caller.Request = api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: deps.Config, Method: "grants.test-child", RequestID: fx.ID(t), IdempotencyKey: fx.ID(t), Params: fx.JSON(t, request)}
	caller.Request.RequestSHA256, err = api.RequestDigest(caller.Request)
	if err != nil {
		t.Fatal(err)
	}
	caller.Frame = &fx.Frame{Raw: fx.JSON(t, caller.Request)}
	owner, finish := state.TrackMutation(ctx)
	defer finish()
	_, won, err := state.ReserveMutation(owner, api.RequestReservation{Scope: caller, RawRequest: caller.Frame.Bytes(), Deadline: fx.Expiry()})
	if err != nil || !won {
		t.Fatal("native check request reservation failed", err)
	}
	job, err := state.PrepareCheckWorker(owner, caller, f.Execution, request, f.Plan.Inputs.Grants)
	if err != nil {
		t.Fatal("native test preparation failed", err)
	}
	if err := json.NewEncoder(ready).Encode(f.Lane); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(ack, signal[:]); err != nil || signal[0] != 1 {
		t.Fatal("native check witness failed", err)
	}
	if err := ready.Close(); err != nil {
		t.Fatal(err)
	}
	runNativeCheckJob(t, ctx, f, helper, meta.Binding, job)
	operation, err := state.PublishCheckInputs(owner, caller, job)
	if err != nil || operation.Result == nil {
		t.Fatal("native check inputs publication failed", err)
	}
	if operation.LifeID != request.Child.LifeID || operation.Run != request.Child.Run {
		t.Fatal("native checker public operation lost its actual child and run")
	}
	retainedReply, err := state.LookupReceipt(ctx, caller, api.RequestKey{Method: caller.Request.Method, IdempotencyKey: caller.Request.IdempotencyKey, RequestSHA256: caller.Request.RequestSHA256})
	if err != nil || retainedReply.Reply == nil {
		t.Fatal("native checker did not commit its original public dispatcher reply", err)
	}
	var returned api.Operation
	if api.DecodeObject(retainedReply.Reply.Result, &returned) != nil || returned.Result == nil || *returned.Result != *operation.Result || returned.ID != operation.ID || returned.LifeID != operation.LifeID || returned.Run != operation.Run {
		t.Fatal("native checker public reply differs from its real completed inputs")
	}
	recipe, err := state.Blob(ctx, f.Execution, api.BlobReadRequest{ObjectID: operation.Result.ID, Limit: api.MaxChunkBytes})
	if err != nil {
		t.Fatal(err)
	}
	var review api.ReviewRequest
	if api.DecodeObject(recipe.Data, &review) != nil || review.Target != request.Child || len(review.Checks) != 1 {
		t.Fatal("native check result is not an exact review input recipe")
	}
	check, err := state.Blob(ctx, f.Execution, api.BlobReadRequest{ObjectID: review.Checks[0].ID, Limit: api.MaxChunkBytes})
	if err != nil {
		t.Fatal(err)
	}
	var receipt reviewjob.CheckRecord
	if api.DecodeObject(check.Data, &receipt) != nil || receipt.WorkerLeaseID != job.Lease.ID || receipt.OperationID != operation.ID || receipt.Name != reviewjob.SnapshotIntegrity {
		t.Fatal("review inputs did not cite the real completed test worker")
	}
	caller.Request.Method, caller.Request.Params, caller.Request.RequestID, caller.Request.IdempotencyKey = "lane.review", fx.JSON(t, review), fx.ID(t), fx.ID(t)
	caller.Request.RequestSHA256, err = api.RequestDigest(caller.Request)
	if err != nil {
		t.Fatal(err)
	}
	caller.Frame = &fx.Frame{Raw: fx.JSON(t, caller.Request)}
	reviewOwner, finishReview := state.TrackMutation(ctx)
	defer finishReview()
	_, won, err = state.ReserveMutation(reviewOwner, api.RequestReservation{Scope: caller, RawRequest: caller.Frame.Bytes(), Deadline: fx.Expiry()})
	if err != nil || !won {
		t.Fatal(err)
	}
	subject, err := sourcePort.ReviewSnapshot(ctx, f.Execution, request.Child)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := sourcePort.ReserveReviewWorker(reviewOwner, caller, review, subject, []string{reviewjob.SnapshotIntegrity})
	if err != nil {
		t.Fatal("native test receipt rejected by verifier reservation", err)
	}
	verifier, err := sourcePort.ReviewJob(ctx, f.Execution, lease.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	runNativeCheckJob(t, ctx, f, helper, meta.Binding, verifier)
	output, err := sourcePort.AwaitReviewResult(reviewOwner, caller, lease)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := state.Blob(ctx, f.Execution, api.BlobReadRequest{ObjectID: output.ID, Limit: api.MaxChunkBytes})
	if err != nil {
		t.Fatal(err)
	}
	var evidence api.ReviewEvidence
	if api.DecodeObject(raw.Data, &evidence) != nil || len(evidence.Checks) != 1 || evidence.Checks[0].WorkerLeaseID != job.Lease.ID {
		t.Fatal("native export did not consume the actual native test receipt")
	}
	if evidence.Coverage != api.CoveragePartial || evidence.Inventory.ToolCoverage != api.CoveragePartial {
		t.Fatal("incomplete provider capture became complete native review coverage")
	}
	verified, err := state.Verify(ctx, api.VerifyRequest{Scope: "all"})
	if err != nil || !verified.OK {
		t.Fatal("native test and export state did not verify", err)
	}
	t.Logf("native test and export measured: check_sha256=%s result_sha256=%s coverage=%s", review.Checks[0].SHA256, output.SHA256, evidence.Coverage)
}

func nativeReviewRetainOwned(t *testing.T, f *fx.Fixture, class string, raw []byte, owner api.Actor) api.BlobRef {
	t.Helper()
	cause := f.Intent(t, api.InternalObjectRetain)
	ref, err := f.State.RetainObject(context.Background(), f.Execution, api.RetainObjectRequest{Intent: cause, Object: api.ObjectWrite{ObjectKey: fx.ID(t), Class: class, Bytes: raw, SHA256: fx.Digest(raw), Origin: "service", ACL: api.ObjectACL{Config: f.Deps.Config, Owner: owner, LifeID: f.Lane.LifeID, Audience: "owner", Generation: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

func runNativeCheckJob(t *testing.T, ctx context.Context, f *fx.Fixture, helper *admin.Service, base api.InstalledBinding, job archivejob.Job) {
	t.Helper()
	source := any(f.State).(nativeReviewPort)
	native := any(helper).(nativeReviewHelper)
	claim, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: job.Lease.EffectID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: job.Lease.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	if err := source.BeginReviewAllocation(ctx, f.Execution, claim); err != nil {
		t.Fatal(err)
	}
	allocation, err := native.ReviewWorkerLease(ctx, job, claim)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.RecordReviewAllocation(ctx, f.Execution, claim, allocation); err != nil {
		t.Fatal(err)
	}
	workerID, err := source.ReviewWorkerID(ctx, f.Execution, claim)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := base
	endpoint.Class, endpoint.Socket, endpoint.LaunchID, endpoint.Target, endpoint.WorkerLeaseID = api.EndpointWorker, "/runtime/laneboss-worker.sock", workerID, &job.Lease.Target, job.Lease.ID
	endpoint.EndpointGeneration = allocation.EndpointGeneration
	handoff, err := source.ReviewHandoff(ctx, f.Execution, claim, allocation, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	peers, err := peerlinux.New(helper)
	if err != nil {
		t.Fatal(err)
	}
	defer peers.Close()
	auth, err := identity.New(identity.Dependencies{Peers: peers, Registry: helper, Store: f.State, Clock: f.Deps.Clock, Workers: helper})
	if err != nil {
		t.Fatal(err)
	}
	authWait, release := context.WithCancel(ctx)
	defer release()
	probe, err := service.OpenArchiveProbe(ctx, service.Dependencies{Store: f.State, Clock: f.Deps.Clock, Binding: base, Authenticator: archiveAuthHold{auth, authWait.Done()}}, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	if _, err := native.RegisterReviewWorker(ctx, job, claim, handoff, endpoint); err != nil {
		t.Fatal(err)
	}
	prepared, err := native.PrepareReviewWorker(ctx, job, claim)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := source.BindReviewWorker(ctx, f.Execution, claim, prepared)
	if err != nil {
		t.Fatal(err)
	}
	var process api.ProcessHandle
	err = helper.WithWorkerLaunch(ctx, prepared, func(held context.Context) error {
		permit, err := auth.BindLaunch(held, binding)
		if err != nil {
			return err
		}
		cause := *claim.Record.Effect.Context
		cause.Kind, cause.Actor = api.InternalHelperOpen, f.Execution.Actor
		process, err = native.OpenReviewWorker(held, job, claim, api.HelperOpenRequest{Cause: cause, Prepared: prepared, Permit: permit, OperationID: job.Intent.OperationID, EffectID: job.Lease.EffectID})
		return err
	})
	if err != nil {
		t.Fatal("actual native checker/verifier could not open", err)
	}
	if err := source.RecordReviewProcess(ctx, f.Execution, claim, process); err != nil {
		t.Fatal(err)
	}
	observed, err := native.ObserveReviewWorker(ctx, job, claim)
	if err != nil || observed.State != "running" || observed.Handle != process {
		t.Fatal("native check was not observed running", err)
	}
	release()
	deadline, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		observed, err = native.ObserveReviewWorker(deadline, job, claim)
		if err != nil {
			t.Fatal(err)
		}
		if observed.State == "exited" {
			break
		}
		select {
		case <-deadline.Done():
			t.Fatal("native check did not exit")
		case <-ticker.C:
		}
	}
	if observed.ExitCode == nil || *observed.ExitCode != 0 || observed.Survivors == nil || *observed.Survivors != 0 || observed.Signal != nil {
		t.Fatal("native check has no actual successful zero-survivor wait")
	}
	ack, err := source.ReviewAcknowledgement(ctx, f.Execution, claim)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.State.CompleteEffect(ctx, f.Execution, api.EffectOutcome{EffectID: job.Lease.EffectID, ClaimID: claim.ClaimID, ExpectedGeneration: claim.Record.Generation, Status: "succeeded", Output: &ack.Result, Observation: &observed}); err == nil {
		t.Fatal("native checker completed without its real retirement measurement")
	}
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
	proof, err := native.RetireReviewWorker(ctx, job, claim)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.RecordReviewRetirement(ctx, f.Execution, claim, proof); err != nil {
		t.Fatal(err)
	}
	if proof.Release == nil {
		t.Fatal("native check has no actual retirement")
	}
	observed = proof.Release.Quiescence
	if _, err := f.State.CompleteEffect(ctx, f.Execution, api.EffectOutcome{EffectID: job.Lease.EffectID, ClaimID: claim.ClaimID, ExpectedGeneration: claim.Record.Generation, Status: "succeeded", Output: &ack.Result, Observation: &observed}); err != nil {
		t.Fatal(err)
	}
}
