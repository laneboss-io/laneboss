//go:build linux

package service

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/identity"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// Only the initial public archive intent and native boundary are fixtures.
// Freeze sealing, immutable bytes, effect claims, handoff, binding, identity
// events, principal lookup and reconciler are the actual SQLite components.
// No successful process exit or archive completion is supplied by this fixture.
type archiveIdentityRecord struct {
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

type archiveIdentityNative struct {
	intent   archivejob.Intent
	snapshot archivejob.Snapshot
}

func (n *archiveIdentityNative) FreezeArchive(ctx context.Context, intent archivejob.Intent, lane api.Lane) (archivejob.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return archivejob.Snapshot{}, err
	}
	if intent != n.intent || lane.LifeID != intent.Request.Target.LifeID || lane.Run != intent.Request.Target.Run {
		return archivejob.Snapshot{}, serviceError(api.CodeIntegrity, "component freeze selected another intent")
	}
	return n.snapshot, nil
}
func (n *archiveIdentityNative) CheckArchiveFreeze(ctx context.Context, intent archivejob.Intent, freeze archivejob.Freeze) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if intent != n.intent || !reflect.DeepEqual(freeze, n.snapshot.Freeze) {
		return serviceError(api.CodeIntegrity, "component freeze read-back changed")
	}
	return nil
}

type archiveIdentityKey struct{}
type archiveIdentityHelper struct {
	api.HelperControl
	api.PeerVerifier
	f                     *fx.Fixture
	t                     *testing.T
	job                   archivejob.Job
	claim                 api.EffectLease
	allocation            api.HelperLease
	endpoint              api.InstalledBinding
	handoff               api.PreparedSpecHandoff
	prepared              api.PreparedLaunch
	process               api.ProcessHandle
	permit                *api.LaunchPermit
	directory             *os.File
	mode                  string
	opens, locks, borrows int
	reconciles            int
	lostOpen              bool
	preOpenFailed         bool
	ctx                   context.Context
}

func (*archiveIdentityHelper) RegisterContainment(context.Context, api.ContainmentBinding) error {
	return serviceError(api.CodeForbidden, "component containment is enrolled at its fixture boundary")
}

func (h *archiveIdentityHelper) check(ctx context.Context, job archivejob.Job, claim api.EffectLease) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	scope := api.Scope{Config: h.f.Deps.Config, Actor: api.Actor{Kind: "service", ID: claim.Record.ClaimantID}}
	actual, err := h.f.State.ArchiveJob(ctx, scope, job.Intent.OperationID)
	if err != nil {
		return err
	}
	current, err := h.f.State.Effect(ctx, scope, job.Lease.EffectID)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(actual, job) || !reflect.DeepEqual(current, claim.Record) || claim.ClaimID != current.ClaimID {
		return serviceError(api.CodeConflict, "component helper lost its actual original archive claim")
	}
	h.claim = claim
	return nil
}
func (h *archiveIdentityHelper) ArchiveWorkerLease(ctx context.Context, job archivejob.Job, claim api.EffectLease) (api.HelperLease, error) {
	return h.allocation, h.check(ctx, job, claim)
}
func (h *archiveIdentityHelper) RegisterArchiveWorker(ctx context.Context, job archivejob.Job, claim api.EffectLease, handoff api.PreparedSpecHandoff, endpoint api.InstalledBinding) (api.PreparedSpecReceipt, error) {
	if err := h.check(ctx, job, claim); err != nil {
		return api.PreparedSpecReceipt{}, err
	}
	if h.handoff.Spec.ID != "" && (!reflect.DeepEqual(h.handoff.Spec, handoff.Spec) || h.handoff.Original != handoff.Original || h.handoff.SpecSHA256 != handoff.SpecSHA256) {
		return api.PreparedSpecReceipt{}, serviceError(api.CodeIntegrity, "component retry replaced immutable archive spec")
	}
	h.handoff, h.endpoint = handoff, endpoint
	return api.PreparedSpecReceipt{SpecID: handoff.Spec.ID, Config: handoff.Config, Target: handoff.Spec.Target, LeaseID: h.allocation.ID, SpecSHA256: handoff.SpecSHA256, RuntimeManifest: job.Lease.RuntimeManifest, OperationID: job.Lease.OperationID}, nil
}
func (h *archiveIdentityHelper) PrepareArchiveWorker(ctx context.Context, job archivejob.Job, claim api.EffectLease) (api.PreparedLaunch, error) {
	if err := h.check(ctx, job, claim); err != nil {
		return api.PreparedLaunch{}, err
	}
	if h.prepared.ID == "" {
		h.prepared = api.PreparedLaunch{ID: fx.ID(h.t), GateID: fx.ID(h.t), Target: job.Lease.Target, ContainmentID: h.allocation.ContainmentID, ProcessGeneration: "archive-component:" + string(fx.ID(h.t)), SpecSHA256: h.handoff.SpecSHA256, EndpointGeneration: h.allocation.EndpointGeneration}
	}
	return h.prepared, nil
}
func (h *archiveIdentityHelper) WithWorkerLaunch(ctx context.Context, prepared api.PreparedLaunch, open func(context.Context) error) error {
	if prepared != h.prepared || h.permit != nil {
		return serviceError(api.CodeConflict, "component archive gate was replaced or already consumed")
	}
	h.locks++
	return open(context.WithValue(ctx, archiveIdentityKey{}, prepared.ID))
}
func (h *archiveIdentityHelper) OpenArchiveWorker(ctx context.Context, job archivejob.Job, claim api.EffectLease, request api.HelperOpenRequest) (api.ProcessHandle, error) {
	if err := h.check(ctx, job, claim); err != nil {
		return api.ProcessHandle{}, err
	}
	if ctx.Value(archiveIdentityKey{}) != h.prepared.ID || request.Prepared != h.prepared {
		return api.ProcessHandle{}, serviceError(api.CodeContainmentUnknown, "component archive open lost the enclosing guard")
	}
	binding, err := h.f.State.LaunchBinding(ctx, h.endpoint.LaunchID)
	if err != nil {
		return api.ProcessHandle{}, err
	}
	if request.Permit.LaunchID != binding.Record.ID || request.Permit.RecordSHA256 != binding.Identity.RecordSHA256 || request.Permit.CommittedSeq != binding.Identity.CommittedSeq {
		return api.ProcessHandle{}, serviceError(api.CodeIntegrity, "component archive open received an uncommitted permit")
	}
	if h.mode == "pre-open-retry" && !h.preOpenFailed {
		h.preOpenFailed = true
		return api.ProcessHandle{}, serviceError(api.CodeConflict, "component gate remains prepared before its first release")
	}
	h.opens++
	h.permit = &request.Permit
	h.process = api.ProcessHandle{ID: binding.Record.ID, Target: binding.Record.Target, ContainmentID: binding.Record.ContainmentID, Generation: binding.Record.ProcessGeneration}
	if h.lostOpen {
		h.lostOpen = false
		return api.ProcessHandle{}, serviceError(api.CodeConflict, "component lost the original archive open reply")
	}
	return h.process, nil
}
func (h *archiveIdentityHelper) ReconcileArchiveWorker(ctx context.Context, job archivejob.Job, claim api.EffectLease) (api.LaunchReconciliation, error) {
	h.reconciles++
	if err := h.check(ctx, job, claim); err != nil {
		return api.LaunchReconciliation{}, err
	}
	result := api.LaunchReconciliation{Prepared: &h.prepared, GateState: "prepared", Observation: api.ProcessObservation{State: "prepared"}}
	if h.permit != nil {
		result.GateState, result.Process, result.ConsumedPermit = "opened", &h.process, h.permit
		result.Observation = api.ProcessObservation{Handle: h.process, State: "running"}
	}
	if h.mode == "replay-permit" {
		bad := *result.ConsumedPermit
		bad.CommittedSeq++
		result.ConsumedPermit = &bad
	}
	return result, nil
}
func (h *archiveIdentityHelper) ObserveArchiveWorker(ctx context.Context, job archivejob.Job, claim api.EffectLease) (api.ProcessObservation, error) {
	if err := h.check(ctx, job, claim); err != nil {
		return api.ProcessObservation{}, err
	}
	return api.ProcessObservation{}, serviceError(api.CodeConflict, "component stops at the next native observation boundary")
}
func (*archiveIdentityHelper) RetireArchiveWorker(context.Context, archivejob.Job, api.EffectLease) (archivejob.Retirement, error) {
	return archivejob.Retirement{}, serviceError(api.CodeContainmentUnknown, "component has no native retirement evidence")
}
func (h *archiveIdentityHelper) ResolveContainment(ctx context.Context, facts api.PeerFacts, endpoint api.InstalledBinding) (api.ContainmentBinding, error) {
	if err := ctx.Err(); err != nil {
		return api.ContainmentBinding{}, err
	}
	if facts.ContainmentID != h.allocation.ContainmentID || !reflect.DeepEqual(endpoint, h.endpoint) {
		return api.ContainmentBinding{}, serviceError(api.CodeContainmentUnknown, "component selected another native allocation")
	}
	return api.ContainmentBinding{Config: endpoint.Config, Lease: h.allocation, Target: h.job.Lease.Target, Backend: endpoint.Backend, BootID: "archive-component", Generation: 1, Directory: h.directory}, nil
}

type archiveIdentityGuard struct {
	a               identity.WorkerLaunchAuthority
	input, endpoint *os.File
	peer            api.VerifiedPeer
}

func (g *archiveIdentityGuard) Authority() identity.WorkerLaunchAuthority { return g.a }
func (g *archiveIdentityGuard) Input() *os.File                           { return g.input }
func (g *archiveIdentityGuard) Endpoint() *os.File                        { return g.endpoint }
func (g *archiveIdentityGuard) Peer() api.VerifiedPeer                    { return g.peer }
func (*archiveIdentityGuard) Check(ctx context.Context) error             { return ctx.Err() }
func (g *archiveIdentityGuard) Close() error                              { return errors.Join(g.input.Close(), g.endpoint.Close()) }

func archiveIdentityMemfd(t *testing.T, raw []byte) *os.File {
	t.Helper()
	fd, err := unix.MemfdCreate("archive-identity-component", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), "archive-identity-component")
	if n, err := file.Write(raw); err != nil || n != len(raw) {
		t.Fatal("component memfd did not retain input", err)
	}
	if err := file.Chmod(0444); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL); err != nil {
		t.Fatal(err)
	}
	view, err := os.Open("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return view
}
func (h *archiveIdentityHelper) AcquireWorkerLaunch(ctx context.Context, config string, prepared api.ID) (identity.WorkerLaunchGuard, error) {
	if config != h.f.Deps.Config || prepared != h.prepared.ID || ctx.Value(archiveIdentityKey{}) != prepared {
		return nil, serviceError(api.CodeContainmentUnknown, "component identity did not borrow the enclosing archive guard")
	}
	h.borrows++
	binding, err := h.f.State.LaunchBinding(ctx, h.endpoint.LaunchID)
	if err != nil {
		return nil, err
	}
	facts := api.PeerFacts{HostUID: h.allocation.UID, HostGID: h.allocation.GID, HostPID: os.Getpid(), ProcessGeneration: h.prepared.ProcessGeneration, ContainmentID: h.allocation.ContainmentID}
	p, err := h.f.State.WorkerBinding(ctx, h.endpoint, facts)
	if err != nil {
		return nil, err
	}
	chunk, err := h.f.State.Blob(ctx, h.f.Execution, api.BlobReadRequest{ObjectID: h.job.Lease.Input.ID, Limit: api.MaxChunkBytes})
	if err != nil {
		return nil, err
	}
	if h.mode == "foreign" {
		p.StageID = fx.ID(h.t)
	}
	if h.mode == "stale" {
		p.Claim.Record.Generation++
	}
	if h.mode == "input" {
		chunk.Data = append(chunk.Data, '\n')
	}
	return &archiveIdentityGuard{a: identity.WorkerLaunchAuthority{Binding: binding, Handoff: h.handoff, Principal: p}, input: archiveIdentityMemfd(h.t, chunk.Data), endpoint: archiveIdentityMemfd(h.t, fx.JSON(h.t, h.endpoint)), peer: &fx.Peer{FactsValue: facts}}, nil
}

func newArchiveIdentity(t *testing.T) (*Server, *archiveIdentityHelper, api.EffectLease, api.Scope, *planReconcileClock) {
	t.Helper()
	f := fx.Ready(t, true)
	f.Opened(t)
	f.Ended(t)
	ctx := context.Background()
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
		t.Fatal("component has no committed end")
	}
	f.Admit(t, "lane.archive", api.ArchiveRequest{Target: f.Reservation.Target, ExpectedGeneration: f.Lane.Generation})
	db, err := sql.Open("sqlite", filepath.Join(f.Deps.Directory, "state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	var storeID api.ID
	err = db.QueryRow("SELECT value FROM meta WHERE name='store_id'").Scan(&storeID)
	if closeErr := db.Close(); err != nil || closeErr != nil {
		t.Fatal(errors.Join(err, closeErr))
	}
	budget := f.Plan.Budget
	expiry := fx.Expiry()
	r := archiveIdentityRecord{Scope: f.Human, Request: f.Human.Request, Lane: f.Lane, Phase: "freezing", Parts: []api.BlobRef{}, WorkerLaunchID: fx.ID(t), WorkerActor: api.Actor{Kind: "worker", ID: fx.ID(t)}}
	r.Job = archivejob.Job{ID: fx.ID(t), Intent: archivejob.Intent{Request: api.ArchiveRequest{Target: f.Reservation.Target, ExpectedGeneration: f.Lane.Generation}, OperationID: f.Receipt.Operation.ID, CancellationEpoch: f.Lane.CancellationEpoch, EndEventID: ended.ID, EndSeq: ended.Seq}}
	r.Grants = api.GrantSet{ID: fx.ID(t), LifeID: f.Lane.LifeID, Generation: 1, PolicyGeneration: 1, ExpiresAt: expiry, Data: []api.DataGrant{}, Resources: []api.ResourceGrant{}, Secrets: []api.SecretGrant{}, Profiles: []api.ProfileGrant{}, Network: []api.NetworkGrant{}, Channels: []api.ChannelGrant{}}
	r.Grants.SHA256 = fx.Digest(fx.JSON(t, r.Grants))
	r.Job.Lease = api.WorkerLease{ID: fx.ID(t), Kind: "archive", Target: f.Reservation.Target, OperationID: r.Job.Intent.OperationID, EffectID: fx.ID(t), GrantSetID: r.Grants.ID, RuntimeManifest: f.Plan.Inputs.Sources.Runtime.Manifest, Generation: 1, ExpiresAt: expiry}
	runtimeChunk, err := f.State.Blob(ctx, f.Execution, api.BlobReadRequest{ObjectID: r.Job.Lease.RuntimeManifest.ID, Limit: api.MaxChunkBytes})
	if err != nil {
		t.Fatal(err)
	}
	var runtime api.RuntimeManifest
	if err := api.DecodeObject(runtimeChunk.Data, &runtime); err != nil {
		t.Fatal(err)
	}
	r.Job.Plan = api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: "archive", Executable: runtime.Bootstrap, GrantSetID: r.Grants.ID, Budget: budget, Argv: []string{"laneboss", "internal", "worker", "--binding", "/runtime/laneboss-worker.json", "--lease", string(r.Job.Lease.ID)}}
	r.Input = archivejob.Input{Schema: "laneboss.archive-input.v2", JobID: r.Job.ID, Intent: r.Job.Intent, ReceiptID: fx.ID(t), StoreID: storeID, Budget: budget}
	content := []byte("archive current bytes " + string(fx.ID(t)))
	ref := api.BlobRef{ID: fx.ID(t), Class: "artifact", Bytes: int64(len(content)), SHA256: fx.Digest(content)}
	tree := fx.JSON(t, api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{{Path: "current.txt", Kind: "file", Mode: 0600, Content: &ref}}})
	treeRef := api.BlobRef{ID: fx.ID(t), Class: "manifest", Bytes: int64(len(tree)), SHA256: fx.Digest(tree)}
	zero := uint64(0)
	native := &archiveIdentityNative{intent: r.Job.Intent, snapshot: archivejob.Snapshot{Freeze: archivejob.Freeze{Target: f.Reservation.Target, LaunchID: f.Lane.LaunchID, CancellationEpoch: f.Lane.CancellationEpoch, Snapshot: treeRef, Writers: &zero, WritableExports: &zero, ObservedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}, Objects: []api.ObjectWrite{
		{ObjectKey: ref.ID, Class: ref.Class, Bytes: content, SHA256: ref.SHA256, Origin: "service", ACL: api.ObjectACL{Config: f.Deps.Config, LifeID: f.Lane.LifeID}},
		{ObjectKey: treeRef.ID, Class: treeRef.Class, Bytes: tree, SHA256: treeRef.SHA256, Origin: "service", ACL: api.ObjectACL{Config: f.Deps.Config, LifeID: f.Lane.LifeID}},
	}}}
	clock := &planReconcileClock{}
	f.Deps.Clock, f.Deps.ArchiveNative = clock, native
	f.Replace(t, "archive_job", r.Job.Intent.OperationID, 1, r)
	if err := f.State.RecoverArchives(ctx); err != nil {
		t.Fatal("real archive freeze reconciliation failed", err)
	}
	job, err := f.State.ArchiveJob(ctx, f.Execution, r.Job.Intent.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := directory.Close(); err != nil {
			t.Error(err)
		}
	})
	h := &archiveIdentityHelper{f: f, t: t, job: job, directory: directory, allocation: api.HelperLease{ID: fx.ID(t), UID: f.Plan.Lease.UID + 1, GID: f.Plan.Lease.GID + 1, ContainmentID: fx.ID(t), EndpointGeneration: 1}}
	auth, err := identity.New(identity.Dependencies{Peers: h, Registry: h, Store: f.State, Clock: clock, Workers: h})
	if err != nil {
		t.Fatal(err)
	}
	host := fixtureServer(t)
	host.options.Config, host.deps.Store, host.deps.Authenticator, host.deps.Clock, host.runtime.Helper = f.Deps.Config, f.State, auth, clock, h
	host.runtime.Store = f.State
	host.deps.Binding = api.InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision, Protocol: api.Protocol, APISchema: api.SchemaVersion, Config: f.Deps.Config, Class: api.EndpointHuman, InstallationGeneration: 1, EndpointGeneration: 1, ServiceUID: uint32(os.Geteuid()), ServiceGID: uint32(os.Getegid()), Socket: filepath.Join(privateHostDirectory(t), "service.sock"), ArtifactSHA256: job.Plan.Executable.SHA256, ServiceVersion: job.Plan.Executable.Version, Backend: "linux-bwrap-landlock"}
	ctx, cancel := context.WithCancel(ctx)
	h.ctx = ctx
	t.Cleanup(func() { cancel(); host.workers.Wait() })
	scope := f.Execution
	claim, err := f.State.ClaimEffect(ctx, scope, api.EffectClaimRequest{EffectID: job.Lease.EffectID, ExpectedGeneration: 1, ClaimantID: scope.Actor.ID, Deadline: api.Timestamp(clock.Now().Add(time.Second).UTC().Format(time.RFC3339Nano))})
	if err != nil {
		t.Fatal(err)
	}
	return host, h, claim, scope, clock
}

func TestArchiveIdentityReconcile(t *testing.T) {
	for _, mode := range []string{"current", "foreign", "stale", "input", "missing", "pre-open-retry", "lost-open", "replay-permit"} {
		t.Run(mode, func(t *testing.T) {
			host, h, claim, scope, clock := newArchiveIdentity(t)
			h.mode, h.lostOpen = mode, mode == "lost-open" || mode == "replay-permit"
			if mode == "missing" {
				auth, err := identity.New(identity.Dependencies{Peers: h, Registry: h, Store: h.f.State, Clock: clock})
				if err != nil {
					t.Fatal(err)
				}
				host.deps.Authenticator = auth
			}
			_, err := host.runArchive(h.ctx, scope, claim)
			if mode == "foreign" || mode == "stale" || mode == "input" || mode == "missing" {
				if err == nil || h.opens != 0 {
					t.Fatal("foreign, stale or unheld archive handoff opened a gate", err)
				}
				if mode == "missing" {
					codeIs(t, err, api.CodeNotImplemented)
				}
				return
			}
			codeIs(t, err, api.CodeConflict)
			firstOpens, finalBinds := 1, 1
			if mode == "pre-open-retry" {
				firstOpens, finalBinds = 0, 2
			}
			if h.opens != firstOpens || h.locks != 1 || h.borrows != 1 {
				t.Fatal("real identity handoff did not reach the original gate", err, h.opens, h.locks, h.borrows)
			}
			firstSpec, firstInput := h.handoff.Spec, h.job.Lease.Input
			if mode == "replay-permit" {
				_, err := host.runArchive(h.ctx, scope, claim)
				codeIs(t, err, api.CodeIntegrity)
				if h.opens != 1 || h.borrows != 1 {
					t.Fatal("replayed permit opened the archive again")
				}
				return
			}
			clock.advance(2 * time.Second)
			if result := host.reconcileEffect(h.ctx, claim.Record.Effect, make(effectRetries)); result != attemptNext {
				t.Fatal("archive retry stopped the reconciler", host.fault)
			}
			if host.fault != nil || h.opens != 1 || h.locks != finalBinds || h.borrows != finalBinds || h.reconciles != 1 || !reflect.DeepEqual(firstSpec, h.handoff.Spec) || firstInput != h.job.Lease.Input || h.claim.ClaimID == claim.ClaimID {
				t.Fatal("fresh archive attempt replaced immutable pins or opened twice", host.fault)
			}
			scope.Actor.ID = h.claim.Record.ClaimantID
			recovery, err := h.f.State.ArchiveRecovery(context.Background(), scope, h.claim)
			if err != nil || recovery.Process != h.process || recovery.Retirement != nil {
				t.Fatal("retry did not retain the original process under its live claim", err)
			}
			current, err := h.f.State.Effect(context.Background(), scope, h.job.Lease.EffectID)
			if err != nil || current.Outcome != nil || current.State != api.EffectClaimed {
				t.Fatal("opening was falsely reported as archive success", err)
			}
		})
	}
}
