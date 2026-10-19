//go:build linux

// Package testfx supplies explicit component identities and helper receipt
// fixtures. It is imported only by tests. No fixture is installed acceptance,
// a source resolver, a helper executor, or an authenticated AI-service test.
package testfx

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	release "laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/store"
)

type Clock struct{}

func (Clock) Now() time.Time { return time.Now() }

func ID(t testing.TB) api.ID {
	t.Helper()
	id, err := wire.NewID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func Digest(data []byte) api.Digest {
	sum := sha256.Sum256(data)
	return api.Digest(hex.EncodeToString(sum[:]))
}
func JSON(t testing.TB, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func Expiry() api.Timestamp {
	return api.Timestamp(time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano))
}

type Peer struct {
	FactsValue api.PeerFacts
	Err        error
}

func (p *Peer) Facts(ctx context.Context) (api.PeerFacts, error) {
	if err := ctx.Err(); err != nil {
		return api.PeerFacts{}, err
	}
	return p.FactsValue, p.Err
}
func (p *Peer) Alive(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return p.Err
}
func (p *Peer) Close() error { return nil }

type Connection struct {
	Identity api.ID
	Endpoint api.InstalledBinding
	Verified api.VerifiedPeer
	Socket   net.Conn
}

func (c *Connection) ID() api.ID                    { return c.Identity }
func (c *Connection) Binding() api.InstalledBinding { return c.Endpoint }
func (c *Connection) Peer() api.VerifiedPeer        { return c.Verified }
func (c *Connection) Conn() net.Conn                { return c.Socket }
func (c *Connection) BindPeer(peer api.VerifiedPeer) error {
	if c.Verified != nil {
		return &api.Error{Code: api.CodeConflict, Message: "fixture peer already bound"}
	}
	c.Verified = peer
	return nil
}
func (c *Connection) BindReadAuthority(api.ReadAuthority) error {
	return &api.Error{Code: api.CodeForbidden, Message: "fixture has no human read session"}
}
func (c *Connection) ReadAuthority(context.Context) (api.ReadAuthority, error) {
	return api.ReadAuthority{}, &api.Error{Code: api.CodeForbidden, Message: "fixture has no human read session"}
}
func (c *Connection) Close() error {
	if c.Socket == nil {
		return nil
	}
	return c.Socket.Close()
}

type Frame struct {
	Raw []byte
	Err error
}

func (f *Frame) Bytes() []byte { return append([]byte(nil), f.Raw...) }
func (f *Frame) Verify(ctx context.Context, connection api.ConnectionContext) error {
	if f.Err != nil {
		return f.Err
	}
	if connection == nil || connection.Peer() == nil {
		return &api.Error{Code: api.CodeUnauthenticated, Message: "fixture frame has no peer"}
	}
	return connection.Peer().Alive(ctx)
}

type Fixture struct {
	// Native canaries supply kernel facts before capture and prepare are
	// committed; ordinary component fixtures retain their explicit inputs.
	CaptureSetup  func(api.CaptureBinding) api.CaptureBinding
	PlanSetup     func(*api.LaunchPlan)
	Allocation    api.HelperLeaseRequest
	State         *store.Service
	Deps          store.Dependencies
	Human         api.Scope
	Execution     api.Scope
	Start         api.StartRequest
	Raw           []byte
	Receipt       api.MutationReceipt
	Reservation   api.LaunchReservation
	Record        api.LaunchPlanRecord
	Claim         api.EffectLease
	Ceiling       api.GrantSet
	Plan          api.LaunchPlan
	Prepared      api.PreparedLaunch
	PreparedClaim api.EffectLease
	Binding       api.LaunchBindingRequest
	Lane          api.Lane
	Worker        api.Scope
	WorkerLease   api.WorkerLease
	Process       api.ProcessHandle
}

func New(t testing.TB, configs ...string) *Fixture {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Fatal("launch fixtures require an unprivileged Linux test UID")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp(home, ".lb-v2-service-launch-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	f := &Fixture{Deps: store.Dependencies{Config: "launch-fixture", Directory: directory, Clock: Clock{}}}
	if len(configs) == 1 {
		f.Deps.Config = configs[0]
	}
	f.State, err = store.New(f.Deps)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.State.Close(); err != nil {
			t.Error(err)
		}
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	return populate(t, f)
}

// NewIn prepares a second authentic launch in an existing component store.
// The caller retains the returned State after the primitive ticket install.
func NewIn(t testing.TB, state *store.Service, deps store.Dependencies) *Fixture {
	t.Helper()
	return populate(t, &Fixture{State: state, Deps: deps})
}

func populate(t testing.TB, f *Fixture) *Fixture {
	t.Helper()
	f.Execution = api.Scope{Config: f.Deps.Config, Actor: api.Actor{Kind: "service", ID: ID(t)}, Source: "worker", PolicyGeneration: 1}
	principal := api.Actor{Kind: "human", ID: ID(t)}
	connection := &Connection{Identity: ID(t), Endpoint: api.InstalledBinding{Config: f.Deps.Config, Class: api.EndpointHuman, EndpointGeneration: 1},
		Verified: &Peer{FactsValue: api.PeerFacts{HostUID: uint32(os.Geteuid()), HostGID: uint32(os.Getegid()), HostPID: os.Getpid(), ProcessGeneration: "component-human"}}}
	f.Human = api.Scope{Config: f.Deps.Config, Actor: principal, EndpointGeneration: 1, PolicyGeneration: 1, Source: "cli", Connection: connection}
	source := JSON(t, api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{{Path: ".", Kind: "directory", Mode: 0700}}})
	task := []byte("# Component launch\n" + string(ID(t)))
	sourceRef := api.BlobRef{ID: ID(t), Class: "manifest", Bytes: int64(len(source)), SHA256: Digest(source)}
	taskRef := api.BlobRef{ID: ID(t), Class: "task", Bytes: int64(len(task)), SHA256: Digest(task)}
	f.Ceiling = api.GrantSet{ID: ID(t), LifeID: ID(t), SHA256: Digest(source), Generation: 1, PolicyGeneration: 1, ExpiresAt: Expiry(), Resources: []api.ResourceGrant{},
		Data:    []api.DataGrant{{ID: ID(t), SourceObjectID: sourceRef.ID, SourceSHA256: sourceRef.SHA256, RelativePath: ".", Access: "rw", Delivery: "copy", Destination: "/work/main", Delegate: true, HistoryScope: "tree", ExpiresAt: Expiry()}},
		Secrets: []api.SecretGrant{}, Network: []api.NetworkGrant{}, Channels: []api.ChannelGrant{}, Profiles: []api.ProfileGrant{{ID: ID(t), ProfileID: ID(t), Driver: api.DriverCodex, Provider: "component-provider", Delegate: true, ExpiresAt: Expiry()}}}
	f.Ceiling.SHA256 = ""
	sealed, err := api.CanonicalJSON(JSON(t, f.Ceiling))
	if err != nil {
		t.Fatal(err)
	}
	f.Ceiling.SHA256 = Digest(sealed)
	intent := f.Intent(t, api.InternalOrgBootstrap)
	intent.CauseOperationID, intent.CauseRequestID, intent.EffectID, intent.Target = "", "", "", api.LifeRef{}
	object := func(ref api.BlobRef, data []byte, owner api.Actor) api.ObjectWrite {
		return api.ObjectWrite{ObjectKey: ref.ID, Class: ref.Class, Bytes: data, SHA256: ref.SHA256, Origin: "service", ACL: api.ObjectACL{Config: f.Deps.Config, Owner: owner, Audience: "owner", Generation: 1}}
	}
	policy := api.EffectivePolicy{Generation: 1, SHA256: Digest(JSON(t, f.Ceiling)), Context: api.RoleContext{Level: 6, Role: "supervisor"}, Rules: []api.Rule{}, Skip: []api.SkipEntry{}, Sources: []api.SourceRef{}, ProfileExclusions: []api.ID{}}
	var newPolicy *api.EffectivePolicy
	if _, err := f.State.Policy(context.Background(), f.Execution); err != nil {
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeNotFound {
			t.Fatal(err)
		}
		newPolicy = &policy
	}
	if _, err := f.State.Transact(context.Background(), api.Transaction{Scope: f.Execution, Internal: &intent, Writes: api.StateWrites{Policy: newPolicy, Grants: []api.GrantSet{f.Ceiling}, Objects: []api.ObjectWrite{object(sourceRef, source, f.Execution.Actor), object(taskRef, task, principal)}}}); err != nil {
		t.Fatal("component policy/source setup failed", err)
	}
	ticket := api.Ticket{ID: ID(t), PrincipalID: principal.ID, Config: f.Deps.Config, EndpointGeneration: 1, Level: 5, Role: "supervisor", GrantSetID: f.Ceiling.ID, ExpiresAt: Expiry()}
	// Only the primitive already-enrolled ticket is fixture installation data.
	// Close the real writer first. Every reservation/plan/binding below uses
	// production APIs; the fixture never inserts a lane, plan or launch binding.
	f.Replace(t, "ticket", ticket.ID, 1, struct {
		RedeemedBy         api.ID
		PrincipalID        api.ID
		Config             string
		EndpointGeneration api.Generation
		Ticket             api.Ticket
	}{PrincipalID: principal.ID, Config: f.Deps.Config, EndpointGeneration: 1, Ticket: ticket})
	f.Start = api.StartRequest{Lane: string(ID(t)), ProjectID: ID(t), Level: 5, Role: "supervisor", Task: taskRef, Driver: api.DriverCodex, ProfileGrantID: f.Ceiling.Profiles[0].ID,
		Model: "fixture-model", Effort: "high", RootTicketID: ticket.ID, ExpectedPolicyGeneration: 1,
		Budget: api.Budget{WallMS: 60000, CPUSeconds: 10, MemoryBytes: 1 << 20, Processes: 10, DiskBytes: 1 << 20, Currency: "USD"},
		Grants: api.GrantRequest{Resources: []api.ResourceDelegation{}, Data: []api.DataGrantRequest{{ParentGrantID: f.Ceiling.Data[0].ID, RelativePath: ".", Access: "rw", Delivery: "copy", Destination: "/work/main", Delegate: true, ExpiresAt: api.Timestamp(time.Now().Add(30 * time.Minute).UTC().Format(time.RFC3339Nano))}},
			Secrets: []api.SecretDelegation{}, Profiles: []api.ProfileDelegation{{ParentGrantID: f.Ceiling.Profiles[0].ID, ProfileID: f.Ceiling.Profiles[0].ProfileID, Delegate: true, ExpiresAt: api.Timestamp(time.Now().Add(30 * time.Minute).UTC().Format(time.RFC3339Nano))}}, Network: []api.NetworkDelegation{}, Channels: []api.ChannelDelegation{}}}
	f.Admit(t, "lane.start", f.Start)
	return f
}

func (f *Fixture) Admit(t testing.TB, method api.Method, params any) {
	t.Helper()
	request := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: f.Deps.Config, Method: method, RequestID: ID(t), IdempotencyKey: ID(t), Params: JSON(t, params)}
	var err error
	request.RequestSHA256, err = wire.RequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	f.Human.Request = request
	f.Raw, err = json.MarshalIndent(request, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	f.Human.Frame = &Frame{Raw: f.Raw}
	f.Receipt, err = f.State.ReserveRequest(context.Background(), api.RequestReservation{Scope: f.Human, RawRequest: f.Raw, Deadline: Expiry()})
	if err != nil {
		t.Fatal("component public request reservation failed", err)
	}
}

func (f *Fixture) Replace(t testing.TB, kind string, id api.ID, generation api.Generation, value any) {
	f.Corrupt(t, kind, id, generation, value)
	reopened, err := store.New(f.Deps)
	if err != nil {
		t.Fatal("component fixture could not reopen", err)
	}
	f.State = reopened
}

// Corrupt changes protected fixture state only after closing the writer, for
// explicit restart-integrity controls. Production never imports this package.
func (f *Fixture) Corrupt(t testing.TB, kind string, id api.ID, generation api.Generation, value any) {
	t.Helper()
	if err := f.State.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(f.Deps.Directory, "state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	data := JSON(t, value)
	if _, err := tx.Exec("INSERT INTO projection_history(kind,id,data,sha256) VALUES(?,?,?,?)", kind, string(id), data, string(Digest(data))); err != nil {
		tx.Rollback()
		db.Close()
		t.Fatal(err)
	}
	if _, err := tx.Exec("INSERT INTO projections VALUES(?,?,?,?) ON CONFLICT(kind,id) DO UPDATE SET generation=excluded.generation,data=excluded.data", kind, string(id), uint64(generation), data); err != nil {
		tx.Rollback()
		db.Close()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

func (f *Fixture) Intent(t testing.TB, kind api.InternalKind) api.InternalIntent {
	t.Helper()
	return api.InternalIntent{ID: ID(t), Kind: kind, Config: f.Deps.Config, Actor: f.Execution.Actor, RequestedBy: f.Reservation.RequestedBy,
		CauseOperationID: f.Reservation.OperationID, CauseRequestID: f.Reservation.RequestID, EffectID: f.Claim.Record.Effect.ID, Target: f.Reservation.Target, CancellationEpoch: f.Reservation.CancellationEpoch}
}

func (f *Fixture) Reserve(t testing.TB, deadlines ...api.Timestamp) {
	t.Helper()
	deadline := Expiry()
	if len(deadlines) > 1 {
		t.Fatal("fixture reserve accepts one deadline")
	}
	if len(deadlines) == 1 {
		deadline = deadlines[0]
	}
	var err error
	f.Reservation, err = f.State.ReserveLaunch(context.Background(), f.Human, f.ReservationRequest(t))
	if err != nil {
		t.Fatal("store-issued launch reservation failed", err)
	}
	f.Record, err = f.State.LaunchPlan(context.Background(), f.Execution, f.Reservation.ID)
	if err != nil {
		t.Fatal(err)
	}
	effects, err := f.State.PendingEffects(context.Background(), api.CursorRequest{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	for _, effect := range effects {
		if effect.PlanLaunch != nil && effect.PlanLaunch.ReservationID == f.Reservation.ID {
			f.Claim, err = f.State.ClaimEffect(context.Background(), f.Execution, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: deadline})
			if err != nil {
				t.Fatal(err)
			}
			return
		}
	}
	t.Fatal("reservation did not create its planning effect")
}

func (f *Fixture) ReservationRequest(t testing.TB) api.LaunchReservationRequest {
	t.Helper()
	request := api.LaunchReservationRequest{OperationID: f.Receipt.Operation.ID}
	if f.Human.Request.Method == "lane.start" || f.Human.Request.Method == "lane.adopt" {
		if f.Human.Actor.Kind == "human" {
			request.Guards = []api.TransactionGuard{{Ticket: &api.TicketUse{TicketID: f.Start.RootTicketID, PrincipalID: f.Human.Actor.ID, Config: f.Deps.Config, EndpointGeneration: f.Human.EndpointGeneration, Level: f.Start.Level, Role: f.Start.Role, GrantSetID: f.Ceiling.ID}}}
		}
	} else {
		request.Guards = []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: f.Lane.LifeID, Epoch: f.Lane.CancellationEpoch}}}
	}
	return request
}

func (f *Fixture) Transition(t testing.TB, record api.LaunchPlanRecord, writes api.StateWrites, events []api.Event, kind api.InternalKind, effect api.ID) api.Commit {
	t.Helper()
	cause := f.Intent(t, kind)
	if effect != "" {
		cause.EffectID = effect
	}
	writes.LaunchPlans = []api.LaunchPlanRecord{record}
	comparisons := []api.Compare{{Kind: api.CompareLaunchPlan, ID: f.Reservation.ID, Generation: f.Record.Generation}}
	if f.Record.Phase == "reserved" {
		comparisons = append(comparisons, api.Compare{Kind: api.CompareGrants, ID: f.Reservation.GrantSetID})
	}
	if record.Phase == "bound" {
		comparisons = append(comparisons, api.Compare{Kind: api.CompareLane, ID: f.Reservation.Target.LifeID, Generation: f.Reservation.BaseGeneration})
	}
	commit, err := f.State.Transact(context.Background(), api.Transaction{Scope: f.Execution, Internal: &cause, Writes: writes, Events: events, Compare: comparisons,
		Guards: []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: f.Reservation.Target.LifeID, Epoch: f.Reservation.CancellationEpoch}}}})
	if err != nil {
		t.Fatal("launch phase transaction failed", record.Phase, err)
	}
	f.Record = record
	return commit
}

func (f *Fixture) Event(t testing.TB, kind api.EventKind, value any) api.Event {
	t.Helper()
	r := f.Reservation
	return api.Event{Schema: api.SchemaVersion, ID: ID(t), Config: r.Config, Kind: kind, Actor: f.Execution.Actor, RequestedBy: r.RequestedBy,
		OperationID: r.OperationID, RequestID: r.RequestID, LifeID: r.Target.LifeID, Run: r.Target.Run, RootLifeID: r.RootLifeID, ParentLifeID: r.ParentLifeID,
		StarterChain: append([]api.ID{}, r.StarterChain...), StarterEventSeq: r.StarterEventSeq, Origin: "service", Payload: JSON(t, value)}
}

func (f *Fixture) Source(t testing.TB) {
	t.Helper()
	input := f.SourceTransaction(t)
	if _, err := f.State.Transact(context.Background(), input); err != nil {
		t.Fatal("launch source transaction failed", err)
	}
	f.Record = input.Writes.LaunchPlans[0]
}

// SourceTransaction constructs the actual planner issuance transaction without
// committing it, so refusal tests can submit wider grants to the real writer.
func (f *Fixture) SourceTransaction(t testing.TB) api.Transaction {
	t.Helper()
	r := f.Reservation
	grants := f.Ceiling
	grants.ID, grants.LifeID, grants.ParentLifeID = r.GrantSetID, r.Target.LifeID, r.ParentLifeID
	grants.Data = append([]api.DataGrant{}, f.Ceiling.Data...)
	grants.Profiles = append([]api.ProfileGrant{}, f.Ceiling.Profiles...)
	grants.ExpiresAt = f.Start.Grants.Data[0].ExpiresAt
	grants.Data[0].ExpiresAt, grants.Profiles[0].ExpiresAt = grants.ExpiresAt, grants.ExpiresAt
	grants.Data[0].ParentGrantID, grants.Profiles[0].ParentGrantID = f.Ceiling.Data[0].ID, f.Ceiling.Profiles[0].ID
	if r.ParentLifeID == "" {
		grants.Data[0].ParentGrantID, grants.Profiles[0].ParentGrantID = "", ""
	}
	grants.Data[0].ID, grants.Profiles[0].ID = ID(t), ID(t)
	grants.Data[0].RelativePath, grants.Data[0].Access, grants.Data[0].Delivery = f.Start.Grants.Data[0].RelativePath, f.Start.Grants.Data[0].Access, f.Start.Grants.Data[0].Delivery
	grants.Data[0].Destination, grants.Data[0].Delegate = f.Start.Grants.Data[0].Destination, f.Start.Grants.Data[0].Delegate
	grants.Profiles[0].Delegate = f.Start.Grants.Profiles[0].Delegate
	grants.Channels = []api.ChannelGrant{}
	for _, request := range f.Start.Grants.Channels {
		for _, parent := range f.Ceiling.Channels {
			if parent.ID == request.ParentGrantID {
				child := parent
				child.ID, child.ParentGrantID, child.Delegate, child.ExpiresAt = ID(t), parent.ID, request.Delegate, request.ExpiresAt
				if r.ParentLifeID == "" {
					child.ParentGrantID = ""
				}
				grants.Channels = append(grants.Channels, child)
			}
		}
	}
	grants.SHA256 = ""
	sealed, err := api.CanonicalJSON(JSON(t, grants))
	if err != nil {
		t.Fatal(err)
	}
	grants.SHA256 = Digest(sealed)
	source := api.ProjectLaunchSource{EnrollmentID: ID(t), Generation: 1, ProjectID: f.Start.ProjectID, GrantID: grants.Data[0].ID,
		Object: api.BlobRef{ID: f.Ceiling.Data[0].SourceObjectID, SHA256: f.Ceiling.Data[0].SourceSHA256, Bytes: lenSource(t, f), Class: "manifest"}, Base: strings.Repeat("a", 40), HistoryScope: "tree"}
	executable := api.Executable{ID: ID(t), SHA256: Digest([]byte(ID(t))), Version: "component-v1"}
	manifest := api.RuntimeManifest{Schema: "laneboss.runtime.v2", Generation: 1, Artifact: executable, Bootstrap: api.Executable{ID: ID(t), SHA256: Digest([]byte(ID(t))), Version: release.Version}, Objects: []api.RuntimeObject{}, Bindings: []api.InstalledBinding{}}
	runtime := api.LaunchRuntime{EnrollmentID: ID(t), Generation: 1, Backend: "linux-bwrap-landlock", Driver: r.Driver,
		Executable: executable, Manifest: f.Retain(t, "manifest", JSON(t, manifest), f.Execution.Actor, "")}
	inputs := api.LaunchInputs{Grants: grants, Sources: api.LaunchSources{ReservationID: r.ID, Project: source, Runtime: runtime}}
	record := f.Record
	record.Generation++
	record.Phase, record.Inputs = "sourced", &inputs
	cause := f.Intent(t, api.InternalLaunchPlan)
	return api.Transaction{Scope: f.Execution, Internal: &cause,
		Writes:  api.StateWrites{Grants: []api.GrantSet{grants}, LaunchPlans: []api.LaunchPlanRecord{record}},
		Events:  []api.Event{f.Event(t, "grants.issued", api.GrantEvent{GrantSet: grants})},
		Compare: []api.Compare{{Kind: api.CompareLaunchPlan, ID: r.ID, Generation: f.Record.Generation}, {Kind: api.CompareGrants, ID: r.GrantSetID}},
		Guards:  []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: r.Target.LifeID, Epoch: r.CancellationEpoch}}}}
}

func lenSource(t testing.TB, f *Fixture) int64 {
	t.Helper()
	meta, err := f.State.ObjectMetadata(context.Background(), f.Execution, f.Ceiling.Data[0].SourceObjectID)
	if err != nil {
		t.Fatal(err)
	}
	return meta.Ref.Bytes
}

func (f *Fixture) Retain(t testing.TB, class string, data []byte, owner api.Actor, life api.ID) api.BlobRef {
	t.Helper()
	intent := f.Intent(t, api.InternalLaunchPlan)
	ref, err := f.State.RetainObject(context.Background(), f.Execution, api.RetainObjectRequest{Intent: intent,
		Object: api.ObjectWrite{ObjectKey: ID(t), Class: class, Bytes: data, SHA256: Digest(data), Origin: "service", ACL: api.ObjectACL{Config: f.Deps.Config, Owner: owner, LifeID: life, Audience: "owner", Generation: 1}}})
	if err != nil {
		t.Fatal("component immutable object retention failed", err)
	}
	return ref
}

func (f *Fixture) BuildPlan(t testing.TB, registered bool) {
	t.Helper()
	f.BuildPlanForIdentity(t, registered, uint32(os.Geteuid()), uint32(os.Getegid()))
}

// BuildPlanForIdentity retains the supplied component lease before sealing
// any plan/spec bytes. Endpoint composition fixtures model a distinct lane UID;
// native connector fixtures can keep the default actual process identity.
func (f *Fixture) BuildPlanForIdentity(t testing.TB, registered bool, uid, gid uint32) {
	t.Helper()
	r := f.Reservation
	inputs := *f.Record.Inputs
	allocateCause := f.Intent(t, api.InternalHelperAllocate)
	allocateCause.EffectID = ID(t)
	allocate := api.Effect{ID: allocateCause.EffectID, OperationID: r.OperationID, Context: &allocateCause,
		HelperAllocate: &api.HelperLeaseRequest{ReservationID: r.ID, Cause: allocateCause, Config: r.Config, LifeID: r.Target.LifeID, Backend: inputs.Sources.Runtime.Backend, Budget: f.Start.Budget, RuntimeManifestID: inputs.Sources.Runtime.Manifest.ID}}
	f.Allocation = *allocate.HelperAllocate
	parent := f.Intent(t, api.InternalLaunchPlan)
	if _, err := f.State.Transact(context.Background(), api.Transaction{Scope: f.Execution, Internal: &parent, Effects: []api.Effect{allocate}}); err != nil {
		t.Fatal(err)
	}
	claim, err := f.State.ClaimEffect(context.Background(), f.Execution, api.EffectClaimRequest{EffectID: allocate.ID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: Expiry()})
	if err != nil {
		t.Fatal(err)
	}
	lease := api.HelperLease{ID: ID(t), UID: uid, GID: gid, ContainmentID: ID(t), EndpointGeneration: 1}
	if _, err := f.State.CompleteEffect(context.Background(), f.Execution, api.EffectOutcome{EffectID: allocate.ID, ClaimID: claim.ClaimID, ExpectedGeneration: claim.Record.Generation, Status: "succeeded", HelperLease: &lease}); err != nil {
		t.Fatal(err)
	}
	workspace := api.Workspace{ID: ID(t), ProjectID: inputs.Sources.Project.ProjectID, Base: inputs.Sources.Project.Base, Branch: "lane/" + string(r.Target.LifeID), LogicalCWD: "/work/main", Snapshot: f.Retain(t, "manifest", []byte("component workspace "+string(ID(t))), f.Execution.Actor, r.Target.LifeID)}
	home := api.PrivateHomeBinding{LifeID: r.Target.LifeID, RootID: ID(t), Generation: 1, Home: api.PrivateHome{ID: ID(t), WorkspaceID: workspace.ID, VendorDirectory: ".codex", HistoryID: ID(t)}}
	materialization := api.Materialization{GrantSetID: r.GrantSetID, Manifest: f.Retain(t, "manifest", []byte("component materialization "+string(ID(t))), f.Execution.Actor, r.Target.LifeID),
		Objects: []api.MaterializedObject{{GrantID: inputs.Grants.Data[0].ID, SourceIdentity: "component-source-inode", DestinationIdentity: "component-destination-inode", SnapshotSHA256: workspace.Snapshot.SHA256, WorkspaceID: workspace.ID}}}
	workerInput := f.Retain(t, "manifest", JSON(t, api.LaunchDataRequest{ReservationID: r.ID, GrantSetID: r.GrantSetID, LeaseID: lease.ID}), f.Execution.Actor, r.Target.LifeID)
	workerCause := f.Intent(t, api.InternalObjectRetain)
	workerCause.EffectID = ID(t)
	job := api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: "import", Executable: api.Executable{ID: ID(t), SHA256: Digest([]byte(ID(t))), Version: "component-v1"}, Argv: []string{"component-fixed-materialization"}, Input: workerInput, GrantSetID: r.GrantSetID, Budget: f.Start.Budget}
	workerEffect := api.Effect{ID: workerCause.EffectID, OperationID: r.OperationID, Context: &workerCause, Worker: &job}
	parent = f.Intent(t, api.InternalLaunchPlan)
	if _, err := f.State.Transact(context.Background(), api.Transaction{Scope: f.Execution, Internal: &parent, Effects: []api.Effect{workerEffect}}); err != nil {
		t.Fatal(err)
	}
	workerClaim, err := f.State.ClaimEffect(context.Background(), f.Execution, api.EffectClaimRequest{EffectID: workerEffect.ID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: Expiry()})
	if err != nil {
		t.Fatal(err)
	}
	zero, exit := uint64(0), 0
	measured := api.ProcessObservation{Handle: api.ProcessHandle{ID: ID(t), Target: r.Target, ContainmentID: ID(t), Generation: "component-materialization-process"}, State: "exited", ExitCode: &exit, Survivors: &zero, PromptStatus: "not_written", ObservedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}
	if _, err := f.State.CompleteEffect(context.Background(), f.Execution, api.EffectOutcome{EffectID: workerEffect.ID, ClaimID: workerClaim.ClaimID, ExpectedGeneration: workerClaim.Record.Generation, Status: "succeeded", Output: &materialization.Manifest, Observation: &measured}); err != nil {
		t.Fatal("component fixed-worker receipt was not retained", err)
	}
	slot := api.CredentialSlot{ID: ID(t), ProfileGrantID: inputs.Grants.Profiles[0].ID, ProfileID: inputs.Grants.Profiles[0].ProfileID, Mode: "codex-file", LeaseID: ID(t), ExpiresAt: Expiry()}
	runner := api.RunnerPlan{Driver: r.Driver, Executable: inputs.Sources.Runtime.Executable, Argv: []string{string(inputs.Sources.Runtime.Executable.ID), "component"}, CWD: workspace.LogicalCWD, EnvironmentNames: []string{},
		Prompt: f.Retain(t, "prompt", []byte("component prompt "+string(ID(t))), f.Execution.Actor, r.Target.LifeID), Home: home.Home, Slot: slot,
		Session: api.Session{ID: ID(t), Driver: r.Driver, VendorVersion: "component-v1", HomeID: home.Home.ID, HistoryID: home.Home.HistoryID, LogicalCWD: workspace.LogicalCWD}, AdapterVersion: "component-v1"}
	capture := api.CaptureBinding{ID: ID(t), Config: r.Config, ReservationID: r.ID, Target: r.Target, LaunchID: r.LaunchID, HelperLeaseID: lease.ID, OperationID: r.OperationID, RequestID: r.RequestID, RequestedBy: r.RequestedBy, Generation: 1,
		Status: "refused", Streams: []api.CaptureStreamBinding{}, Refusal: api.NotImplemented("lb-v2-admin", "component unavailable capture disposition")}
	capture.Refusal.OperationID = r.OperationID
	if registered {
		capture = f.RegisterWorker(t, capture, inputs)
	}
	kind := api.EventKind("capture.refused")
	if registered {
		kind = "capture.bound"
	}
	cause := f.Intent(t, api.InternalLaunchPlan)
	if _, err := f.State.Transact(context.Background(), api.Transaction{Scope: f.Execution, Internal: &cause, Events: []api.Event{f.Event(t, kind, capture)}}); err != nil {
		t.Fatal("capture disposition commit failed", err)
	}
	f.Plan = api.LaunchPlan{Reservation: r, Inputs: inputs, Lease: lease, Data: api.LaunchData{ReservationID: r.ID, Target: r.Target, LeaseID: lease.ID, Source: inputs.Sources.Project, Workspace: workspace, Home: home, Materialization: materialization}, Runner: runner,
		Injection: api.Injection{Target: r.Target, SlotIDs: []api.ID{slot.ID}, TaskSecretNames: []string{}, TaskSecretFileNames: []string{}, GrantIDs: []api.ID{}, SourceVersions: []string{}, Outcome: "prepared"}, Budget: f.Start.Budget, Capture: capture}
	if f.PlanSetup != nil {
		f.PlanSetup(&f.Plan)
	}
	record := f.Record
	record.Generation++
	record.Phase, record.Plan = "planned", &f.Plan
	f.Transition(t, record, api.StateWrites{}, []api.Event{f.Event(t, "launch.planned", record)}, api.InternalLaunchPlan, "")
}

func (f *Fixture) RegisterWorker(t testing.TB, b api.CaptureBinding, inputs api.LaunchInputs) api.CaptureBinding {
	t.Helper()
	b.Status, b.Refusal, b.WorkerLeaseID, b.EffectID, b.ProducerID, b.ProducerGeneration, b.BootID = "registered", nil, ID(t), f.Claim.Record.Effect.ID, ID(t), "component-capture-process", "component-boot"
	b.Supervisor = &api.Executable{ID: ID(t), SHA256: Digest([]byte(ID(t))), Version: "component-v1"}
	b.Streams = []api.CaptureStreamBinding{{ID: ID(t), Stream: "stdout", PipeID: ID(t)}, {ID: ID(t), Stream: "stderr", PipeID: ID(t)}}
	if f.CaptureSetup != nil {
		b = f.CaptureSetup(b)
	}
	f.WorkerLease = api.WorkerLease{ID: b.WorkerLeaseID, Kind: "capture_supervisor", Target: b.Target, OperationID: b.OperationID, EffectID: b.EffectID,
		Input: f.Retain(t, "manifest", []byte("component narrow capture input "+string(ID(t))), f.Execution.Actor, b.Target.LifeID), RuntimeManifest: inputs.Sources.Runtime.Manifest, GrantSetID: f.Reservation.GrantSetID, Generation: 1, ExpiresAt: Expiry()}
	cause := f.Intent(t, api.InternalLaunchPlan)
	if _, err := f.State.Transact(context.Background(), api.Transaction{Scope: f.Execution, Internal: &cause, Writes: api.StateWrites{WorkerLeases: []api.WorkerLease{f.WorkerLease}}}); err != nil {
		t.Fatal(err)
	}
	worker := api.Actor{Kind: "worker", ID: b.ProducerID}
	launch := api.LaunchRecord{Kind: "worker", ID: ID(t), Config: b.Config, Target: b.Target, RootLifeID: b.Target.LifeID, StarterChain: []api.ID{}, Actor: worker, UIDLeaseID: ID(t), HostUID: uint32(os.Geteuid()),
		ProcessGeneration: b.ProducerGeneration, ContainmentID: ID(t), GrantSetID: f.Reservation.GrantSetID, GrantsSHA256: inputs.Grants.SHA256, PolicyGeneration: 1, EndpointGeneration: 1}
	workerCause := f.Intent(t, api.InternalLifecycleEffect)
	event := f.Event(t, "identity.bound", launch)
	if _, err := f.State.Transact(context.Background(), api.Transaction{Scope: f.Execution, Internal: &workerCause, Events: []api.Event{event}}); err != nil {
		t.Fatal(err)
	}
	connection := &Connection{Identity: ID(t), Endpoint: api.InstalledBinding{Config: b.Config, Class: api.EndpointWorker, EndpointGeneration: 1, LaunchID: launch.ID, Target: &b.Target, WorkerLeaseID: b.WorkerLeaseID},
		Verified: &Peer{FactsValue: api.PeerFacts{HostUID: launch.HostUID, HostGID: uint32(os.Getegid()), HostPID: os.Getpid(), ProcessGeneration: b.ProducerGeneration, ContainmentID: launch.ContainmentID}}}
	f.Worker = api.Scope{Config: b.Config, Actor: worker, LaunchID: launch.ID, EndpointGeneration: 1, PolicyGeneration: 1, Connection: connection, Source: "worker", Frame: &Frame{Raw: []byte("component outside-job frame")}}
	return b
}

func (f *Fixture) Spec(t testing.TB) {
	t.Helper()
	p, r := f.Plan, f.Reservation
	spec := api.LaunchSpec{Kind: "agent", PlanID: r.ID, Capture: &p.Capture, ID: r.SpecID, Target: r.Target, LaunchID: r.LaunchID, Backend: p.Inputs.Sources.Runtime.Backend, UIDLeaseID: p.Lease.ID,
		Workspace: p.Data.Workspace, Materialization: p.Data.Materialization, Grants: p.Inputs.Grants, Runner: &p.Runner, Injection: p.Injection, Budget: p.Budget, EndpointGeneration: p.Lease.EndpointGeneration, RuntimeManifest: p.Inputs.Sources.Runtime.Manifest, PolicyGeneration: r.PolicyGeneration}
	data, err := api.CanonicalJSON(JSON(t, spec))
	if err != nil {
		t.Fatal(err)
	}
	ref := f.Retain(t, "launch_spec", data, f.Execution.Actor, r.Target.LifeID)
	cause := f.Intent(t, api.InternalHelperRegister)
	handoff := api.PreparedSpecHandoff{Cause: cause, Config: r.Config, Spec: spec, Original: ref, SpecSHA256: Digest(data), OperationID: r.OperationID, RequestID: r.RequestID}
	record := f.Record
	record.Generation++
	record.Phase, record.Handoff = "spec_retained", &handoff
	f.Transition(t, record, api.StateWrites{}, nil, api.InternalLaunchPlan, "")
}

func (f *Fixture) PrepareJob(t testing.TB) {
	t.Helper()
	r, p := f.Reservation, f.Plan
	prepare := f.Intent(t, api.InternalHelperPrepare)
	prepare.EffectID = ID(t)
	request := api.HelperLaunchRequest{Cause: prepare, LeaseID: p.Lease.ID, PreparedSpecID: r.SpecID, SpecSHA256: f.Record.Handoff.SpecSHA256}
	effect := api.Effect{ID: prepare.EffectID, OperationID: r.OperationID, Context: &prepare, HelperPrepare: &request}
	if _, err := f.State.Transact(context.Background(), api.Transaction{Scope: f.Execution, Internal: &prepare, Effects: []api.Effect{effect}}); err != nil {
		t.Fatal(err)
	}
	claim, err := f.State.ClaimEffect(context.Background(), f.Execution, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: Expiry()})
	if err != nil {
		t.Fatal(err)
	}
	f.Prepared = api.PreparedLaunch{ID: ID(t), SpecSHA256: request.SpecSHA256, Target: r.Target, ContainmentID: p.Lease.ContainmentID, ProcessGeneration: "component-agent-process", EndpointGeneration: p.Lease.EndpointGeneration, GateID: ID(t)}
	// A new prepared gate has no process observation yet. In particular a
	// child cannot reuse the parent's previously opened process handle.
	f.Process = api.ProcessHandle{}
	f.PreparedClaim = claim
}

func (f *Fixture) Bind(t testing.TB, retainedTurn ...api.TurnSnapshot) {
	t.Helper()
	if f.PreparedClaim.ClaimID == "" {
		f.PrepareJob(t)
	}
	r, p, claim := f.Reservation, f.Plan, f.PreparedClaim
	effect := claim.Record.Effect
	var err error
	launch := api.LaunchRecord{Kind: "agent", ID: r.LaunchID, Config: r.Config, Target: r.Target, RootLifeID: r.RootLifeID, ParentLifeID: r.ParentLifeID, StarterChain: append([]api.ID{}, r.StarterChain...), StarterEventSeq: r.StarterEventSeq,
		Actor: api.Actor{Kind: "lane", ID: ID(t), LifeID: r.Target.LifeID, Level: f.Start.Level, Role: f.Start.Role}, UIDLeaseID: p.Lease.ID, HostUID: p.Lease.UID, ProcessGeneration: f.Prepared.ProcessGeneration,
		ContainmentID: p.Lease.ContainmentID, GrantSetID: r.GrantSetID, GrantsSHA256: p.Inputs.Grants.SHA256, PolicyGeneration: r.PolicyGeneration, EndpointGeneration: p.Lease.EndpointGeneration}
	binding := api.LaunchBindingRequest{Record: launch, Prepared: f.Prepared, Recovery: &api.LaunchRecovery{PlanID: r.ID, OriginalRequest: r.OriginalRequest, Handoff: *f.Record.Handoff, Home: p.Data.Home, Capture: p.Capture}}
	f.Lane = api.Lane{Task: f.Start.Task, LaunchID: r.LaunchID, CancellationEpoch: r.CancellationEpoch, Counters: api.TaskCounters{}, ProfileGrantID: p.Runner.Slot.ProfileGrantID, Model: f.Start.Model, Effort: f.Start.Effort, BudgetRemaining: p.Budget,
		LifeID: r.Target.LifeID, Name: f.Start.Lane, ParentLifeID: r.ParentLifeID, RootLifeID: r.RootLifeID, StarterChain: append([]api.ID{}, r.StarterChain...), StarterEventSeq: r.StarterEventSeq, Level: f.Start.Level, Role: f.Start.Role, State: "preparing", Generation: r.Generation, Run: r.Target.Run,
		LogicalTurnID: ID(t), Session: p.Runner.Session, Workspace: p.Data.Workspace, GrantSetID: r.GrantSetID, PolicyGeneration: r.PolicyGeneration, Containment: "prepared"}
	turn := api.TurnSnapshot{Target: r.Target, LogicalTurnID: f.Lane.LogicalTurnID, Task: f.Lane.Task, Prompt: &p.Runner.Prompt, Trigger: api.Trigger{Kind: r.Mode, MailIDs: []api.ID{}, CausingSeqs: []api.Sequence{}}, PolicyGeneration: r.PolicyGeneration, Generation: 1, GuidanceID: ID(t), MailIDs: []api.ID{}, Status: "prepared", CreatedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}
	if len(retainedTurn) > 1 {
		t.Fatal("binding fixture accepts one retained turn")
	}
	if len(retainedTurn) == 1 {
		turn = retainedTurn[0]
		turn.Generation++
		turn.Prompt, turn.Status = &p.Runner.Prompt, "prepared"
		f.Lane.LogicalTurnID = turn.LogicalTurnID
	}
	endpoint := api.InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision, Protocol: api.Protocol, APISchema: api.SchemaVersion, Config: r.Config, Class: api.EndpointLane,
		InstallationGeneration: 1, EndpointGeneration: p.Lease.EndpointGeneration, ServiceUID: uint32(os.Geteuid()), ServiceGID: uint32(os.Getegid()), Socket: filepath.Join(f.Deps.Directory, "component.sock"), ArtifactSHA256: Digest([]byte(ID(t))), ServiceVersion: release.Version, Backend: p.Inputs.Sources.Runtime.Backend, LaunchID: r.LaunchID, Target: &r.Target}
	created := api.LaunchEvent{Task: f.Lane.Task, LaunchID: r.LaunchID, Lane: f.Lane, GrantSetID: r.GrantSetID, GrantsSHA256: p.Inputs.Grants.SHA256, PolicyGeneration: r.PolicyGeneration,
		PromptTemplate: api.TemplateRef{ID: ID(t), SourceSHA256: Digest([]byte(ID(t))), Generation: 1, RenderedSHA256: p.Runner.Prompt.SHA256}, TaskSHA256: f.Lane.Task.SHA256, Prompt: p.Runner.Prompt, BoundaryBackend: endpoint.Backend, EndpointGeneration: endpoint.EndpointGeneration,
		TaskSecretNames: []string{}, TaskSecretFileNames: []string{}, SecretGrantIDs: []api.ID{}, SecretSourceVersions: []string{}, InjectionOutcome: p.Injection.Outcome, Trigger: turn.Trigger}
	record := f.Record
	record.Generation++
	record.Phase = "bound"
	createdKind := api.EventKind("lane.created")
	if r.Mode == "adopt" {
		createdKind = "lane.adopted"
	}
	if r.BaseGeneration > 0 {
		createdKind = "launch.prepared"
	}
	f.Transition(t, record, api.StateWrites{IdentityBindings: []api.LaunchBindingRequest{binding}, Lanes: []api.Lane{f.Lane}, Turns: []api.TurnSnapshot{turn}, Endpoints: []api.EndpointProjection{{Binding: endpoint, Generation: 1}}},
		[]api.Event{f.Event(t, "identity.bound", launch), f.Event(t, createdKind, created)}, api.InternalHelperPrepare, effect.ID)
	if _, err := f.State.CompleteEffect(context.Background(), f.Execution, api.EffectOutcome{EffectID: effect.ID, ClaimID: claim.ClaimID, ExpectedGeneration: claim.Record.Generation, Status: "succeeded", Prepared: &f.Prepared}); err != nil {
		t.Fatal(err)
	}
	f.Binding, err = f.State.LaunchBinding(context.Background(), r.LaunchID)
	if err != nil {
		t.Fatal(err)
	}
}

func Ready(t testing.TB, registered bool) *Fixture {
	t.Helper()
	return ReadyForIdentity(t, registered, uint32(os.Geteuid()), uint32(os.Getegid()))
}

func ReadyForIdentity(t testing.TB, registered bool, uid, gid uint32) *Fixture {
	t.Helper()
	f := New(t)
	f.Reserve(t)
	f.Source(t)
	f.BuildPlanForIdentity(t, registered, uid, gid)
	f.Spec(t)
	f.Bind(t)
	return f
}

func (f *Fixture) LaneScope(t testing.TB) api.Scope {
	t.Helper()
	r := f.Binding.Record
	connection := &Connection{Identity: ID(t), Endpoint: api.InstalledBinding{Config: r.Config, Class: api.EndpointLane, LaunchID: r.ID, Target: &r.Target, EndpointGeneration: r.EndpointGeneration}, Verified: &Peer{FactsValue: api.PeerFacts{HostUID: r.HostUID, HostGID: uint32(os.Getegid()), HostPID: os.Getpid(), ContainmentID: r.ContainmentID, ProcessGeneration: "component-lane-connector"}}}
	return api.Scope{Config: r.Config, Actor: r.Actor, LaunchID: r.ID, EndpointGeneration: r.EndpointGeneration, PolicyGeneration: r.PolicyGeneration, Connection: connection, Source: "cli"}
}

// ControlledChild supplies an actual ancestor endpoint for retained-life
// controls. A service actor never substitutes for the public controller.
func ControlledChild(t testing.TB) *Fixture {
	t.Helper()
	f := Ready(t, true)
	f.Child(t)
	return f
}

func (f *Fixture) Child(t testing.TB, beforeBind ...func(*Fixture)) {
	t.Helper()
	f.Opened(t)
	parent := f.LaneScope(t)
	cause := f.Intent(t, api.InternalObjectRetain)
	raw := []byte("parent controlled task " + string(ID(t)))
	task, err := f.State.RetainObject(context.Background(), f.Execution, api.RetainObjectRequest{Intent: cause, Object: api.ObjectWrite{ObjectKey: ID(t), Class: "task", Bytes: raw, SHA256: Digest(raw), Origin: "service", ACL: api.ObjectACL{Config: f.Deps.Config, Owner: parent.Actor, Audience: "owner", Generation: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	f.Ceiling = f.Plan.Inputs.Grants
	f.Start.Lane = string(ID(t))
	f.Start.Level, f.Start.Role, f.Start.RootTicketID, f.Start.Task = 3, "executor", "", task
	f.Start.Grants.Data = append([]api.DataGrantRequest{}, f.Start.Grants.Data...)
	f.Start.Grants.Profiles = append([]api.ProfileDelegation{}, f.Start.Grants.Profiles...)
	f.Start.Grants.Data[0].ParentGrantID = f.Ceiling.Data[0].ID
	f.Start.Grants.Profiles[0].ParentGrantID = f.Ceiling.Profiles[0].ID
	expires := api.Timestamp(time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339Nano))
	f.Start.Grants.Data[0].ExpiresAt, f.Start.Grants.Profiles[0].ExpiresAt = expires, expires
	f.Start.ProfileGrantID = f.Ceiling.Profiles[0].ID
	f.Human = parent
	f.Admit(t, "lane.start", f.Start)
	f.Reserve(t)
	f.Source(t)
	f.BuildPlan(t, true)
	f.Spec(t)
	f.PreparedClaim = api.EffectLease{}
	if len(beforeBind) != 0 {
		f.PrepareJob(t)
		for _, prepare := range beforeBind {
			prepare(f)
		}
	}
	f.Bind(t)
}

func (f *Fixture) CaptureData(t testing.TB, data []byte) api.BlobRef {
	t.Helper()
	b := f.Plan.Capture
	intent := api.InternalIntent{ID: ID(t), Kind: api.InternalCaptureAppend, Config: b.Config, Actor: f.Worker.Actor, RequestedBy: b.RequestedBy, CauseOperationID: b.OperationID, CauseRequestID: b.RequestID, EffectID: b.EffectID, Target: b.Target, CancellationEpoch: f.Reservation.CancellationEpoch}
	ref, err := f.State.RetainObject(context.Background(), f.Worker, api.RetainObjectRequest{Intent: intent, Object: api.ObjectWrite{ObjectKey: ID(t), Class: "capture", Bytes: data, SHA256: Digest(data), Origin: "service", ACL: api.ObjectACL{Config: b.Config, Owner: f.Worker.Actor, LifeID: b.Target.LifeID, Audience: "owner", Generation: 1}}})
	if err != nil {
		t.Fatal("registered capture bytes were not retained", err)
	}
	return ref
}

func (f *Fixture) AppendRequest(t testing.TB, data *api.BlobRef, eof bool) api.CaptureAppendRequest {
	t.Helper()
	b := f.Plan.Capture
	return api.CaptureAppendRequest{BindingID: b.ID, ExpectedGeneration: 1, StreamID: b.Streams[0].ID, Data: data, EOF: eof,
		Intent: api.InternalIntent{ID: ID(t), Kind: api.InternalCaptureAppend, Config: b.Config, Actor: f.Worker.Actor, RequestedBy: b.RequestedBy, CauseOperationID: b.OperationID, CauseRequestID: b.RequestID, EffectID: b.EffectID, Target: b.Target, CancellationEpoch: f.Reservation.CancellationEpoch}}
}

func (f *Fixture) Observation(t testing.TB, state string) api.LaunchReconciliation {
	t.Helper()
	if f.Process.ID == "" {
		f.Process = api.ProcessHandle{ID: ID(t), Target: f.Reservation.Target, ContainmentID: f.Prepared.ContainmentID, Generation: f.Prepared.ProcessGeneration}
	}
	survivors := uint64(1)
	if state == "exited" {
		survivors = 0
	}
	observation := api.ProcessObservation{Handle: f.Process, State: state, Survivors: &survivors, PromptStatus: "written", ObservedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}
	if state == "exited" {
		exit := 0
		observation.ExitCode = &exit
	}
	permit := api.LaunchPermit{LaunchID: f.Binding.Record.ID, PreparedID: f.Binding.Prepared.ID, RecordSHA256: f.Binding.Identity.RecordSHA256, CommittedSeq: f.Binding.Identity.CommittedSeq}
	return api.LaunchReconciliation{Prepared: &f.Prepared, Process: &f.Process, Observation: observation, GateState: state, ConsumedPermit: &permit}
}

func (f *Fixture) Opened(t testing.TB, native ...api.LaunchReconciliation) {
	t.Helper()
	observer, ok := any(f.State).(interface {
		RecordLaunchObservation(context.Context, api.ID, api.LaunchReconciliation) error
	})
	if !ok {
		t.Fatal("store retained observation port is absent")
	}
	measured := f.Observation(t, "running")
	if len(native) == 1 && native[0].Process != nil {
		measured, f.Process = native[0], *native[0].Process
	}
	if err := observer.RecordLaunchObservation(context.Background(), f.Reservation.LaunchID, measured); err != nil {
		t.Fatal("component gate observation was not retained", err)
	}
	f.Lane.Generation++
	f.Lane.State, f.Lane.Containment = "running", "running"
	record := f.Record
	record.Generation++
	record.Phase = "opened"
	f.Transition(t, record, api.StateWrites{Lanes: []api.Lane{f.Lane}}, nil, api.InternalHelperOpen, "")
	if _, err := f.State.CompleteEffect(context.Background(), f.Execution, api.EffectOutcome{EffectID: f.Claim.Record.Effect.ID, ClaimID: f.Claim.ClaimID, ExpectedGeneration: f.Claim.Record.Generation, Status: "succeeded", LaunchPlan: &f.Plan, Process: &f.Process}); err != nil {
		t.Fatal("component observed planning completion failed", err)
	}
}

func (f *Fixture) Ended(t testing.TB, exitCodes ...int) {
	t.Helper()
	ctx := context.Background()
	before := f.Lane.Generation
	f.Lane.Generation++
	f.Lane.State, f.Lane.Containment = "verifying", "quiescent"
	f.Lane.Session.VendorID = "component-private-session"
	measured := f.Observation(t, "exited")
	exit := 0
	if len(exitCodes) > 1 {
		t.Fatal("ended fixture accepts one measured exit code")
	}
	if len(exitCodes) == 1 {
		exit = exitCodes[0]
	}
	measured.Observation.ExitCode = &exit
	observation := measured.Observation
	observer, ok := any(f.State).(interface {
		RecordLaunchObservation(context.Context, api.ID, api.LaunchReconciliation) error
	})
	if !ok {
		t.Fatal("store retained observation port is absent")
	}
	if err := observer.RecordLaunchObservation(ctx, f.Reservation.LaunchID, measured); err != nil {
		t.Fatal("component final helper observation failed", err)
	}
	// This observes a process whose gate already opened and whose measured
	// exit is retained above. It is not new helper-open authority; that path
	// requires a fresh policy fence and the retained launch-plan write.
	cause := f.Intent(t, api.InternalLifecycleEffect)
	input := api.Transaction{Scope: f.Execution, Internal: &cause, Writes: api.StateWrites{Lanes: []api.Lane{f.Lane}},
		Events:  []api.Event{f.Event(t, "runner.session", f.Lane.Session)},
		Compare: []api.Compare{{Kind: api.CompareLane, ID: f.Lane.LifeID, Generation: before}},
		Guards:  []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: f.Lane.LifeID, Epoch: f.Lane.CancellationEpoch}}}}
	if err := api.ValidateTransactionShape(input); err != nil {
		t.Fatal("component session observation shape failed", err)
	}
	if _, err := f.State.Transact(ctx, input); err != nil {
		t.Fatal("component retained session transition failed", err)
	}
	actual, err := f.State.Lane(ctx, f.Execution, f.Reservation.Target)
	if err != nil || actual.State != "verifying" || actual.Containment != "quiescent" || actual.Generation != f.Lane.Generation || actual.Session != f.Lane.Session {
		t.Fatal("component ended session was not retained", err)
	}
	cause = f.Intent(t, api.InternalHelperStop)
	end := api.RunEndEvent{LaunchID: f.Reservation.LaunchID, Reason: "exit", Observation: observation, BudgetRemaining: f.Lane.BudgetRemaining}
	if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause, Events: []api.Event{f.Event(t, "lane.ended", end)}}); err != nil {
		t.Fatal("component measured run end failed", err)
	}
}

func (f *Fixture) ExpireClaim(t testing.TB) {
	t.Helper()
	record, err := f.State.Effect(context.Background(), f.Execution, f.Claim.Record.Effect.ID)
	if err != nil {
		t.Fatal(err)
	}
	record.ClaimExpiresAt = api.Timestamp(time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano))
	if err := f.State.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(f.Deps.Directory, "state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := db.Exec("UPDATE effect_states SET data=? WHERE id=?", JSON(t, record), string(record.Effect.ID))
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		db.Close()
		t.Fatal("fixture expiry did not update one retained claim", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	f.State, err = store.New(f.Deps)
	if err != nil {
		t.Fatal(err)
	}
}
