package secrets

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	release "laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
	"laneboss.io/laneboss/internal/v2/secrets/testdir"
)

// These fixtures exercise dispatch/validation only. Unexpected calls reach a
// nil embedded interface and fail; they do not simulate a working dependency.
type backendFixture struct {
	api.SecretBackend
}

type storeFixture struct {
	api.StateStore
	stages testdir.StageLedger
	lane   api.Lane
	grants api.GrantSet
	policy api.EffectivePolicy
	lease  api.WorkerLease
	err    error
	reads  int
}

func (f *storeFixture) Transact(ctx context.Context, input api.Transaction) (api.Commit, error) {
	return f.stages.Transact(ctx, input)
}

func (f *storeFixture) CommitSecretStage(ctx context.Context, input api.Transaction, allocated api.SecretStage) (api.Commit, error) {
	return f.stages.CommitSecretStage(ctx, input, allocated)
}

func (*storeFixture) LookupReceipt(context.Context, api.Scope, api.RequestKey) (api.MutationReceipt, error) {
	return api.MutationReceipt{}, api.NotImplemented("lb-v2-service", "fixture receipt store")
}

func (*storeFixture) PendingEffects(context.Context, api.CursorRequest) ([]api.Effect, error) {
	return nil, api.NotImplemented("lb-v2-service", "fixture pending effects")
}
func (*storeFixture) Effect(context.Context, api.Scope, api.ID) (api.EffectRecord, error) {
	return api.EffectRecord{}, api.NotImplemented("lb-v2-service", "fixture effect lookup")
}

func (f *storeFixture) Lane(ctx context.Context, scope api.Scope, target api.LifeRef) (api.Lane, error) {
	f.reads++
	if f.err != nil {
		return api.Lane{}, f.err
	}
	if target.LifeID != f.lane.LifeID || target.Run != f.lane.Run {
		return api.Lane{}, &api.Error{Code: api.CodeNotFound, Message: "fixture target absent"}
	}
	return f.lane, nil
}

func (f *storeFixture) Grants(ctx context.Context, id api.ID) (api.GrantSet, error) {
	f.reads++
	if id != f.grants.ID {
		return api.GrantSet{}, &api.Error{Code: api.CodeNotFound, Message: "fixture grant absent"}
	}
	return f.grants, f.err
}

func (f *storeFixture) WorkerLease(_ context.Context, scope api.Scope, id api.ID) (api.WorkerLease, error) {
	f.reads++
	if f.err != nil {
		return api.WorkerLease{}, f.err
	}
	if scope.Config != "service-case" || scope.Actor.Kind != "service" || id != f.lease.ID {
		return api.WorkerLease{}, &api.Error{Code: api.CodeNotFound, Message: "fixture worker lease absent"}
	}
	return f.lease, nil
}

func (f *storeFixture) Policy(_ context.Context, _ api.Scope) (api.EffectivePolicy, error) {
	f.reads++
	return f.policy, f.err
}
func (f *storeFixture) CurrentApprovedPolicy(ctx context.Context, scope api.Scope) (api.EffectivePolicy, error) {
	return f.Policy(ctx, scope)
}

type grantsFixture struct {
	api.GrantResolver
	err  error
	seen []api.GrantSet
}

func (f *grantsFixture) Revalidate(ctx context.Context, input api.GrantSet) (api.GrantSet, error) {
	f.seen = append(f.seen, input)
	if f.err != nil {
		return api.GrantSet{}, f.err
	}
	return input, nil
}

type humanFixture struct {
	api.HumanVerifier
	checked int
}

func (f *humanFixture) CheckProof(ctx context.Context, scope api.Scope, proof api.ProofRef, target api.HumanChallengeRequest) (api.VerifiedHumanProof, error) {
	f.checked++
	return api.VerifiedHumanProof{}, api.NotImplemented("lb-v2-identity", "fixture proof verification")
}

type clockFixture struct{ now time.Time }

func (f *clockFixture) Now() time.Time { return f.now }

type registryFixture struct {
	handlers map[api.Method]api.Handler
	err      error
}

func (f *registryFixture) Register(method api.Method, handler api.Handler) error {
	if f.err != nil {
		return f.err
	}
	if f.handlers[method] != nil {
		return &api.Error{Code: api.CodeConflict, Message: "fixture duplicate method"}
	}
	f.handlers[method] = handler
	return nil
}

func (f *registryFixture) RegisterStream(method api.Method, handler api.StreamHandler) error {
	return api.NotImplemented("lb-v2-service", "fixture stream registration")
}

func digestFixture(input string) api.Digest {
	sum := sha256.Sum256([]byte(input))
	return api.Digest(hex.EncodeToString(sum[:]))
}

// These typed handles model transport decisions for unit controls only. They
// do not establish OS peer identity, WebAuthn or a production read session.
type peerFixture struct{ err error }

func (f *peerFixture) Facts(context.Context) (api.PeerFacts, error) {
	return api.PeerFacts{}, api.NotImplemented("lb-v2-identity", "fixture peer facts")
}
func (f *peerFixture) Alive(context.Context) error { return f.err }
func (f *peerFixture) Close() error                { f.err = &api.Error{Code: api.CodeUnauthenticated}; return nil }

type connectionFixture struct {
	raw       net.Conn
	id        api.ID
	binding   api.InstalledBinding
	peer      api.VerifiedPeer
	authority api.ReadAuthority
	err       error
}

func (f *connectionFixture) ID() api.ID                    { return f.id }
func (f *connectionFixture) Conn() net.Conn                { return f.raw }
func (f *connectionFixture) Binding() api.InstalledBinding { return f.binding }
func (f *connectionFixture) Peer() api.VerifiedPeer        { return f.peer }

// This fixture starts after authentication. Calling either binder would cross
// its validation-only boundary; it cannot manufacture native peer/proof facts.
func (f *connectionFixture) BindPeer(api.VerifiedPeer) error {
	return api.NotImplemented("lb-v2-identity", "fixture native peer binding")
}
func (f *connectionFixture) BindReadAuthority(api.ReadAuthority) error {
	return api.NotImplemented("lb-v2-identity", "fixture committed read binding")
}
func (f *connectionFixture) ReadAuthority(context.Context) (api.ReadAuthority, error) {
	return f.authority, f.err
}
func (f *connectionFixture) Close() error {
	f.err = &api.Error{Code: api.CodeUnauthenticated}
	return f.peer.Close()
}

type frameFixture struct {
	data       []byte
	connection api.ID
	err        error
}

func (f *frameFixture) Bytes() []byte { return append([]byte(nil), f.data...) }
func (f *frameFixture) Verify(_ context.Context, connection api.ConnectionContext) error {
	if f.err != nil {
		return f.err
	}
	if connection.ID() != f.connection {
		return &api.Error{Code: api.CodeUnauthenticated}
	}
	return nil
}

func framedScope(scope api.Scope) api.Scope {
	digest, err := api.RequestDigest(scope.Request)
	if err != nil {
		panic(err)
	}
	scope.Request.RequestSHA256 = digest
	data, err := json.Marshal(scope.Request)
	if err != nil {
		panic(err)
	}
	// Marshal compacts RawMessage; the dispatcher decodes its actual frame.
	if err := json.Unmarshal(data, &scope.Request); err != nil {
		panic(err)
	}
	scope.Frame = &frameFixture{data: data, connection: scope.Connection.ID()}
	return scope
}

func scopeFixture(method api.Method) api.Scope {
	requestID, err := client.NewRequestID()
	if err != nil {
		panic(err)
	}
	key, err := client.NewRequestID()
	if err != nil {
		panic(err)
	}
	now := time.Now().UTC()
	connection := &connectionFixture{id: "connection-a", peer: &peerFixture{},
		binding: api.InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision,
			Protocol: api.Protocol, APISchema: api.SchemaVersion, Config: "service-case", Class: api.EndpointHuman,
			InstallationGeneration: 1, EndpointGeneration: 1, ServiceUID: 1001, ServiceGID: 1001,
			Socket: "/run/laneboss-test/human.sock", ArtifactSHA256: digestFixture("fixture artifact"),
			ServiceVersion: release.Version, Backend: "linux-bwrap-landlock"},
		authority: api.ReadAuthority{ConnectionID: "connection-a", SessionID: "read-a", PrincipalID: "human-a", CredentialID: "credential-a",
			Config: "service-case", EndpointGeneration: 1,
			IdleExpiresAt: api.Timestamp(now.Add(4 * time.Minute).Format(time.RFC3339Nano)),
			ExpiresAt:     api.Timestamp(now.Add(29 * time.Minute).Format(time.RFC3339Nano))}}
	return framedScope(api.Scope{Config: "service-case", Actor: api.Actor{Kind: "human", ID: "human-a"},
		Connection: connection, EndpointGeneration: 1,
		Request: api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion,
			Config: "service-case", Method: method, Params: json.RawMessage(`{}`),
			RequestID: requestID, IdempotencyKey: key}})
}

func serviceFixture(t *testing.T) (*Service, *storeFixture, *humanFixture, *clockFixture) {
	t.Helper()
	clock := &clockFixture{now: time.Now().UTC()}
	store := &storeFixture{lane: api.Lane{LifeID: "life-a", Run: 1, State: "preparing",
		GrantSetID: "grants-a", PolicyGeneration: 1}, grants: api.GrantSet{
		ID: "grants-a", LifeID: "life-a", SHA256: digestFixture("fixture grants"),
		PolicyGeneration: 1, Generation: 1,
		ExpiresAt: api.Timestamp(clock.now.Add(time.Hour).Format(time.RFC3339Nano))}}
	store.policy = api.EffectivePolicy{Generation: 1, SHA256: digestFixture("fixture policy")}
	human := &humanFixture{}
	s, err := New(Dependencies{ProjectionIdentity: deniedProjection{}, Backend: &backendFixture{}, Store: store, Human: human,
		Clock: clock, Config: "service-case", Grants: &grantsFixture{},
		ServiceScope: api.Scope{Config: "service-case", Actor: api.Actor{Kind: "service", ID: "service-a"}}})
	if err != nil {
		t.Fatal("service fixture initialization failed")
	}
	return s, store, human, clock
}

func withInput(scope api.Scope, input any) api.Scope {
	data, err := json.Marshal(input)
	if err != nil {
		panic(err)
	}
	scope.Request.Params = data
	return framedScope(scope)
}

func TestKeyScopeAndExpiry(t *testing.T) {
	s, _, _, clock := serviceFixture(t)
	ctx := context.Background()
	scope := scopeFixture("secret.key")
	key, err := s.SecretKey(ctx, scope, api.Empty{})
	if err != nil || len(key.PublicKey) != 32 || key.Algorithm != StageAlgorithm || key.ID == "" {
		t.Fatal("ephemeral key issuance failed")
	}
	if expires, err := time.Parse(time.RFC3339Nano, string(key.ExpiresAt)); err != nil ||
		expires.Sub(clock.now) != 120*time.Second {
		t.Fatal("ephemeral key lifetime differs")
	}
	request, err := SealStage("service-case", key, "canary", "one", api.SecretMaterial{Bytes: []byte("synthetic material")})
	if err != nil {
		t.Fatal("issued public key cannot seal")
	}
	stageScope := scopeFixture("secret.stage")
	stageScope = withInput(stageScope, request)
	stageScope.Actor.ID = "human-b"
	stageScope.Connection.(*connectionFixture).authority.PrincipalID = "human-b"
	_, err = s.SecretStage(ctx, stageScope, request)
	stageCode(t, err, api.CodeNotFound)
	stageScope.Actor.ID = scope.Actor.ID
	stageScope.Connection = scope.Connection
	stageScope = framedScope(stageScope)
	staged, err := s.SecretStage(ctx, stageScope, request)
	if err != nil || staged.ID == "" || staged.Name != request.Name || staged.Version != request.Version {
		t.Fatal("valid encrypted stage was not retained")
	}
	clock.now = clock.now.Add(120 * time.Second)
	_, err = s.SecretStage(ctx, stageScope, request)
	stageCode(t, err, api.CodeNotFound)
	for i := 0; i < 4; i++ {
		if _, err := s.SecretKey(ctx, scope, api.Empty{}); err != nil {
			t.Fatal("bounded key issuance failed")
		}
	}
	_, err = s.SecretKey(ctx, scope, api.Empty{})
	stageCode(t, err, api.CodeBudget)
	scope.Actor.Kind = "lane"
	_, err = s.SecretKey(ctx, scope, api.Empty{})
	stageCode(t, err, api.CodeForbidden)
}

func TestRegisterStrictly(t *testing.T) {
	s, _, _, _ := serviceFixture(t)
	registry := &registryFixture{handlers: make(map[api.Method]api.Handler)}
	if err := s.Register(registry); err != nil || len(registry.handlers) != 6 {
		t.Fatal("secret RPC catalog registration differs")
	}
	for method := range registry.handlers {
		if spec, ok := api.Methods[method]; !ok || spec.Owner != "lb-v2-secrets" {
			t.Fatal("registered a method outside this module")
		}
	}
	result, err := registry.handlers["secret.key"](context.Background(), scopeFixture("secret.key"),
		json.RawMessage(`{"extra":"untrusted"}`))
	stageCode(t, err, api.CodeInvalid)
	if result != nil {
		t.Fatal("failed RPC returned a result")
	}
	failure := api.NotImplemented("lb-v2-service", "fixture registrar")
	registry.err = failure
	if err := s.Register(registry); err != failure {
		t.Fatal("registration swallowed a dependency error")
	}
}

func TestMutationStopsBeforeProof(t *testing.T) {
	s, _, human, _ := serviceFixture(t)
	scope := scopeFixture("secret.import")
	request := api.SecretImportRequest{Name: "canary", Version: "one", SealedUploadID: "stage-a"}
	scope = withInput(scope, request)
	_, err := s.SecretImport(context.Background(), scope, request)
	stageCode(t, err, api.CodeUnauthenticated)
	scope.Request.Proof = &api.ProofRef{ID: "proof-a", RequestSHA256: scope.Request.RequestSHA256,
		ExpiresAt: api.Timestamp(s.deps.Clock.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))}
	scope = framedScope(scope)
	got, err := s.SecretImport(context.Background(), scope, request)
	stageCode(t, err, api.CodeNotImplemented)
	if !reflect.DeepEqual(got, api.SecretInfo{}) || human.checked != 0 {
		t.Fatal("unsupported atomic import consumed authority or returned a result")
	}
	request.Name = "*"
	_, err = s.SecretImport(context.Background(), scope, request)
	stageCode(t, err, api.CodeInvalid)
}

func secretGrantFixture(clock *clockFixture) api.SecretGrant {
	return api.SecretGrant{ID: "secret-a", ParentGrantID: "parent-a", SourceHandle: "source-a",
		Name: "canary", Version: "one", Delivery: "env", Target: "TASK_TOKEN",
		ExpiresAt: api.Timestamp(clock.now.Add(time.Minute).Format(time.RFC3339Nano))}
}

func TestGrantSelection(t *testing.T) {
	s, store, _, clock := serviceFixture(t)
	grant := secretGrantFixture(clock)
	store.grants.Secrets = []api.SecretGrant{grant}
	target := api.LifeRef{LifeID: "life-a", Run: 1}
	_, err := s.Inject(context.Background(), target, []api.SecretGrant{grant})
	stageCode(t, err, api.CodeNotImplemented)
	wider := grant
	wider.SourceHandle = "undelegated-source"
	_, err = s.Inject(context.Background(), target, []api.SecretGrant{wider})
	stageCode(t, err, api.CodeForbidden)
	wider = grant
	wider.Delegate = true
	_, err = s.Inject(context.Background(), target, []api.SecretGrant{wider})
	stageCode(t, err, api.CodeForbidden)
	store.reads = 0
	for _, reserved := range []string{"HOME", "PATH", "LANEBOSS_BINDING", "LD_PRELOAD", "CODEX_HOME"} {
		bad := grant
		bad.Target = reserved
		_, err := s.Inject(context.Background(), target, []api.SecretGrant{bad})
		stageCode(t, err, api.CodeForbidden)
	}
	if store.reads != 0 {
		t.Fatal("reserved targets reached a state or secret dependency")
	}
	store.grants.Revoked = true
	_, err = s.Inject(context.Background(), target, []api.SecretGrant{grant})
	stageCode(t, err, api.CodeForbidden)
	store.grants.Revoked = false
	dependency := api.NotImplemented("lb-v2-grants", "fixture ancestry")
	s.deps.Grants = &grantsFixture{err: dependency}
	_, err = s.Inject(context.Background(), target, []api.SecretGrant{grant})
	if err != dependency {
		t.Fatal("grant resolver dependency failure was swallowed")
	}
}

func TestGrantCollisions(t *testing.T) {
	s, store, _, clock := serviceFixture(t)
	one := secretGrantFixture(clock)
	one.Delivery, one.Target = "file", "token"
	two := one
	two.ID, two.Target = "secret-b", "token/other"
	store.grants.Secrets = []api.SecretGrant{one, two}
	_, err := s.Inject(context.Background(), api.LifeRef{LifeID: "life-a", Run: 1}, []api.SecretGrant{one, two})
	stageCode(t, err, api.CodeInvalid)
	if store.reads != 0 {
		t.Fatal("overlapping file targets reached a dependency")
	}
}

func TestCleanupNeedsQuiescence(t *testing.T) {
	s, _, _, _ := serviceFixture(t)
	slot := api.CredentialSlot{ID: "slot-a", LeaseID: "lease-a", ProfileGrantID: "profile-grant", ProfileID: "profile-a"}
	target := api.LifeRef{LifeID: "life-a", Run: 1}
	zero, one, exit := uint64(0), uint64(1), 0
	observation := api.ProcessObservation{Handle: api.ProcessHandle{ID: "process-a", Target: target,
		ContainmentID: "containment-a", Generation: "generation-a"}, State: "exited", ExitCode: &exit}
	for _, survivors := range []*uint64{nil, &one} {
		observation.Survivors = survivors
		err := s.Release(context.Background(), slot, observation)
		stageCode(t, err, api.CodeContainmentUnknown)
	}
	observation.Survivors = &zero
	observation.State = "running"
	stageCode(t, s.Release(context.Background(), slot, observation), api.CodeContainmentUnknown)
	observation.State = "exited"
	stageCode(t, s.Release(context.Background(), slot, observation), api.CodePrerequisite)
	injection := api.Injection{Target: api.LifeRef{LifeID: "other-life", Run: 1}, SlotIDs: []api.ID{"slot-a"}}
	stageCode(t, s.RevokeInjection(context.Background(), injection, observation), api.CodeContainmentUnknown)
}

func TestMissingDepsFail(t *testing.T) {
	_, err := New(Dependencies{})
	stageCode(t, err, api.CodePrerequisite)
	s, _, _, _ := serviceFixture(t)
	var absent *clockFixture
	s.deps.Clock = absent
	_, err = New(s.deps)
	stageCode(t, err, api.CodePrerequisite)
	err = RunInternal(context.Background(), "service-case", []string{"arbitrary-command"})
	stageCode(t, err, api.CodeNotImplemented)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Owner != "lb-v2-secrets" {
		t.Fatal("internal worker did not identify the missing lease owner")
	}
}

func TestProfileSelection(t *testing.T) {
	s, store, _, clock := serviceFixture(t)
	grant := api.ProfileGrant{ID: "profile-grant", ProfileID: "login-a", Driver: api.DriverCodex,
		Provider: "provider-a", ExpiresAt: api.Timestamp(clock.now.Add(time.Minute).Format(time.RFC3339Nano))}
	store.grants.Profiles = []api.ProfileGrant{grant}
	target := api.LifeRef{LifeID: "life-a", Run: 1}
	_, err := s.Acquire(context.Background(), target, grant)
	stageCode(t, err, api.CodePrerequisite)
	for _, field := range []string{"id", "profile", "provider", "paid", "delegate", "expiry"} {
		t.Run(field, func(t *testing.T) {
			requested := grant
			switch field {
			case "id":
				requested.ID = "task-secret"
			case "profile":
				requested.ProfileID = "other-login"
			case "provider":
				requested.Provider = "other-provider"
			case "paid":
				requested.Paid = true
			case "delegate":
				requested.Delegate = true
			case "expiry":
				requested.ExpiresAt = api.Timestamp(clock.now.Add(time.Hour).Format(time.RFC3339Nano))
			}
			_, err := s.Acquire(context.Background(), target, requested)
			stageCode(t, err, api.CodeForbidden)
		})
	}
}

func TestProfileExpiryAndDriver(t *testing.T) {
	s, _, _, clock := serviceFixture(t)
	grant := api.ProfileGrant{ID: "profile-grant", ProfileID: "login-a", Driver: api.DriverCodex,
		Provider: "provider-a", ExpiresAt: api.Timestamp(clock.now.Add(-time.Minute).Format(time.RFC3339Nano))}
	_, err := s.Room(context.Background(), grant)
	stageCode(t, err, api.CodeForbidden)
	grant.ExpiresAt = api.Timestamp(clock.now.Add(time.Minute).Format(time.RFC3339Nano))
	grant.Driver = api.Driver("unknown-driver")
	_, err = s.Room(context.Background(), grant)
	stageCode(t, err, api.CodeUnsupported)
}

func TestReadConnectionGuards(t *testing.T) {
	for _, name := range []string{"absent", "closed", "writer", "frame", "endpoint", "session", "connection", "retained", "idle", "expiry"} {
		t.Run(name, func(t *testing.T) {
			s, _, _, clock := serviceFixture(t)
			scope := scopeFixture("secret.key")
			connection := scope.Connection.(*connectionFixture)
			switch name {
			case "absent":
				scope.Connection = nil
			case "closed":
				if err := connection.peer.Close(); err != nil {
					t.Fatal("fixture peer close failed")
				}
			case "writer":
				scope.Frame.(*frameFixture).err = &api.Error{Code: api.CodeUnauthenticated}
			case "frame":
				scope.Frame.(*frameFixture).data = []byte(`{}`)
			case "endpoint":
				connection.authority.EndpointGeneration++
			case "session":
				connection.authority.SessionID = ""
			case "connection":
				connection.authority.ConnectionID = "connection-b"
			case "retained":
				retained := connection.authority
				retained.SessionID = "read-b"
				scope.ReadAuthority = &retained
			case "idle":
				connection.authority.IdleExpiresAt = api.Timestamp(clock.now.Format(time.RFC3339Nano))
			case "expiry":
				connection.authority.ExpiresAt = api.Timestamp(clock.now.Format(time.RFC3339Nano))
				connection.authority.IdleExpiresAt = connection.authority.ExpiresAt
			}
			key, err := s.SecretKey(context.Background(), scope, api.Empty{})
			stageCode(t, err, api.CodeUnauthenticated)
			if !reflect.DeepEqual(key, api.SecretKey{}) {
				t.Fatal("invalid read connection returned a key")
			}
		})
	}
}

func TestStageReadSession(t *testing.T) {
	s, _, _, _ := serviceFixture(t)
	scope := scopeFixture("secret.key")
	key, err := s.SecretKey(context.Background(), scope, api.Empty{})
	if err != nil {
		t.Fatal("upload key prerequisite failed")
	}
	request, err := SealStage("service-case", key, "canary", "one", api.SecretMaterial{Bytes: []byte("synthetic material")})
	if err != nil {
		t.Fatal("sealed stage prerequisite failed")
	}
	stage := scope
	stage.Request.Method = "secret.stage"
	stage = withInput(stage, request)
	first, err := s.SecretStage(context.Background(), stage, request)
	if err != nil || first.ID == "" {
		t.Fatal("valid session stage failed")
	}
	connection := stage.Connection.(*connectionFixture)
	connection.id = "connection-b" // Same principal and session on a new connector.
	connection.authority.ConnectionID = connection.id
	stage = framedScope(stage)
	_, err = s.SecretStage(context.Background(), stage, request)
	stageCode(t, err, api.CodeNotFound)
	connection.id = "connection-a"
	connection.authority.ConnectionID = connection.id
	connection.authority.SessionID = "read-b"
	stage = framedScope(stage)
	_, err = s.SecretStage(context.Background(), stage, request)
	stageCode(t, err, api.CodeNotFound)
	connection.authority.SessionID = "read-a"
	stage = framedScope(stage)
	replayed, err := s.SecretStage(context.Background(), stage, request)
	if err != nil || replayed != first {
		t.Fatal("stage retry did not retain its exact receipt")
	}
}

func TestStageCommitFailure(t *testing.T) {
	s, ledger, _, _ := serviceFixture(t)
	scope := scopeFixture("secret.key")
	key, err := s.SecretKey(context.Background(), scope, api.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := SealStage(scope.Config, key, "commit.canary", "v1", api.SecretMaterial{Bytes: []byte("synthetic staging material")})
	if err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), sealed.Ciphertext...)
	scope.Request.Method = "secret.stage"
	scope = withInput(scope, sealed)
	sentinel := &api.Error{Code: api.CodeUnavailable, Message: "component stage commit unavailable"}
	ledger.stages.Failure = sentinel
	reply, err := s.SecretStage(context.Background(), scope, sealed)
	if !errors.Is(err, sentinel) || reply != (api.SecretStage{}) || len(s.stages) != 0 {
		t.Fatal("failed stage commit retained its allocation", err)
	}
	if !bytes.Equal(original, sealed.Ciphertext) {
		t.Fatal("failed stage publication cleared caller-owned ciphertext")
	}
	ledger.stages.Failure = nil
	if reply, err := s.SecretStage(context.Background(), scope, sealed); err != nil || reply.ID == "" {
		t.Fatal("original stage intent could not commit after its transient failure", err)
	}
}

type mismatchedStageRangeStore struct {
	*storeFixture
	halfEmpty bool
}

func (s *mismatchedStageRangeStore) CommitSecretStage(ctx context.Context, input api.Transaction, allocated api.SecretStage) (api.Commit, error) {
	commit, err := s.storeFixture.CommitSecretStage(ctx, input, allocated)
	if err != nil {
		return commit, err
	}
	if s.halfEmpty {
		commit.FirstSeq, commit.Operation.FirstSeq = 0, 0
	} else {
		commit.FirstSeq++
		commit.LastSeq++
	}
	return commit, nil
}

func TestStageCommitRangeBinding(t *testing.T) {
	for _, mode := range []string{"different-operation-range", "half-empty-range"} {
		t.Run(mode, func(t *testing.T) {
			s, ledger, _, _ := serviceFixture(t)
			s.deps.Store = &mismatchedStageRangeStore{storeFixture: ledger, halfEmpty: mode == "half-empty-range"}
			scope := scopeFixture("secret.key")
			key, err := s.SecretKey(context.Background(), scope, api.Empty{})
			if err != nil {
				t.Fatal(err)
			}
			sealed, err := SealStage(scope.Config, key, "commit.canary", "v1", api.SecretMaterial{Bytes: []byte("synthetic range material")})
			if err != nil {
				t.Fatal(err)
			}
			scope.Request.Method = "secret.stage"
			scope = withInput(scope, sealed)
			reply, err := s.SecretStage(context.Background(), scope, sealed)
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeIntegrity || typed.Message != "secret stage has no exact committed reply" ||
				reply != (api.SecretStage{}) || len(s.stages) != 0 {
				t.Fatal("stage accepted sequence range outside its committed operation", err)
			}
		})
	}
}

func TestKeyReadExpiryBound(t *testing.T) {
	s, _, _, clock := serviceFixture(t)
	scope := scopeFixture("secret.key")
	limit := clock.now.Add(30 * time.Second)
	scope.Connection.(*connectionFixture).authority.IdleExpiresAt = api.Timestamp(limit.Format(time.RFC3339Nano))
	key, err := s.SecretKey(context.Background(), scope, api.Empty{})
	if err != nil {
		t.Fatal("bounded read key prerequisite failed")
	}
	if key.ExpiresAt != api.Timestamp(limit.Format(time.RFC3339Nano)) {
		t.Fatal("upload key outlived its current read authority")
	}
}

func eligibilityFixture(store *storeFixture, clock *clockFixture) api.ProfileEligibilityRequest {
	from := api.ProfileGrant{ID: "profile-from", ProfileID: "login-a", Driver: api.DriverCodex,
		Provider: "provider-a", ExpiresAt: api.Timestamp(clock.now.Add(time.Minute).Format(time.RFC3339Nano))}
	to := from
	to.ID, to.ProfileID = "profile-to", "login-b"
	store.grants.Profiles = []api.ProfileGrant{from, to}
	store.policy = api.EffectivePolicy{Generation: 1, SHA256: digestFixture("fixture policy")}
	session := api.Session{ID: "session-a", Driver: api.DriverCodex, HistoryID: "history-a",
		HomeID: "home-a", VendorID: "vendor-session", VendorVersion: "test-version", LogicalCWD: "/work"}
	store.lane.Session, store.lane.Model, store.lane.ProfileGrantID = session, "fixture-model", from.ID
	return api.ProfileEligibilityRequest{Target: api.LifeRef{LifeID: "life-a", Run: 1},
		GrantSetID: store.grants.ID, FromGrantID: from.ID, ToGrantID: to.ID,
		Driver: api.DriverCodex, Model: store.lane.Model, Session: session, HistoryID: session.HistoryID}
}

func TestEligibilityCurrentState(t *testing.T) {
	s, store, _, clock := serviceFixture(t)
	request := eligibilityFixture(store, clock)
	output, err := s.Eligibility(context.Background(), request)
	stageCode(t, err, api.CodePrerequisite)
	if !reflect.DeepEqual(output, api.ProfileEligibility{}) {
		t.Fatal("missing eligibility evidence returned a result")
	}
	for _, name := range []string{"model", "session", "history", "grants", "from", "provider", "paid", "excluded"} {
		t.Run(name, func(t *testing.T) {
			s, store, _, clock := serviceFixture(t)
			request := eligibilityFixture(store, clock)
			code := api.CodeConflict
			switch name {
			case "model":
				request.Model = "another-model"
			case "session":
				request.Session.ID = "another-session"
			case "history":
				request.Session.HistoryID, request.HistoryID = "other-history", "other-history"
			case "grants":
				request.GrantSetID = "another-grants"
			case "from":
				request.FromGrantID = "another-profile"
			case "provider":
				store.grants.Profiles[1].Provider = "other-provider"
				code = api.CodeForbidden
			case "paid":
				store.grants.Profiles[1].Paid = true
				code = api.CodeForbidden
			case "excluded":
				store.policy.ProfileExclusions = []api.ID{"login-b"}
				code = api.CodeForbidden
			}
			_, err := s.Eligibility(context.Background(), request)
			stageCode(t, err, code)
		})
	}
}

func workerFixture(store *storeFixture, clock *clockFixture) (api.WorkerLease, []api.WorkerCredential) {
	grant := secretGrantFixture(clock)
	store.grants.Secrets = []api.SecretGrant{grant}
	ref := api.BlobRef{ID: "input-a", SHA256: digestFixture("fixture input"), Bytes: 1, Class: "content"}
	store.lease = api.WorkerLease{ID: "job-a", Kind: "channel", Target: api.LifeRef{LifeID: "life-a", Run: 1},
		OperationID: "operation-a", EffectID: "effect-a", Input: ref, RuntimeManifest: ref,
		GrantSetID: store.grants.ID, Generation: 1,
		ExpiresAt: api.Timestamp(clock.now.Add(time.Minute).Format(time.RFC3339Nano))}
	return store.lease, []api.WorkerCredential{{Name: grant.Name, Version: grant.Version,
		SourceHandle: grant.SourceHandle, Delivery: grant.Delivery, Target: grant.Target}}
}

func TestWorkerLeaseAndSubset(t *testing.T) {
	s, store, _, clock := serviceFixture(t)
	lease, credentials := workerFixture(store, clock)
	output, err := s.InjectWorker(context.Background(), lease, credentials)
	stageCode(t, err, api.CodeNotImplemented)
	if !reflect.DeepEqual(output, api.Injection{}) {
		t.Fatal("missing worker projection returned a result")
	}
	for _, name := range []string{"lease", "generation", "runtime", "expired", "consumed", "source", "target", "version", "reserved"} {
		t.Run(name, func(t *testing.T) {
			s, store, _, clock := serviceFixture(t)
			lease, credentials := workerFixture(store, clock)
			code := api.CodeConflict
			switch name {
			case "lease":
				lease.EffectID = "other-effect"
			case "generation":
				lease.Generation++
			case "runtime":
				lease.RuntimeManifest.SHA256 = digestFixture("other runtime")
			case "expired":
				lease.ExpiresAt = api.Timestamp(clock.now.Format(time.RFC3339Nano))
				code = api.CodeForbidden
			case "consumed":
				lease.ConsumedBy = "other-operation"
				code = api.CodeForbidden
			case "source":
				credentials[0].SourceHandle = "other-source"
				code = api.CodeForbidden
			case "target":
				credentials[0].Target = "OTHER_TOKEN"
				code = api.CodeForbidden
			case "version":
				credentials[0].Version = "other-version"
				code = api.CodeForbidden
			case "reserved":
				credentials[0].Target = "HOME"
				code = api.CodeForbidden
			}
			_, err := s.InjectWorker(context.Background(), lease, credentials)
			stageCode(t, err, code)
		})
	}
	dependency := api.NotImplemented("lb-v2-service", "fixture worker lease")
	store.err = dependency
	_, err = s.InjectWorker(context.Background(), lease, credentials)
	if err != dependency {
		t.Fatal("worker lease dependency failure was swallowed")
	}
}
