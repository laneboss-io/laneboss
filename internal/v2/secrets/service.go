// Package secrets implements protected staging and secret administration.
package secrets

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"reflect"
	"sync"
	"time"

	release "laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

type Dependencies struct {
	Backend api.SecretBackend
	Store   api.StateStore
	Human   api.HumanVerifier
	Clock   api.Clock
	// Config and ServiceScope are installed service inputs, never RPC fields.
	Config           string
	ServiceScope     api.Scope
	Grants           api.GrantResolver
	Helper           api.HelperControl
	CleanupNative    api.PlanCleanupNativeReader
	WithdrawalNative api.CredentialWithdrawalReader
	Control          api.LaunchControlSource
	UsageJobs        UsageJobControl
	Bootstrap        api.WorkerBootstrap
	// ProjectionIdentity authenticates the installed private broker/helper
	// channel. A serialized peer label cannot supply this mandatory port.
	ProjectionIdentity api.CredentialProjectionIdentity
	// The outside broker host installs these runner-owned validators. Missing
	// selected-mode validation refuses projection; there is no schema fallback.
	CodexValidator    CodexCredentialValidator
	HeadlessValidator HeadlessCredentialValidator
	APIKeyValidator   APIKeyCredentialValidator
}

type uploadKey struct {
	private    *ecdh.PrivateKey
	actor      api.ID
	connection api.ID
	session    api.ID
	endpoint   api.Generation
	public     api.SecretKey
	expires    time.Time
}

type Service struct {
	deps         Dependencies
	mu           sync.Mutex
	cleanupMu    sync.Mutex
	keys         map[api.ID]uploadKey
	stages       map[api.ID]sealedStage
	projectionMu sync.Mutex
	projections  map[api.ID]*projectionFlight
}

// Identity has not published read-window constants in api. These maximum
// remaining windows are pinned here and in CONTRACTS.md until it does.
const readIdleLimit = 5 * time.Minute
const readAbsoluteLimit = 30 * time.Minute
const stageLifetime = 120 * time.Second

func New(deps Dependencies) (*Service, error) {
	if wire.Nil(deps.Backend) || wire.Nil(deps.Store) || wire.Nil(deps.Human) || wire.Nil(deps.Clock) {
		return nil, wire.Error(api.CodePrerequisite, "secrets requires backend, store, human verifier and clock")
	}
	if wire.Nil(deps.ProjectionIdentity) {
		return nil, wire.Error(api.CodePrerequisite, "secrets requires its installed credential projection identity")
	}
	if !wire.ID(deps.Config) {
		return nil, wire.Error(api.CodePrerequisite, "secrets requires its installed configuration")
	}
	if deps.ServiceScope.Config == "" {
		deps.ServiceScope = api.Scope{Config: deps.Config, Actor: api.Actor{Kind: "service", ID: "secrets"}}
	}
	if deps.ServiceScope.Config != "" && (deps.ServiceScope.Config != deps.Config ||
		deps.ServiceScope.Actor.Kind != "service" || !wire.ID(string(deps.ServiceScope.Actor.ID))) {
		return nil, wire.Error(api.CodeInvalid, "credential worker service scope is inconsistent")
	}
	return &Service{deps: deps, keys: make(map[api.ID]uploadKey), stages: make(map[api.ID]sealedStage), projections: make(map[api.ID]*projectionFlight)}, nil
}

var _ api.SecretsAPI = (*Service)(nil)
var _ api.Module = (*Service)(nil)
var _ api.CredentialBroker = (*Service)(nil)

func register[I, O any](registry api.Registrar, method api.Method,
	fn func(context.Context, api.Scope, I) (O, error)) error {
	return registry.Register(method, func(ctx context.Context, scope api.Scope, raw json.RawMessage) (json.RawMessage, error) {
		var input I
		if err := wire.Decode(raw, &input, api.MaxFrameBytes); err != nil {
			return nil, err
		}
		output, err := fn(ctx, scope, input)
		if err != nil {
			return nil, err
		}
		encoded, err := json.Marshal(output)
		if err != nil {
			return nil, wire.Error(api.CodeIntegrity, "cannot encode secret response")
		}
		return encoded, nil
	})
}

func (s *Service) Register(registry api.Registrar) error {
	if wire.Nil(registry) {
		return wire.Error(api.CodeInvalid, "secret RPC registrar is required")
	}
	registrations := []func() error{
		func() error { return register(registry, "secret.key", s.SecretKey) },
		func() error { return register(registry, "secret.stage", s.SecretStage) },
		func() error { return register(registry, "secret.import", s.SecretImport) },
		func() error { return register(registry, "secret.rotate", s.SecretRotate) },
		func() error { return register(registry, "secret.revoke", s.SecretRevoke) },
		func() error { return register(registry, "secret.list", s.SecretList) },
	}
	for _, registration := range registrations {
		if err := registration(); err != nil {
			return err
		}
	}
	return nil
}

// The transport owns these handles. Serialized actor/session labels cannot
// substitute for a live connector and every-fragment writer verification.
func (s *Service) transport(ctx context.Context, scope api.Scope, method api.Method, class api.EndpointClass) error {
	if err := wire.Context(ctx); err != nil {
		return err
	}
	if scope.Config != s.deps.Config || scope.Request.Config != scope.Config ||
		scope.Request.Method != method || scope.Request.Protocol != api.Protocol ||
		scope.Request.Schema != api.SchemaVersion || !wire.Digest(scope.Request.RequestSHA256) ||
		!wire.ID(string(scope.Request.RequestID)) || !wire.ID(string(scope.Request.IdempotencyKey)) {
		return wire.Error(api.CodeUnauthenticated, "secret request lacks authenticated dispatcher metadata")
	}
	if wire.Nil(scope.Connection) || wire.Nil(scope.Frame) || !wire.ID(string(scope.Connection.ID())) {
		return wire.Error(api.CodeUnauthenticated, "secret request requires a live transport connection and frame")
	}
	binding := scope.Connection.Binding()
	if err := api.ValidateBinding(binding, s.deps.Config, release.Version); err != nil {
		return err
	}
	if binding.Class != class || binding.EndpointGeneration != scope.EndpointGeneration {
		return wire.Error(api.CodeUnauthenticated, "secret request differs from its installed endpoint")
	}
	peer := scope.Connection.Peer()
	if wire.Nil(peer) {
		return wire.Error(api.CodeUnauthenticated, "secret request has no verified connector lifetime")
	}
	if err := peer.Alive(ctx); err != nil {
		return err
	}
	if err := scope.Frame.Verify(ctx, scope.Connection); err != nil {
		return err
	}
	var framed api.Request
	if err := api.DecodeObject(scope.Frame.Bytes(), &framed); err != nil || !reflect.DeepEqual(framed, scope.Request) {
		return wire.Error(api.CodeUnauthenticated, "secret scope differs from the authenticated request frame")
	}
	digest, err := api.RequestDigest(scope.Request)
	if err != nil || digest != scope.Request.RequestSHA256 {
		return wire.Error(api.CodeUnauthenticated, "secret request intent digest differs from its frame")
	}
	return nil
}

// A proof may cross genuine human connections; browsing authority cannot.
// Mutation proofs are checked before backend work and consumed with the event
// and exact typed reply in the StateStore transaction.
func (s *Service) human(ctx context.Context, scope api.Scope, method api.Method, proof bool) (api.ReadAuthority, error) {
	if err := s.transport(ctx, scope, method, api.EndpointHuman); err != nil {
		return api.ReadAuthority{}, err
	}
	if scope.Actor.Kind != "human" || !wire.ID(string(scope.Actor.ID)) || scope.LaunchID != "" {
		return api.ReadAuthority{}, wire.Error(api.CodeForbidden, "secret administration requires verified human authority")
	}
	if proof && scope.Request.Proof == nil {
		return api.ReadAuthority{}, wire.Error(api.CodeUnauthenticated, "secret mutation requires an operation-bound human proof")
	}
	if proof {
		p := scope.Request.Proof // The missing-proof guard above owns the typed refusal.
		if p != nil && (!wire.ID(string(p.ID)) || p.RequestSHA256 != scope.Request.RequestSHA256 ||
			!future(p.ExpiresAt, s.deps.Clock.Now())) {
			return api.ReadAuthority{}, wire.Error(api.CodeForbidden, "secret proof differs from the request intent or has expired")
		}
		return api.ReadAuthority{}, nil
	}
	if scope.Request.Proof != nil {
		return api.ReadAuthority{}, wire.Error(api.CodeInvalid, "secret read and staging requests cannot carry an operation proof")
	}
	return s.readAuthority(ctx, scope)
}

func (s *Service) readAuthority(ctx context.Context, scope api.Scope) (api.ReadAuthority, error) {
	authority, err := scope.Connection.ReadAuthority(ctx)
	if err != nil {
		return api.ReadAuthority{}, err
	}
	now := s.deps.Clock.Now()
	idle, idleErr := time.Parse(time.RFC3339Nano, string(authority.IdleExpiresAt))
	expires, expiryErr := time.Parse(time.RFC3339Nano, string(authority.ExpiresAt))
	if !wire.ID(string(authority.SessionID)) || !wire.ID(string(authority.CredentialID)) ||
		!wire.ID(string(authority.ConnectionID)) || authority.ConnectionID != scope.Connection.ID() ||
		(scope.ReadAuthority != nil && *scope.ReadAuthority != authority) ||
		authority.PrincipalID != scope.Actor.ID || authority.Config != scope.Config ||
		authority.EndpointGeneration != scope.EndpointGeneration ||
		!future(authority.IdleExpiresAt, now) || !future(authority.ExpiresAt, now) ||
		idleErr != nil || expiryErr != nil || idle.After(expires) ||
		idle.After(now.Add(readIdleLimit)) || expires.After(now.Add(readAbsoluteLimit)) {
		return api.ReadAuthority{}, wire.Error(api.CodeUnauthenticated, "secret read authority is absent, expired or outside this connection scope")
	}
	return authority, nil
}

func (s *Service) expireKeys(now time.Time) {
	for id, key := range s.keys {
		if !now.Before(key.expires) {
			delete(s.keys, id)
		}
	}
	for id, stage := range s.stages {
		if !now.Before(stage.key.expires) {
			clear(stage.request.Ciphertext)
			delete(s.stages, id)
		}
	}
}

func (s *Service) SecretKey(ctx context.Context, scope api.Scope, request api.Empty) (api.SecretKey, error) {
	authority, err := s.human(ctx, scope, "secret.key", false)
	if err != nil {
		return api.SecretKey{}, err
	}
	if err := requestMatches(scope, request); err != nil {
		return api.SecretKey{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.deps.Clock.Now()
	s.expireKeys(now)
	count := 0
	for _, key := range s.keys {
		if key.actor == scope.Actor.ID {
			count++
		}
	}
	if count >= 4 || len(s.keys) >= 128 {
		return api.SecretKey{}, wire.Error(api.CodeBudget, "too many unexpired secret upload keys")
	}
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return api.SecretKey{}, wire.Error(api.CodeUnavailable, "protected upload randomness is unavailable")
	}
	id, err := wire.RandomID()
	if err != nil {
		return api.SecretKey{}, err
	}
	expires := now.Add(stageLifetime)
	for _, bound := range []api.Timestamp{authority.IdleExpiresAt, authority.ExpiresAt} {
		limit, _ := time.Parse(time.RFC3339Nano, string(bound)) // validated by human
		if limit.Before(expires) {
			expires = limit
		}
	}
	public := api.SecretKey{ID: id, Algorithm: StageAlgorithm, PublicKey: private.PublicKey().Bytes(),
		ExpiresAt: api.Timestamp(expires.UTC().Format(time.RFC3339Nano))}
	s.keys[id] = uploadKey{private: private, actor: scope.Actor.ID, public: public,
		connection: scope.Connection.ID(), session: authority.SessionID,
		endpoint: scope.EndpointGeneration, expires: expires}
	// Return a distinct byte slice: an in-process caller cannot mutate stored keys.
	public.PublicKey = append([]byte(nil), public.PublicKey...)
	return public, nil
}

func (s *Service) SecretStage(ctx context.Context, scope api.Scope, request api.SecretStageRequest) (api.SecretStage, error) {
	authority, err := s.human(ctx, scope, "secret.stage", false)
	if err != nil {
		return api.SecretStage{}, err
	}
	if err := ValidateStageInput(request); err != nil {
		return api.SecretStage{}, err
	}
	if err := requestMatches(scope, request); err != nil {
		return api.SecretStage{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireKeys(s.deps.Clock.Now())
	key, ok := s.keys[request.KeyID]
	if !ok || key.actor != scope.Actor.ID {
		return api.SecretStage{}, wire.Error(api.CodeNotFound, "upload key is absent for this human principal")
	}
	if key.connection != scope.Connection.ID() || key.session != authority.SessionID || key.endpoint != scope.EndpointGeneration {
		return api.SecretStage{}, wire.Error(api.CodeNotFound, "upload key is absent for this live human read session")
	}
	id := secretID(scope, "stage")
	if prior, ok := s.stages[id]; ok {
		if prior.digest != scope.Request.RequestSHA256 {
			return api.SecretStage{}, wire.Error(api.CodeIdempotencyConflict, "stage retry key belongs to a different intent")
		}
		return s.finishStage(ctx, scope, authority, prior.receipt)
	}
	if len(s.stages) >= 128 {
		return api.SecretStage{}, wire.Error(api.CodeBudget, "too many unexpired encrypted stages")
	}
	actorStages := 0
	for _, stage := range s.stages {
		if stage.key.actor == scope.Actor.ID {
			actorStages++
		}
	}
	if actorStages >= 8 {
		return api.SecretStage{}, wire.Error(api.CodeBudget, "too many unexpired encrypted stages for this principal")
	}
	request.EphemeralPublicKey = append([]byte(nil), request.EphemeralPublicKey...)
	request.Nonce = append([]byte(nil), request.Nonce...)
	request.Ciphertext = append([]byte(nil), request.Ciphertext...)
	receipt := api.SecretStage{ID: id, Name: request.Name, Version: request.Version,
		ExpiresAt: api.Timestamp(key.expires.UTC().Format(time.RFC3339Nano))}
	s.stages[id] = sealedStage{key: key, request: request, receipt: receipt, digest: scope.Request.RequestSHA256}
	return s.finishStage(ctx, scope, authority, receipt)
}

func (s *Service) SecretImport(ctx context.Context, scope api.Scope, request api.SecretImportRequest) (api.SecretInfo, error) {
	if _, err := s.human(ctx, scope, "secret.import", true); err != nil {
		return api.SecretInfo{}, err
	}
	if err := ValidateImportInput(request); err != nil {
		return api.SecretInfo{}, err
	}
	if err := requestMatches(scope, request); err != nil {
		return api.SecretInfo{}, err
	}
	return s.importSecret(ctx, scope, request.Name, request.Version, "", request.SealedUploadID)
}

func (s *Service) SecretRotate(ctx context.Context, scope api.Scope, request api.SecretRotateRequest) (api.SecretInfo, error) {
	if _, err := s.human(ctx, scope, "secret.rotate", true); err != nil {
		return api.SecretInfo{}, err
	}
	if err := ValidateRotateInput(request); err != nil {
		return api.SecretInfo{}, err
	}
	if err := requestMatches(scope, request); err != nil {
		return api.SecretInfo{}, err
	}
	return s.importSecret(ctx, scope, request.Name, "", request.ExpectedVersion, request.SealedUploadID)
}

func (s *Service) SecretRevoke(ctx context.Context, scope api.Scope, request api.SecretRevokeRequest) (api.Operation, error) {
	if _, err := s.human(ctx, scope, "secret.revoke", true); err != nil {
		return api.Operation{}, err
	}
	if err := ValidateRevokeInput(request); err != nil {
		return api.Operation{}, err
	}
	if err := requestMatches(scope, request); err != nil {
		return api.Operation{}, err
	}
	return s.revokeSecret(ctx, scope, request)
}

func (s *Service) SecretList(ctx context.Context, scope api.Scope, request api.Empty) (api.SecretList, error) {
	if err := wire.Context(ctx); err != nil {
		return api.SecretList{}, err
	}
	if scope.Request.Proof != nil {
		return api.SecretList{}, wire.Error(api.CodeInvalid, "secret list cannot carry an operation proof")
	}
	if err := requestMatches(scope, request); err != nil {
		return api.SecretList{}, err
	}
	if scope.Actor.Kind == "human" {
		if _, err := s.human(ctx, scope, "secret.list", false); err != nil {
			return api.SecretList{}, err
		}
	} else if scope.Config != s.deps.Config || scope.Actor.Kind != "lane" ||
		!wire.ID(string(scope.Actor.LifeID)) || !wire.ID(string(scope.LaunchID)) {
		return api.SecretList{}, wire.Error(api.CodeForbidden, "secret list requires authenticated object visibility")
	} else {
		if err := s.transport(ctx, scope, "secret.list", api.EndpointLane); err != nil {
			return api.SecretList{}, err
		}
		binding := scope.Connection.Binding()
		if binding.LaunchID != scope.LaunchID || binding.Target.LifeID != scope.Actor.LifeID {
			return api.SecretList{}, wire.Error(api.CodeForbidden, "secret list differs from its exact installed life")
		}
	}
	return s.listMetadata(ctx, scope)
}
