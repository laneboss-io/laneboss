// Package identity owns identity derivation and operation-bound human proof.
// Missing trusted inputs are explicit failures, never UID/label fallbacks.
package identity

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type Dependencies struct {
	Peers       api.PeerVerifier
	Registry    api.ContainmentRegistry
	Store       api.StateStore
	Clock       api.Clock
	Attestation AttestationPolicy
	Sessions    SessionReadback
	Workers     WorkerLaunchSource
}

type Service struct {
	deps          Dependencies
	connectionMu  sync.RWMutex
	connections   api.ConnectionInvalidator
	invalidations map[api.ID]api.TransportInvalidationReceipt
	readLocks     [64]sync.Mutex
	attestation   attestationTrust
}

func New(deps Dependencies) (*Service, error) {
	if nilDependency(deps.Peers) || nilDependency(deps.Registry) || nilDependency(deps.Store) || nilDependency(deps.Clock) {
		return nil, refusal(api.CodePrerequisite, "identity dependencies are required")
	}
	trust, err := freezeAttestation(deps.Attestation)
	if err != nil {
		return nil, err
	}
	deps.Attestation = cloneAttestationPolicy(deps.Attestation)
	return &Service{deps: deps, attestation: trust}, nil
}

func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	valueOf := reflect.ValueOf(value)
	switch valueOf.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return valueOf.IsNil()
	default:
		return false
	}
}

var _ api.IdentityAPI = (*Service)(nil)
var _ api.Authenticator = (*Service)(nil)
var _ api.ConnectionScopeSource = (*Service)(nil)
var _ api.HumanVerifier = (*Service)(nil)
var _ api.Module = (*Service)(nil)

func (s *Service) Register(registry api.Registrar) error {
	if registry == nil {
		return refusal(api.CodePrerequisite, "identity registrar is required")
	}
	methods := []struct {
		method api.Method
		call   api.Handler
	}{
		{"identity.self", handler(s.IdentitySelf)},
		{"human.challenge", handler(s.HumanChallenge)},
		{"human.confirm", handler(s.HumanConfirm)},
		{"human.session", handler(s.HumanSession)},
		{"human.enroll", handler(s.HumanEnroll)},
		{"human.pending", handler(s.HumanPending)},
		{"ticket.issue", handler(s.TicketIssue)},
	}
	for _, method := range methods {
		checked := func(ctx context.Context, scope api.Scope, raw json.RawMessage) (json.RawMessage, error) {
			if err := ValidateInput(method.method, raw); err != nil {
				return nil, err
			}
			return method.call(ctx, scope, raw)
		}
		if err := registry.Register(method.method, checked); err != nil {
			return err
		}
	}
	return nil
}

func handler[Input, Output any](call func(context.Context, api.Scope, Input) (Output, error)) api.Handler {
	return func(ctx context.Context, scope api.Scope, raw json.RawMessage) (json.RawMessage, error) {
		var input Input
		if err := strictObject(raw, &input); err != nil {
			return nil, err
		}
		output, err := call(ctx, scope, input)
		if err != nil {
			return nil, err
		}
		return json.Marshal(output)
	}
}

// IdentitySelf returns a projection of the durable launch after the dispatcher
// has authenticated this exact connection. Source/Request never escape.
func (s *Service) IdentitySelf(ctx context.Context, scope api.Scope, _ api.Empty) (api.Scope, error) {
	if scope.Actor.Kind == "human" {
		if err := s.verifyScope(ctx, scope); err != nil {
			return api.Scope{}, err
		}
		if err := s.checkReadSession(ctx, scope); err != nil {
			return api.Scope{}, err
		}
		return api.Scope{Config: scope.Config, Actor: scope.Actor, EndpointGeneration: scope.EndpointGeneration,
			PolicyGeneration: scope.PolicyGeneration}, nil
	}
	record, err := s.currentLaunch(ctx, scope)
	if err != nil {
		return api.Scope{}, err
	}
	policy, err := s.deps.Store.Policy(ctx, scope)
	if err != nil {
		return api.Scope{}, err
	}
	if policy.Generation == 0 || policy.Generation != scope.PolicyGeneration {
		return api.Scope{}, refusal(api.CodeConflict, "identity projection requires the current policy scope")
	}
	return api.Scope{Config: record.Config, Actor: record.Actor, LaunchID: record.ID,
		EndpointGeneration: record.EndpointGeneration,
		PolicyGeneration:   scope.PolicyGeneration}, nil
}

func (s *Service) currentLaunch(ctx context.Context, scope api.Scope) (api.LaunchRecord, error) {
	var empty api.LaunchRecord
	if !validID(scope.LaunchID) || scope.Config == "" || scope.Actor.Kind != "lane" {
		return empty, refusal(api.CodeUnauthenticated, "a verified current launch is required")
	}
	record, err := s.deps.Store.Launch(ctx, scope.LaunchID)
	if err != nil {
		return empty, err
	}
	if record.Revoked || record.Kind != "agent" || record.ID != scope.LaunchID || record.Config != scope.Config ||
		record.Actor != scope.Actor || record.EndpointGeneration != scope.EndpointGeneration ||
		record.PolicyGeneration == 0 || record.PolicyGeneration > scope.PolicyGeneration {
		return empty, refusal(api.CodeUnauthenticated, "launch authority is stale or revoked")
	}
	lane, err := s.deps.Store.Lane(ctx, scope, record.Target)
	if err != nil {
		return empty, err
	}
	if lane.Cleaned || lane.LaunchID != record.ID || lane.LifeID != record.Target.LifeID || lane.Run != record.Target.Run ||
		lane.Level != record.Actor.Level || lane.Role != record.Actor.Role ||
		lane.GrantSetID != record.GrantSetID || lane.PolicyGeneration < record.PolicyGeneration || lane.PolicyGeneration > scope.PolicyGeneration ||
		lane.ParentLifeID != record.ParentLifeID || lane.RootLifeID != record.RootLifeID ||
		lane.StarterEventSeq != record.StarterEventSeq || !reflect.DeepEqual(lane.StarterChain, record.StarterChain) {
		return empty, refusal(api.CodeUnauthenticated, "launch no longer matches the current life")
	}
	return record, nil
}

func (s *Service) Authenticate(ctx context.Context, connection api.ConnectionContext) (_ api.Scope, resultErr error) {
	if nilDependency(connection) {
		return api.Scope{}, refusal(api.CodePrerequisite, "transport connection context is required")
	}
	// Draft.4's order has no identity/containment callback cycle: native
	// verification uses only this raw socket and its protected endpoint binding.
	// A newly acquired peer belongs here until BindPeer succeeds. Transport owns
	// it thereafter; every authentication failure closes the connection.
	var acquired api.VerifiedPeer
	defer func() {
		if resultErr != nil {
			if !nilDependency(acquired) {
				resultErr = errors.Join(resultErr, acquired.Close())
			}
			resultErr = errors.Join(resultErr, connection.Close())
		}
	}()
	if !validID(connection.ID()) || nilDependency(connection.Conn()) {
		return api.Scope{}, refusal(api.CodeUnauthenticated, "transport socket and connection identity are required")
	}
	if !nilDependency(connection.Peer()) {
		return api.Scope{}, refusal(api.CodeConflict, "connection peer is already bound")
	}
	binding := connection.Binding()
	if err := api.ValidateBinding(binding, binding.Config, binding.ServiceVersion); err != nil {
		return api.Scope{}, err
	}
	peer, err := s.deps.Peers.Verify(ctx, connection.Conn(), binding)
	acquired = peer
	if err != nil {
		return api.Scope{}, err
	}
	if nilDependency(peer) {
		return api.Scope{}, refusal(api.CodeIntegrity, "peer verifier returned no lifetime handle")
	}
	if !reflect.TypeOf(peer).Comparable() {
		return api.Scope{}, refusal(api.CodeIntegrity, "peer lifetime handle has no stable identity")
	}
	if err := connection.BindPeer(peer); err != nil {
		return api.Scope{}, err
	}
	if connection.Peer() != peer {
		return api.Scope{}, refusal(api.CodeIntegrity, "transport did not retain the verified peer")
	}
	acquired = nil
	return s.connectionScope(ctx, connection)
}

// CurrentConnectionScope revalidates an already pinned lifetime and current
// durable authority. It neither calls Verify nor replaces the original peer.
func (s *Service) CurrentConnectionScope(ctx context.Context, connection api.ConnectionContext) (scope api.Scope, resultErr error) {
	if nilDependency(connection) {
		return scope, refusal(api.CodeUnauthenticated, "current connection requires its original verified peer")
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, connection.Close())
		}
	}()
	if nilDependency(connection.Peer()) {
		return scope, refusal(api.CodeUnauthenticated, "current connection requires its original verified peer")
	}
	return s.connectionScope(ctx, connection)
}

func (s *Service) Authorize(ctx context.Context, scope api.Scope, request api.Request) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if request.Protocol != api.Protocol || request.Schema != api.SchemaVersion {
		return refusal(api.CodeVersion, "unsupported identity protocol or schema")
	}
	if request.Config == "" || scope.Config != request.Config {
		return refusal(api.CodeForbidden, "request configuration differs from the bound scope")
	}
	if scope.Actor.Kind == "worker" {
		return s.authorizeWorker(ctx, scope, request)
	}
	spec, exists := api.Methods[request.Method]
	if !exists {
		return refusal(api.CodeInvalid, "unknown identity operation")
	}
	if scope.Actor.Kind == "lane" {
		if request.Proof != nil || spec.Access == "human-proof" ||
			spec.Access == "human-read" || spec.Access == "human-endpoint" {
			return refusal(api.CodeForbidden, "lane endpoints cannot use human authority")
		}
	}
	if request.Method == "lane.start" || request.Method == "lane.adopt" || spec.Access == "l6" {
		if err := s.authorizeClaims(ctx, scope, request); err != nil {
			return err
		}
	}
	if scope.Actor.Kind == "lane" {
		if _, err := s.currentLaunch(ctx, scope); err != nil {
			return err
		}
	} else {
		if scope.Actor.Kind != "human" {
			return refusal(api.CodeUnauthenticated, "no authenticated principal")
		}
		if (!spec.Mutation || api.HumanSessionMethod(request.Method) || spec.Access == "human-endpoint" ||
			spec.Access == "human-read" || spec.Access == "spawn") && request.Proof != nil {
			return refusal(api.CodeForbidden, "operation does not accept an envelope proof")
		}
		if spec.Mutation && !api.HumanSessionMethod(request.Method) && spec.Access != "human-endpoint" && spec.Access != "human-read" && spec.Access != "spawn" && request.Proof == nil {
			return refusal(api.CodeUnauthenticated, "fresh operation-bound human proof is required")
		}
	}
	if err := s.verifyScope(ctx, scope); err != nil {
		return err
	}
	if nilDependency(scope.Frame) {
		return gap("Authorize", "credential-verified request frame")
	}
	if err := scope.Frame.Verify(ctx, scope.Connection); err != nil {
		return err
	}
	var framed api.Request
	if err := api.DecodeObject(scope.Frame.Bytes(), &framed); err != nil {
		return err
	}
	if !reflect.DeepEqual(framed, request) {
		return refusal(api.CodeIntegrity, "request differs from the verified frame")
	}
	digest, err := api.RequestDigest(request)
	if err != nil || request.RequestSHA256 != digest || !validID(request.RequestID) ||
		len(request.RequestID) < 22 || !validID(request.IdempotencyKey) || len(request.IdempotencyKey) < 22 {
		return refusal(api.CodeInvalid, "request metadata or intent digest is invalid")
	}
	if err := s.authorizeClaims(ctx, scope, request); err != nil {
		return err
	}
	if scope.Actor.Kind == "human" {
		// A root ticket authorizes only its eventual guarded launch. The CLI
		// first establishes a separate same-socket read session for preflight.
		if spec.Access == "spawn" {
			return s.refreshReadSession(ctx, scope)
		}
		if api.HumanSessionMethod(request.Method) || spec.Access == "human-read" || !spec.Mutation && spec.Access != "public" {
			return s.refreshReadSession(ctx, scope)
		}
		// The dispatcher checks receipts before module preflight. Proof use is
		// deliberately deferred to Transact, where it is atomic with the write.
	}
	return nil
}

func (s *Service) BindLaunch(ctx context.Context, request api.LaunchBindingRequest) (api.LaunchPermit, error) {
	record := request.Record
	worker := record.Kind == "worker" || record.Actor.Kind == "worker"
	if !worker {
		if err := validateLaunch(record); err != nil {
			return api.LaunchPermit{}, err
		}
	} else if !validID(record.ID) || record.Kind != "worker" || record.Actor.Kind != "worker" {
		return api.LaunchPermit{}, refusal(api.CodeInvalid, "incomplete worker launch selector")
	}
	if err := validateBindingRequest(request); err != nil {
		return api.LaunchPermit{}, err
	}
	durable, err := s.deps.Store.LaunchBinding(ctx, record.ID)
	if err != nil {
		return api.LaunchPermit{}, err
	}
	if durable.Record.Kind == "worker" && durable.Record.Actor.Kind == "worker" {
		return s.bindWorkerLaunch(ctx, request, durable)
	}
	if worker {
		return api.LaunchPermit{}, refusal(api.CodeInvalid, "worker selector does not name a retained worker launch")
	}
	plan, serviceScope, err := s.retainedLaunchPlan(ctx, durable)
	if err != nil {
		return api.LaunchPermit{}, err
	}
	if !reflect.DeepEqual(durable.Recovery, request.Recovery) {
		return api.LaunchPermit{}, refusal(api.CodeConflict, "launch differs from its retained recovery inputs")
	}
	if durable.Identity.LaunchID != record.ID || durable.Identity.EventID != request.Identity.EventID ||
		durable.Identity.RecordSHA256 != request.Identity.RecordSHA256 ||
		durable.Identity.CommittedSeq != request.Identity.CommittedSeq {
		return api.LaunchPermit{}, refusal(api.CodeConflict, "launch differs from its committed identity receipt")
	}
	if !reflect.DeepEqual(durable.Record, record) || durable.Prepared != request.Prepared {
		return api.LaunchPermit{}, refusal(api.CodeConflict, "launch differs from its committed record")
	}
	if err := s.checkIdentityEvent(ctx, serviceScope, durable); err != nil {
		return api.LaunchPermit{}, err
	}
	scope := api.Scope{Config: record.Config, Actor: record.Actor, LaunchID: record.ID,
		EndpointGeneration: record.EndpointGeneration}
	// A new permit uses current authorization, even if the coordinator already
	// advanced the live projection. The sealed plan keeps its original bytes and
	// must still match current policy at the final authority check below.
	policy, err := s.deps.Store.Policy(ctx, scope)
	if err != nil {
		return api.LaunchPermit{}, err
	}
	scope.PolicyGeneration = policy.Generation
	if _, err := s.currentLaunch(ctx, scope); err != nil {
		return api.LaunchPermit{}, err
	}
	if err := s.checkGrants(ctx, scope, record); err != nil {
		return api.LaunchPermit{}, err
	}
	if err := s.checkPlanAuthority(ctx, scope, plan); err != nil {
		return api.LaunchPermit{}, err
	}
	if _, err := s.CheckLaunchCredentials(ctx, durable); err != nil {
		return api.LaunchPermit{}, err
	}
	return api.LaunchPermit{LaunchID: record.ID, PreparedID: durable.Prepared.ID,
		RecordSHA256: durable.Identity.RecordSHA256, CommittedSeq: durable.Identity.CommittedSeq}, nil
}

func (s *Service) RevokeLaunch(ctx context.Context, launchID api.ID) error {
	if !validID(launchID) {
		return refusal(api.CodeInvalid, "invalid launch identifier")
	}
	return s.invalidateCommittedLaunch(ctx, launchID)
}

func (s *Service) HumanChallenge(ctx context.Context, scope api.Scope, request api.HumanChallengeRequest) (api.HumanChallenge, error) {
	return s.Challenge(ctx, scope, request)
}

func (s *Service) Challenge(ctx context.Context, scope api.Scope, request api.HumanChallengeRequest) (api.HumanChallenge, error) {
	if err := ctx.Err(); err != nil {
		return api.HumanChallenge{}, err
	}
	if err := validateIntent(request); err != nil {
		return api.HumanChallenge{}, err
	}
	return s.issueChallenge(ctx, scope, request)
}

func (s *Service) HumanConfirm(ctx context.Context, scope api.Scope, request api.HumanConfirmRequest) (api.ProofRef, error) {
	return s.Confirm(ctx, scope, request)
}

func (s *Service) Confirm(ctx context.Context, scope api.Scope, request api.HumanConfirmRequest) (api.ProofRef, error) {
	if err := ctx.Err(); err != nil {
		return api.ProofRef{}, err
	}
	if err := validateConfirmation(request); err != nil {
		return api.ProofRef{}, err
	}
	return s.confirmAssertion(ctx, scope, request)
}

// CheckProof reads immutable verification facts. It never consumes a nonce;
// mutations submit ProofUse to the service-owned store's commit boundary.
func (s *Service) CheckProof(ctx context.Context, scope api.Scope, proof api.ProofRef, target api.HumanChallengeRequest) (api.VerifiedHumanProof, error) {
	if err := ctx.Err(); err != nil {
		return api.VerifiedHumanProof{}, err
	}
	if scope.Actor.Kind != "human" || scope.Config == "" {
		return api.VerifiedHumanProof{}, refusal(api.CodeUnauthenticated, "verified human endpoint is required")
	}
	if err := validateIntent(target); err != nil {
		return api.VerifiedHumanProof{}, err
	}
	expiry, err := utcTime(proof.ExpiresAt)
	if err != nil || !validID(proof.ID) || proof.RequestSHA256 != target.RequestSHA256 ||
		!s.deps.Clock.Now().Before(expiry) {
		return api.VerifiedHumanProof{}, refusal(api.CodeUnauthenticated, "operation proof is invalid or expired")
	}
	verified, err := s.deps.Store.Proof(ctx, scope, proof.ID)
	if err != nil {
		return api.VerifiedHumanProof{}, err
	}
	if err := s.checkStoredProof(ctx, scope, proof, target, verified); err != nil {
		return api.VerifiedHumanProof{}, err
	}
	return verified, nil
}

func (s *Service) HumanSession(ctx context.Context, scope api.Scope, _ api.HumanSessionRequest) (api.HumanSession, error) {
	if err := ctx.Err(); err != nil {
		return api.HumanSession{}, err
	}
	return s.issueReadSession(ctx, scope)
}

func (s *Service) TicketIssue(ctx context.Context, scope api.Scope, request api.TicketIssueRequest) (api.Ticket, error) {
	if err := ctx.Err(); err != nil {
		return api.Ticket{}, err
	}
	expires, err := validateTicketInput(request)
	if err != nil {
		return api.Ticket{}, err
	}
	// Current expiry is a server preflight after receipt lookup; the CLI's
	// shared input check must not prevent an exact retry of an older receipt.
	if !s.deps.Clock.Now().Before(expires) {
		return api.Ticket{}, refusal(api.CodeInvalid, "ticket expiry must be in the future")
	}
	if scope.Actor.Kind != "human" || scope.Request.Method != "ticket.issue" || scope.Request.Proof == nil {
		return api.Ticket{}, refusal(api.CodeUnauthenticated, "ticket issuance requires operation confirmation")
	}
	return s.issueTicket(ctx, scope, request)
}

func refusal(code api.ErrorCode, message string) *api.Error {
	return &api.Error{Code: code, Message: message, Owner: "lb-v2-identity",
		Instead: "Use the installed service with current launch or operation-bound human authority."}
}

func gap(operation, dependency string) *api.Error {
	return &api.Error{Code: api.CodeNotImplemented, Owner: "lb-v2-identity",
		Message: operation + " requires " + dependency,
		Instead: "Integrate the frozen-contract amendments recorded in identity/contract-gaps.md."}
}

func utcTime(value api.Timestamp) (time.Time, error) {
	if len(value) == 0 || value[len(value)-1] != 'Z' {
		return time.Time{}, refusal(api.CodeInvalid, "UTC timestamp is required")
	}
	parsed, err := time.Parse(time.RFC3339Nano, string(value))
	if err != nil {
		return time.Time{}, refusal(api.CodeInvalid, "invalid timestamp")
	}
	return parsed, nil
}
