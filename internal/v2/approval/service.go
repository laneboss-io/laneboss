// Package approval stages and approves D6 changes through the service-owned
// state/identity ports. Only the outbox publisher may install a generation.
package approval

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type Dependencies struct {
	Store     api.StateStore
	Human     api.HumanVerifier
	Worker    api.DataWorker
	Publisher api.OrgPublisher
	Clock     api.Clock
}

type Service struct {
	deps Dependencies
}

func New(deps Dependencies) (*Service, error) {
	for _, dependency := range []any{deps.Store, deps.Human, deps.Worker, deps.Publisher, deps.Clock} {
		if absent(dependency) {
			return nil, &api.Error{Code: api.CodePrerequisite, Message: "approval requires state store, human verifier, confined worker, publisher and clock",
				Instead: "Configure all frozen approval dependencies in the service composition root.", Owner: "lb-v2-approval"}
		}
	}
	return &Service{deps: deps}, nil
}

var _ api.ApprovalAPI = (*Service)(nil)
var _ api.Module = (*Service)(nil)

func (s *Service) Register(registry api.Registrar) error {
	if absent(registry) {
		return invalid("approval requires a method registry")
	}
	for _, entry := range []struct {
		method  api.Method
		handler api.Handler
	}{
		{"org.change.propose", handler(s.OrgChangePropose)},
		{"org.change.get", handler(s.OrgChangeGet)},
		{"org.change.approve", handler(s.OrgChangeApprove)},
		{"org.change.apply", handler(s.OrgChangeApply)},
	} {
		if err := registry.Register(entry.method, entry.handler); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) OrgChangePropose(ctx context.Context, scope api.Scope, request api.ChangeProposeRequest) (api.ChangeRequest, error) {
	if err := requestScope(ctx, scope, "org.change.propose", request); err != nil {
		return api.ChangeRequest{}, err
	}
	if err := s.currentL6(ctx, scope); err != nil {
		return api.ChangeRequest{}, err
	}
	if err := ValidatePropose(request); err != nil {
		return api.ChangeRequest{}, err
	}
	reserved, err := s.reservation(ctx, scope)
	if err != nil {
		return api.ChangeRequest{}, err
	}
	if reserved.Reply != nil {
		result, err := readReply[api.ChangeRequest](reserved.Reply)
		if err != nil {
			return api.ChangeRequest{}, err
		}
		if result.Config != scope.Config || result.Requester != scope.Actor {
			return api.ChangeRequest{}, integrity("proposal replay belongs to another scope")
		}
		return result, ValidateProposeResult(request, result)
	}
	if err := s.verifyBlob(ctx, scope, request.Reason); err != nil {
		return api.ChangeRequest{}, err
	}
	for _, file := range request.Files {
		if file.After != nil {
			if err := s.verifyBlob(ctx, scope, *file.After); err != nil {
				return api.ChangeRequest{}, err
			}
		}
	}
	snapshot, err := s.snapshot(ctx, scope, request.OrgID, request.BaseGeneration)
	if err != nil {
		return api.ChangeRequest{}, err
	}
	if err := validateOwnedDeltas(snapshot, request.Files, nil); err != nil {
		return api.ChangeRequest{}, err
	}
	if err := s.verifyBlob(ctx, scope, snapshot.OwnershipManifest); err != nil {
		return api.ChangeRequest{}, err
	}
	files, err := normalizedFiles(request.Files, false)
	if err != nil {
		return api.ChangeRequest{}, err
	}
	now := s.deps.Clock.Now().UTC()
	if now.IsZero() {
		return api.ChangeRequest{}, integrity("proposal requires a service-clock instant")
	}
	input := api.ChangeRequest{ID: stableID(reserved.Operation.ID, "change"), Config: scope.Config,
		OrgID: request.OrgID, Requester: scope.Actor, BaseGeneration: request.BaseGeneration,
		Files: files, Derived: []api.ResourceDelta{}, Reason: request.Reason, SourceSnapshot: snapshot.Ref,
		OwnershipManifest: snapshot.OwnershipManifest, Renderer: snapshot.Renderer, Status: "proposed",
		CreatedAt: api.Timestamp(now.Format(time.RFC3339Nano)), ExpiresAt: api.Timestamp(now.Add(24 * time.Hour).Format(time.RFC3339Nano))}
	workerInput, err := cloneChange(input)
	if err != nil {
		return api.ChangeRequest{}, err
	}
	rendered, err := s.renderChange(ctx, scope, workerInput)
	if err != nil {
		return api.ChangeRequest{}, err
	}
	if err := ValidateRenderedChange(input, rendered); err != nil {
		return api.ChangeRequest{}, err
	}
	if err := validateSnapshotBinding(rendered, snapshot); err != nil {
		return api.ChangeRequest{}, err
	}
	if err := s.verifyChangeBlobs(ctx, scope, rendered); err != nil {
		return api.ChangeRequest{}, err
	}
	tx, err := transaction(scope)
	if err != nil {
		return api.ChangeRequest{}, err
	}
	event, err := s.changeEvent(ctx, scope, reserved.Operation.ID, "org.change.proposed", api.ChangeEvent{Change: rendered, Reason: "exact source and derived staging"})
	if err != nil {
		return api.ChangeRequest{}, err
	}
	raw, err := replyBytes(rendered)
	if err != nil {
		return api.ChangeRequest{}, err
	}
	tx.Compare = []api.Compare{{Kind: api.CompareOrg, ID: request.OrgID, Generation: request.BaseGeneration},
		{Kind: api.CompareChange, ID: rendered.ID}}
	tx.Writes.Changes, tx.Events, tx.Reply = []api.ChangeRequest{rendered}, []api.Event{event}, &api.RPCReply{Result: raw}
	reply, err := s.commit(ctx, scope, reserved.Operation.ID, tx)
	if err != nil {
		return api.ChangeRequest{}, err
	}
	result, err := readReply[api.ChangeRequest](reply)
	if err != nil {
		return api.ChangeRequest{}, err
	}
	if err := ValidateRevalidation(rendered, result); err != nil {
		return api.ChangeRequest{}, err
	}
	return result, ValidateProposeResult(request, result)
}

func (s *Service) OrgChangeGet(ctx context.Context, scope api.Scope, request api.ChangeGetRequest) (api.ChangeRequest, error) {
	if err := requestScope(ctx, scope, "org.change.get", request); err != nil {
		return api.ChangeRequest{}, err
	}
	if err := ValidateGet(request); err != nil {
		return api.ChangeRequest{}, err
	}
	if scope.Actor.Kind == "lane" {
		if err := s.currentL6(ctx, scope); err != nil {
			return api.ChangeRequest{}, err
		}
	} else if scope.Actor.Kind != "human" || !validID(scope.Actor.ID) {
		return api.ChangeRequest{}, forbidden("only the proposing L6 or a verified human may read a staged change")
	} else {
		bound, err := s.humanRead(ctx, scope)
		if err != nil {
			return api.ChangeRequest{}, err
		}
		scope = bound
	}
	change, err := s.readChange(ctx, scope, request.ChangeID)
	if err != nil {
		return api.ChangeRequest{}, err
	}
	if scope.Actor.Kind == "lane" && change.Requester != scope.Actor {
		return api.ChangeRequest{}, &api.Error{Code: api.CodeNotFound, Message: "staged change is not visible", Instead: route, Owner: "lb-v2-approval"}
	}
	return cloneChange(change)
}

func (s *Service) OrgChangeApprove(ctx context.Context, scope api.Scope, request api.ChangeApproveRequest) (api.ChangeApproval, error) {
	if err := requestScope(ctx, scope, "org.change.approve", request); err != nil {
		return api.ChangeApproval{}, err
	}
	if err := humanActor(scope); err != nil {
		return api.ChangeApproval{}, err
	}
	if err := ValidateApprove(request); err != nil {
		return api.ChangeApproval{}, err
	}
	if err := humanProof(scope); err != nil {
		return api.ChangeApproval{}, err
	}
	proof := scope.Request.Proof
	reserved, err := s.reservation(ctx, scope)
	if err != nil {
		return api.ChangeApproval{}, err
	}
	if reserved.Reply != nil {
		result, err := readReply[api.ChangeApproval](reserved.Reply)
		if err != nil {
			return api.ChangeApproval{}, err
		}
		return result, ValidateApproveResult(request, result)
	}
	change, err := s.readChange(ctx, scope, request.ChangeID)
	if err != nil {
		return api.ChangeApproval{}, err
	}
	if change.Status != "proposed" && change.Status != "approved" {
		return api.ChangeApproval{}, conflict("staged change is no longer open for approval")
	}
	if change.ManifestSHA256 != request.ManifestSHA256 || change.BaseGeneration != request.BaseGeneration {
		return api.ChangeApproval{}, conflict("human review does not match the retained manifest and base")
	}
	snapshot, err := s.snapshot(ctx, scope, change.OrgID, change.BaseGeneration)
	if err != nil {
		return api.ChangeApproval{}, err
	}
	if err := validateSnapshotBinding(change, snapshot); err != nil {
		return api.ChangeApproval{}, err
	}
	if err := s.verifyChangeBlobs(ctx, scope, change); err != nil {
		return api.ChangeApproval{}, err
	}
	target := api.HumanChallengeRequest{Method: scope.Request.Method, TargetID: change.ID,
		RequestSHA256: scope.Request.RequestSHA256, BaseGeneration: change.BaseGeneration}
	facts, err := s.deps.Human.CheckProof(ctx, scope, *proof, target)
	if err != nil {
		return api.ChangeApproval{}, err
	}
	approved, err := approvalFromProof(s.deps.Clock.Now(), scope, reserved.Operation.ID, change, facts)
	if err != nil {
		return api.ChangeApproval{}, err
	}
	tx, err := transaction(scope)
	if err != nil {
		return api.ChangeApproval{}, err
	}
	event, err := s.changeEvent(ctx, scope, reserved.Operation.ID, "org.change.approved", api.ChangeEvent{Change: change, Approval: &approved, Reason: "verified exact-change human approval"})
	if err != nil {
		return api.ChangeApproval{}, err
	}
	raw, err := replyBytes(approved)
	if err != nil {
		return api.ChangeApproval{}, err
	}
	tx.Compare = []api.Compare{{Kind: api.CompareOrg, ID: change.OrgID, Generation: change.BaseGeneration},
		{Kind: api.CompareApproval, ID: approved.ID}}
	tx.Guards = []api.TransactionGuard{{Proof: &api.ProofUse{Proof: *proof, Target: target}}}
	tx.Writes.Approvals, tx.Events, tx.Reply = []api.ChangeApproval{approved}, []api.Event{event}, &api.RPCReply{Result: raw}
	reply, err := s.commit(ctx, scope, reserved.Operation.ID, tx)
	if err != nil {
		return api.ChangeApproval{}, err
	}
	result, err := readReply[api.ChangeApproval](reply)
	if err != nil {
		return api.ChangeApproval{}, err
	}
	if result != approved {
		return api.ChangeApproval{}, integrity("approval commit changed the verified receipt")
	}
	return result, ValidateApproveResult(request, result)
}

func (s *Service) OrgChangeApply(ctx context.Context, scope api.Scope, request api.ChangeApplyRequest) (api.ChangeReceipt, error) {
	if err := requestScope(ctx, scope, "org.change.apply", request); err != nil {
		return api.ChangeReceipt{}, err
	}
	if err := s.currentL6(ctx, scope); err != nil {
		return api.ChangeReceipt{}, err
	}
	if err := ValidateApply(request); err != nil {
		return api.ChangeReceipt{}, err
	}
	reserved, err := s.reservation(ctx, scope)
	if err != nil {
		return api.ChangeReceipt{}, err
	}
	if reserved.Reply != nil || reserved.Deferred != nil {
		reply := reserved.Reply
		if reply == nil {
			reply, err = s.publicationReply(ctx, scope, reserved.Operation.ID, reserved.Deferred)
			if err != nil {
				return api.ChangeReceipt{}, err
			}
		}
		result, err := readReply[api.ChangeReceipt](reply)
		if err != nil {
			return api.ChangeReceipt{}, err
		}
		return result, ValidateApplyResult(request, result)
	}
	change, err := s.readChange(ctx, scope, request.ChangeID)
	if err != nil {
		return api.ChangeReceipt{}, err
	}
	if change.Status != "proposed" && change.Status != "approved" {
		return api.ChangeReceipt{}, conflict("staged change is no longer open for application")
	}
	if change.Requester != scope.Actor {
		return api.ChangeReceipt{}, forbidden("only the proposing current L6 life may apply the change")
	}
	if request.ExpectedGeneration != change.BaseGeneration {
		return api.ChangeReceipt{}, conflict("application base differs from the retained change")
	}
	snapshot, err := s.snapshot(ctx, scope, change.OrgID, change.BaseGeneration)
	if err != nil {
		return api.ChangeReceipt{}, err
	}
	if err := validateSnapshotBinding(change, snapshot); err != nil {
		return api.ChangeReceipt{}, err
	}
	approved, err := s.deps.Store.Approval(ctx, scope, request.ApprovalID)
	if err != nil {
		return api.ChangeReceipt{}, err
	}
	if approved.ID != request.ApprovalID {
		return api.ChangeReceipt{}, integrity("store returned another approval")
	}
	if err := ValidateApprovalBinding(s.deps.Clock.Now(), change, approved); err != nil {
		return api.ChangeReceipt{}, err
	}
	workerInput, err := renderInputs(change)
	if err != nil {
		return api.ChangeReceipt{}, err
	}
	rendered, err := s.renderChange(ctx, scope, workerInput)
	if err != nil {
		return api.ChangeReceipt{}, err
	}
	if err := ValidateRevalidation(change, rendered); err != nil {
		return api.ChangeReceipt{}, err
	}
	if err := s.verifyRenderedBlobs(ctx, scope, rendered); err != nil {
		return api.ChangeReceipt{}, err
	}
	if err := s.verifyChangeBlobs(ctx, scope, change); err != nil {
		return api.ChangeReceipt{}, err
	}
	tx, err := transaction(scope)
	if err != nil {
		return api.ChangeReceipt{}, err
	}
	launch, err := s.deps.Store.Launch(ctx, scope.LaunchID)
	if err != nil {
		return api.ChangeReceipt{}, err
	}
	if launch.ID != scope.LaunchID || launch.Config != scope.Config || launch.Actor != scope.Actor || launch.Revoked ||
		launch.EndpointGeneration != scope.EndpointGeneration || launch.Target.LifeID != scope.Actor.LifeID || launch.Target.Run == 0 {
		return api.ChangeReceipt{}, forbidden("publication requires the current authenticated L6 launch")
	}
	life, err := s.deps.Store.Lane(ctx, scope, launch.Target)
	if err != nil {
		return api.ChangeReceipt{}, err
	}
	if life.LifeID != launch.Target.LifeID || life.Run != launch.Target.Run || life.LaunchID != launch.ID || life.Cleaned || life.CancellationEpoch > maxInteger {
		return api.ChangeReceipt{}, forbidden("publication requires the current recorded L6 life revision")
	}
	effectID := stableID(reserved.Operation.ID, "publish")
	intent := api.InternalIntent{ID: stableID(reserved.Operation.ID, "intent"), Kind: api.InternalOrgPublish,
		Config: scope.Config, Actor: api.Actor{Kind: "service", ID: "lb-v2-approval"}, RequestedBy: scope.Actor,
		CauseOperationID: reserved.Operation.ID, CauseRequestID: scope.Request.RequestID, EffectID: effectID, Target: launch.Target, CancellationEpoch: life.CancellationEpoch}
	tx.Compare = []api.Compare{{Kind: api.CompareOrg, ID: change.OrgID, Generation: change.BaseGeneration}}
	tx.Guards = []api.TransactionGuard{{Approval: &api.ApprovalUse{ApprovalID: approved.ID,
		ChangeID: change.ID, ManifestSHA256: change.ManifestSHA256, BaseGeneration: change.BaseGeneration}}}
	tx.Effects = []api.Effect{{ID: effectID, OperationID: reserved.Operation.ID, Context: &intent, ApplyChange: &request}}
	tx.Deferred = &api.DeferredReply{Key: reserved.Key, OperationID: reserved.Operation.ID, EffectID: effectID}
	// No applied event, application projection or success reply precedes actual
	// publication. The service outbox supplies the publisher lease and completion.
	reply, err := s.commit(ctx, scope, reserved.Operation.ID, tx)
	if err != nil {
		return api.ChangeReceipt{}, err
	}
	result, err := readReply[api.ChangeReceipt](reply)
	if err != nil {
		return api.ChangeReceipt{}, err
	}
	if result.ManifestSHA256 != change.ManifestSHA256 {
		return api.ChangeReceipt{}, integrity("publication receipt differs from the approved manifest")
	}
	return result, ValidateApplyResult(request, result)
}

func absent(value any) bool {
	if value == nil {
		return true
	}
	kind := reflect.ValueOf(value)
	switch kind.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Func, reflect.Chan, reflect.Interface, reflect.Slice:
		return kind.IsNil()
	default:
		return false
	}
}

func handler[Request, Result any](call func(context.Context, api.Scope, Request) (Result, error)) api.Handler {
	return func(ctx context.Context, scope api.Scope, raw json.RawMessage) (json.RawMessage, error) {
		var request Request
		if err := DecodeJSON(raw, &request); err != nil {
			return nil, err
		}
		result, err := call(ctx, scope, request)
		if err != nil {
			return nil, err
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			return nil, integrity("approval result could not be encoded")
		}
		return encoded, nil
	}
}

func requestScope(ctx context.Context, scope api.Scope, method api.Method, params any) error {
	if err := contextFailure(ctx); err != nil {
		return err
	}
	request := scope.Request
	if !validID(api.ID(scope.Config)) || request.Config != scope.Config || request.Method != method ||
		request.Protocol != api.Protocol || request.Schema != api.SchemaVersion ||
		!validID(request.RequestID) || len(request.RequestID) < 22 ||
		!validID(request.IdempotencyKey) || len(request.IdempotencyKey) < 22 {
		return invalid("approval request lacks authenticated dispatcher metadata")
	}
	// Strictly decode to the same concrete request type so missing fields,
	// duplicate keys, unknown fields and explicit null cannot be normalized away.
	copyParams := reflect.New(reflect.TypeOf(params))
	if err := DecodeJSON(request.Params, copyParams.Interface()); err != nil {
		return err
	}
	wire, err := canonical(copyParams.Elem().Interface())
	if err != nil {
		return err
	}
	actual, err := canonical(params)
	if err != nil || !bytes.Equal(wire, actual) {
		return invalid("approval parameters differ from the authenticated intent")
	}
	digest, err := api.RequestDigest(request)
	if err != nil || !validDigest(request.RequestSHA256) || digest != request.RequestSHA256 {
		return invalid("approval request intent digest does not match")
	}
	// A lane proof never becomes authority through completed replay. Validate
	// the same human-kind/shape/intent boundary used by approval before lookup;
	// current-clock expiry and nonce consumption still follow original replay.
	if request.Proof != nil {
		if method != "org.change.approve" {
			return forbidden("only approval accepts an operation proof; reads require a bound session")
		}
		if err := humanActor(scope); err != nil {
			return err
		}
		if err := humanProof(scope); err != nil {
			return err
		}
	}
	return nil
}

func humanActor(scope api.Scope) error {
	if scope.Actor.Kind != "human" || !validID(scope.Actor.ID) || scope.Actor.LifeID != "" ||
		scope.Actor.Level != 0 || scope.Actor.Role != "" || scope.LaunchID != "" ||
		scope.EndpointGeneration == 0 || scope.EndpointGeneration > maxInteger {
		return forbidden("D6 approval requires the verified human endpoint and fresh confirmation")
	}
	return nil
}

func humanProof(scope api.Scope) error {
	proof := scope.Request.Proof
	if proof == nil || !validID(proof.ID) || proof.RequestSHA256 != scope.Request.RequestSHA256 {
		return forbidden("human confirmation is absent or covers another intent")
	}
	if _, err := timestamp(proof.ExpiresAt); err != nil {
		return forbidden("human confirmation has an invalid expiry")
	}
	return nil
}

func (s *Service) currentL6(ctx context.Context, scope api.Scope) error {
	if scope.Actor.Kind != "lane" || scope.Actor.Level != 6 || !validID(scope.Actor.ID) ||
		!validID(scope.Actor.LifeID) || scope.Actor.Role == "" || !validID(scope.LaunchID) ||
		scope.EndpointGeneration == 0 || scope.EndpointGeneration > maxInteger {
		return forbidden("org changes require an authenticated current recorded L6 life")
	}
	record, err := s.deps.Store.Launch(ctx, scope.LaunchID)
	if err != nil {
		return err
	}
	if record.Revoked || record.Target.Run == 0 || record.ID != scope.LaunchID || record.Config != scope.Config ||
		record.Actor != scope.Actor || record.Target.LifeID != scope.Actor.LifeID ||
		record.EndpointGeneration != scope.EndpointGeneration {
		return forbidden("the recorded L6 launch is revoked, stale or belongs to another scope")
	}
	return nil
}

func (s *Service) readChange(ctx context.Context, scope api.Scope, id api.ID) (api.ChangeRequest, error) {
	change, err := s.deps.Store.Change(ctx, scope, id)
	if err != nil {
		return api.ChangeRequest{}, err
	}
	if change.ID != id {
		return api.ChangeRequest{}, integrity("store returned a different staged change")
	}
	if change.Config != scope.Config {
		return api.ChangeRequest{}, integrity("store returned a staged change from another configuration")
	}
	if err = ValidateChange(change); err != nil {
		return api.ChangeRequest{}, err
	}
	return change, nil
}

func cloneChange(change api.ChangeRequest) (api.ChangeRequest, error) {
	// ValidateChange already checked both lists. Copy the nested BlobRefs too;
	// callers cannot mutate a retained in-memory projection through an alias.
	var err error
	change.Files, err = normalizedFiles(change.Files, false)
	if err != nil {
		return api.ChangeRequest{}, err
	}
	change.Derived, err = normalizedFiles(change.Derived, true)
	if err != nil {
		return api.ChangeRequest{}, err
	}
	return change, nil
}

func renderInputs(change api.ChangeRequest) (api.ChangeRequest, error) {
	// Retained outputs never enter Render, including through nested references.
	change.Derived = []api.ResourceDelta{}
	change.Diff = api.BlobRef{}
	change.ManifestSHA256 = ""
	return cloneChange(change)
}

func (s *Service) renderChange(ctx context.Context, scope api.Scope, change api.ChangeRequest) (api.ChangeRequest, error) {
	if worker, ok := s.deps.Worker.(api.ScopedOrgRenderer); ok {
		return worker.RenderForScope(ctx, scope, change)
	}
	if worker, ok := s.deps.Worker.(interface {
		RenderChange(context.Context, api.Scope, api.ChangeRequest) (api.ChangeRequest, error)
	}); ok {
		return worker.RenderChange(ctx, scope, change)
	}
	return s.deps.Worker.Render(ctx, change)
}

func (s *Service) humanRead(ctx context.Context, scope api.Scope) (api.Scope, error) {
	if err := humanActor(scope); err != nil {
		return api.Scope{}, err
	}
	if scope.ReadAuthority == nil || absent(scope.Connection) {
		return api.Scope{}, forbidden("staged change reads require a bound human session")
	}
	bound, err := api.WithReadAuthority(ctx, scope)
	if err != nil {
		return api.Scope{}, err
	}
	want, live := scope.ReadAuthority, bound.ReadAuthority
	if want.ConnectionID != live.ConnectionID || want.SessionID != live.SessionID ||
		want.CredentialID != live.CredentialID || want.PrincipalID != live.PrincipalID ||
		want.Config != live.Config || want.EndpointGeneration != live.EndpointGeneration {
		return api.Scope{}, forbidden("staged change read session differs from its live connection")
	}
	return bound, nil
}

func (s *Service) verifyChangeBlobs(ctx context.Context, scope api.Scope, change api.ChangeRequest) error {
	for _, ref := range []api.BlobRef{change.Reason, change.OwnershipManifest, change.Diff} {
		if err := s.verifyBlob(ctx, scope, ref); err != nil {
			return err
		}
	}
	for _, files := range [][]api.ResourceDelta{change.Files, change.Derived} {
		for _, file := range files {
			if file.After != nil {
				if err := s.verifyBlob(ctx, scope, *file.After); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
