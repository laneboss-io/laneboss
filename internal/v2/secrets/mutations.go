package secrets

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

type sealedStage struct {
	key     uploadKey
	request api.SecretStageRequest
	receipt api.SecretStage
	digest  api.Digest
	claimed api.RequestKey
}

// Protected backends may implement this lane-local capability. It serializes
// version checks, backend I/O and the single proof/event/reply transaction.
// It is not a second state writer, generic metadata DB or public value lookup.
type mutationBackend interface {
	WithMutation(context.Context, api.ID, func(api.SecretBackend, []api.SecretInfo) error) error
}

func requestMatches[I any](scope api.Scope, input I) error {
	var framed I
	if err := wire.Decode(scope.Request.Params, &framed, api.MaxFrameBytes); err != nil {
		return err
	}
	if !reflect.DeepEqual(framed, input) {
		return wire.Error(api.CodeUnauthenticated, "secret input differs from the authenticated request")
	}
	return nil
}

func secretID(scope api.Scope, label string) api.ID {
	parts := []string{"laneboss.secrets.v2", label, scope.Config, scope.Actor.Kind,
		string(scope.Actor.ID), string(scope.Actor.LifeID), string(scope.Request.Method), string(scope.Request.IdempotencyKey)}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return api.ID("secret-" + hex.EncodeToString(sum[:]))
}

func requestKey(scope api.Scope) api.RequestKey {
	return api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey, RequestSHA256: scope.Request.RequestSHA256}
}

func receiptMatches(scope api.Scope, receipt api.MutationReceipt) bool {
	return receipt.Config == scope.Config && receipt.Key == requestKey(scope) &&
		receipt.Actor == scope.Actor && wire.ID(string(receipt.Operation.ID))
}

func (s *Service) receipt(ctx context.Context, scope api.Scope, reserve bool) (api.MutationReceipt, error) {
	receipt, err := s.deps.Store.LookupReceipt(ctx, scope, requestKey(scope))
	var typed *api.Error
	if errors.As(err, &typed) && typed.Code == api.CodeNotFound && reserve {
		deadline := s.deps.Clock.Now().Add(2 * time.Minute)
		if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
			deadline = limit
		}
		receipt, err = s.deps.Store.ReserveRequest(ctx, api.RequestReservation{Scope: scope,
			RawRequest: append([]byte(nil), scope.Frame.Bytes()...), Deadline: api.Timestamp(deadline.UTC().Format(time.RFC3339Nano))})
	}
	if err != nil {
		return api.MutationReceipt{}, err
	}
	if !receiptMatches(scope, receipt) {
		return api.MutationReceipt{}, wire.Error(api.CodeIntegrity, "secret receipt belongs to another request or principal")
	}
	if receipt.Reply == nil && receipt.Operation.Status != "pending" && receipt.Operation.Status != "running" {
		return api.MutationReceipt{}, wire.Error(api.CodeIntegrity, "secret receipt omitted its final reply")
	}
	return receipt, nil
}

func infoReply(reply *api.RPCReply, name, version, expected string) (api.SecretInfo, error) {
	if reply == nil {
		return api.SecretInfo{}, wire.Error(api.CodeIntegrity, "secret transaction omitted its reply")
	}
	if reply.Error != nil {
		return api.SecretInfo{}, reply.Error
	}
	var info api.SecretInfo
	if err := wire.Decode(reply.Result, &info, api.MaxFrameBytes); err != nil || info.Name != name ||
		!wire.Name(info.Version) || !wire.ID(string(info.SourceHandle)) || !wire.ID(string(info.KeyID)) || info.Revoked ||
		(version != "" && info.Version != version) || (expected != "" && info.Version == expected) {
		return api.SecretInfo{}, wire.Error(api.CodeIntegrity, "secret receipt differs from the requested source")
	}
	return info, nil
}

func operationReply(reply *api.RPCReply, id api.ID) (api.Operation, error) {
	if reply == nil {
		return api.Operation{}, wire.Error(api.CodeIntegrity, "secret transaction omitted its reply")
	}
	if reply.Error != nil {
		return api.Operation{}, reply.Error
	}
	var operation api.Operation
	if err := wire.Decode(reply.Result, &operation, api.MaxFrameBytes); err != nil ||
		operation.ID != id || operation.Status != "succeeded" || operation.Error != nil {
		return api.Operation{}, wire.Error(api.CodeIntegrity, "secret revocation receipt is not its completed operation")
	}
	return operation, nil
}

func (s *Service) checkProof(ctx context.Context, scope api.Scope) (api.HumanChallengeRequest, error) {
	target, err := s.deps.Store.AuthorizationTarget(ctx, scope, scope.Request)
	if err != nil {
		return target, err
	}
	if target.Method != scope.Request.Method || target.RequestSHA256 != scope.Request.RequestSHA256 {
		return target, wire.Error(api.CodeIntegrity, "secret authorization target differs from the request")
	}
	verified, err := s.deps.Human.CheckProof(ctx, scope, *scope.Request.Proof, target)
	if err != nil {
		return target, err
	}
	if verified.Ref != *scope.Request.Proof || verified.Config != scope.Config || verified.PrincipalID != scope.Actor.ID ||
		verified.Target != target || verified.EndpointClass != api.EndpointHuman || verified.EndpointGeneration != scope.EndpointGeneration ||
		!wire.ID(string(verified.CredentialID)) || !wire.ID(string(verified.NonceID)) || verified.ConsumedBy != "" {
		return target, wire.Error(api.CodeForbidden, "secret proof facts differ from the authorized operation")
	}
	return target, nil
}

func (s *Service) claimStage(ctx context.Context, scope api.Scope, id api.ID, name, version, expected string) (sealedStage, error) {
	authority, err := s.readAuthority(ctx, scope)
	if err != nil {
		return sealedStage{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireKeys(s.deps.Clock.Now())
	stage, ok := s.stages[id]
	if !ok || stage.key.actor != scope.Actor.ID || stage.key.connection != scope.Connection.ID() ||
		stage.key.session != authority.SessionID || stage.key.endpoint != scope.EndpointGeneration {
		return sealedStage{}, wire.Error(api.CodeNotFound, "encrypted stage is absent for this live human session")
	}
	if stage.request.Name != name || version != "" && stage.request.Version != version ||
		expected != "" && stage.request.Version == expected {
		return sealedStage{}, wire.Error(api.CodeForbidden, "encrypted stage differs from the exact secret intent")
	}
	if stage.claimed != (api.RequestKey{}) && stage.claimed != requestKey(scope) {
		return sealedStage{}, wire.Error(api.CodeConflict, "encrypted stage is already bound to another operation")
	}
	stage.claimed = requestKey(scope)
	s.stages[id] = stage
	stage.request.EphemeralPublicKey = append([]byte(nil), stage.request.EphemeralPublicKey...)
	stage.request.Nonce = append([]byte(nil), stage.request.Nonce...)
	stage.request.Ciphertext = append([]byte(nil), stage.request.Ciphertext...)
	return stage, nil
}

func (s *Service) retireStage(id api.ID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stage := s.stages[id]
	clear(stage.request.Ciphertext)
	delete(s.stages, id)
}

// The lane's metadata replay invariant is documented in CONTRACTS.md: the
// import/rotation event ID is the protected SourceHandle. Only committed events
// advance the head; unknown backend records stop unrelated operations until the
// original request reconciles them. No value is fetched to discover metadata.
func (s *Service) heads(ctx context.Context, scope api.Scope, infos []api.SecretInfo) (map[string]api.SecretInfo, map[api.ID]bool, error) {
	if scope.Config != s.deps.Config {
		return nil, nil, wire.Error(api.CodeForbidden, "secret history belongs to another configuration")
	}
	// Changing the history read to the installed service scope must not turn
	// a configuration label alone into access. The owning public caller has
	// already checked its proof/session; retain its live authenticated frame.
	class := api.EndpointHuman
	if scope.Actor.Kind == "lane" {
		class = api.EndpointLane
	} else if scope.Actor.Kind != "human" {
		return nil, nil, wire.Error(api.CodeForbidden, "secret history requires its authenticated caller")
	}
	if !wire.ID(string(scope.Actor.ID)) {
		return nil, nil, wire.Error(api.CodeForbidden, "secret history caller is absent")
	}
	if err := s.transport(ctx, scope, scope.Request.Method, class); err != nil {
		return nil, nil, err
	}
	// Configuration history is an internal protected read. Public event.tail
	// requires a life/run and cannot supply this metadata projection. Pin one
	// snapshot under the backend lock shared with import/rotate/revoke.
	history := s.deps.ServiceScope
	history.ReadView = nil
	view, err := s.deps.Store.BeginRead(ctx, history)
	if err != nil {
		return nil, nil, err
	}
	if wire.Nil(view) {
		return nil, nil, wire.Error(api.CodeIntegrity, "secret history has no pinned snapshot")
	}
	if view.Snapshot().Config != s.deps.Config {
		return nil, nil, errors.Join(wire.Error(api.CodeIntegrity, "secret history snapshot differs"), view.Close())
	}
	history.ReadView = view
	heads, known, readErr := s.headsInView(ctx, history, infos)
	if err := errors.Join(readErr, view.Close()); err != nil {
		return nil, nil, err
	}
	return heads, known, nil
}

func (s *Service) headsInView(ctx context.Context, scope api.Scope, infos []api.SecretInfo) (map[string]api.SecretInfo, map[api.ID]bool, error) {
	byID := make(map[api.ID]api.SecretInfo, len(infos))
	for _, info := range infos {
		byID[info.SourceHandle] = info
	}
	heads, known := map[string]api.SecretInfo{}, map[api.ID]bool{}
	query := api.EventTailRequest{}
	var last api.Sequence
	var walked, payloadBytes int
	for pages := 0; pages < 256; pages++ {
		if err := wire.Context(ctx); err != nil {
			return nil, nil, err
		}
		page, err := s.deps.Store.Events(ctx, scope, query)
		if err != nil {
			return nil, nil, err
		}
		for _, event := range page.Events {
			walked++
			payloadBytes += len(event.Payload)
			if walked > 65536 || payloadBytes > 8<<20 {
				return nil, nil, wire.Error(api.CodeBudget, "secret history exceeds its bounded reconciliation window")
			}
			if event.Config != scope.Config || event.Seq <= last {
				return nil, nil, wire.Error(api.CodeIntegrity, "secret event stream has inconsistent identity or order")
			}
			last = event.Seq
			if event.Kind != "secret.imported" && event.Kind != "secret.rotated" && event.Kind != "secret.revoked" {
				continue
			}
			var payload api.SecretEvent
			if err := wire.Decode(event.Payload, &payload, api.MaxFrameBytes); err != nil || event.Schema != api.SchemaVersion ||
				len(payload.Names) != 1 || len(payload.Versions) != 1 || len(payload.GrantIDs) != 0 ||
				!wire.Name(payload.Names[0]) || !wire.Name(payload.Versions[0]) || !wire.ID(string(payload.KeyID)) ||
				payload.Outcome != strings.TrimPrefix(string(event.Kind), "secret.") {
				return nil, nil, wire.Error(api.CodeIntegrity, "secret event metadata is incomplete")
			}
			name, version := payload.Names[0], payload.Versions[0]
			if event.Kind == "secret.revoked" {
				current, ok := heads[name]
				if !ok || current.Revoked || current.Version != version || current.KeyID != payload.KeyID || !byID[current.SourceHandle].Revoked {
					return nil, nil, wire.Error(api.CodeIntegrity, "secret revocation differs from the protected source")
				}
				current.Revoked = true
				heads[name], known[current.SourceHandle] = current, true
				continue
			}
			info, ok := byID[event.ID]
			prior, exists := heads[name]
			if !ok || info.Name != name || info.Version != version || info.KeyID != payload.KeyID ||
				event.Kind == "secret.imported" && exists ||
				event.Kind == "secret.rotated" && (!exists || prior.Revoked || prior.Version == version) {
				return nil, nil, wire.Error(api.CodeIntegrity, "secret event differs from the protected source history")
			}
			info.Revoked = false // Only the committed revocation advances this projection.
			heads[name], known[info.SourceHandle] = info, false
		}
		if page.Complete {
			return heads, known, nil
		}
		if page.Cursor == "" || page.Cursor == query.Cursor {
			return nil, nil, wire.Error(api.CodeIntegrity, "secret event stream did not advance")
		}
		query.Cursor = page.Cursor
	}
	return nil, nil, wire.Error(api.CodeBudget, "secret history requires bounded reconciliation")
}

func reconcile(infos []api.SecretInfo, known map[api.ID]bool, name string, own api.ID, revoking bool, current api.SecretInfo) error {
	for _, info := range infos {
		if info.Name != name {
			continue
		}
		revoked, committed := known[info.SourceHandle]
		if !committed && info.SourceHandle != own || info.Revoked && !revoked && (!revoking || info.SourceHandle != current.SourceHandle) {
			return wire.Error(api.CodeConflict, "secret source needs its original operation reconciliation")
		}
	}
	return nil
}

// This is post-backend failure, not a failed preflight. Preserve the operation
// reference so transport/store can retain and reconcile the same reservation.
func commitFailure(err error, operation api.ID) error {
	var typed *api.Error
	if errors.As(err, &typed) {
		copy := *typed
		copy.OperationID = operation
		if typed.Code == api.CodeUnavailable || typed.Code == api.CodeDeadline || typed.Code == api.CodeCancelled {
			copy.Retryable = true
		}
		return &copy
	}
	failure := wire.Error(api.CodeUnavailable, "secret transaction completion is unavailable")
	failure.OperationID, failure.Retryable = operation, true
	return failure
}

func (s *Service) commitSecret(ctx context.Context, scope api.Scope, receipt api.MutationReceipt, target api.HumanChallengeRequest,
	kind api.EventKind, info api.SecretInfo, result any) (*api.RPCReply, error) {
	payload, err := json.Marshal(api.SecretEvent{Names: []string{info.Name}, Versions: []string{info.Version},
		GrantIDs: []api.ID{}, Outcome: strings.TrimPrefix(string(kind), "secret."), KeyID: info.KeyID})
	if err != nil {
		return nil, wire.Error(api.CodeIntegrity, "cannot encode secret event")
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, wire.Error(api.CodeIntegrity, "cannot encode secret result")
	}
	id := info.SourceHandle
	if kind == "secret.revoked" {
		id = secretID(scope, "revoke-event")
	}
	now := api.Timestamp(s.deps.Clock.Now().UTC().Format(time.RFC3339Nano))
	event := api.Event{Schema: api.SchemaVersion, ID: id, Config: scope.Config, Kind: kind,
		Actor: scope.Actor, RequestedBy: scope.Actor, RequestID: scope.Request.RequestID, OperationID: receipt.Operation.ID,
		StarterChain: []api.ID{}, RecordedAt: now, RequestedAt: now, ObservedAt: now, Origin: "service", Payload: payload}
	commit, err := s.deps.Store.Transact(ctx, api.Transaction{Scope: scope,
		RawRequest: append([]byte(nil), scope.Frame.Bytes()...), Reply: &api.RPCReply{Result: encoded},
		Guards: []api.TransactionGuard{{Proof: &api.ProofUse{Proof: *scope.Request.Proof, Target: target}}}, Events: []api.Event{event}})
	if err != nil {
		return nil, commitFailure(err, receipt.Operation.ID)
	}
	if commit.Operation.Error != nil {
		return nil, commit.Operation.Error
	}
	if commit.Operation.ID != receipt.Operation.ID || commit.Operation.Status != "succeeded" || commit.Reply == nil {
		return nil, wire.Error(api.CodeIntegrity, "secret transaction did not retain its completed operation and reply")
	}
	return commit.Reply, nil
}

func (s *Service) importSecret(ctx context.Context, scope api.Scope, name, version, expected string, stageID api.ID) (api.SecretInfo, error) {
	receipt, err := s.receipt(ctx, scope, true)
	if err != nil {
		return api.SecretInfo{}, err
	}
	if receipt.Reply != nil {
		return infoReply(receipt.Reply, name, version, expected)
	}
	backend, ok := s.deps.Backend.(mutationBackend)
	if !ok {
		return api.SecretInfo{}, api.NotImplemented("lb-v2-secrets", "protected backend mutation serialization and metadata")
	}
	target, err := s.checkProof(ctx, scope)
	if err != nil {
		if completed, lookupErr := s.receipt(ctx, scope, false); lookupErr == nil && completed.Reply != nil {
			return infoReply(completed.Reply, name, version, expected)
		}
		return api.SecretInfo{}, err
	}
	var result api.SecretInfo
	err = backend.WithMutation(ctx, receipt.Operation.ID, func(protected api.SecretBackend, infos []api.SecretInfo) error {
		receipt, err = s.receipt(ctx, scope, true)
		if err != nil {
			return err
		}
		if receipt.Reply != nil {
			result, err = infoReply(receipt.Reply, name, version, expected)
			return err
		}
		heads, known, err := s.heads(ctx, scope, infos)
		if err != nil {
			return err
		}
		current, exists := heads[name]
		if expected == "" && exists || expected != "" && (!exists || current.Version != expected || current.Revoked) {
			return wire.Error(api.CodeConflict, "secret current version differs from the requested base")
		}
		source := secretID(scope, "source-"+string(scope.Request.RequestSHA256))
		if err := reconcile(infos, known, name, source, false, current); err != nil {
			return err
		}
		var stored api.SecretInfo
		for _, info := range infos {
			if info.SourceHandle == source {
				stored = info
			}
		}
		if stored.SourceHandle == "" {
			stage, err := s.claimStage(ctx, scope, stageID, name, version, expected)
			if err != nil {
				return err
			}
			defer clear(stage.request.Ciphertext)
			material, err := openStage(scope.Config, stage.key.private, stage.request)
			if err != nil {
				return err
			}
			defer clear(material.Bytes)
			stored, err = protected.Store(ctx, api.SecretInfo{Name: name, Version: stage.request.Version, SourceHandle: source}, material)
			if err != nil {
				return err
			}
		}
		if stored.Name != name || stored.SourceHandle != source || stored.Revoked || !wire.Name(stored.Version) ||
			!wire.ID(string(stored.KeyID)) || version != "" && stored.Version != version || expected != "" && stored.Version == expected {
			return wire.Error(api.CodeIntegrity, "protected backend returned another secret source")
		}
		kind := api.EventKind("secret.imported")
		if expected != "" {
			kind = "secret.rotated"
		}
		reply, err := s.commitSecret(ctx, scope, receipt, target, kind, stored, stored)
		if err != nil {
			return err
		}
		result, err = infoReply(reply, name, version, expected)
		if err == nil {
			s.retireStage(stageID)
		}
		return err
	})
	if err != nil {
		return api.SecretInfo{}, err
	}
	return result, nil
}

func (s *Service) revokeSecret(ctx context.Context, scope api.Scope, request api.SecretRevokeRequest) (api.Operation, error) {
	receipt, err := s.receipt(ctx, scope, true)
	if err != nil {
		return api.Operation{}, err
	}
	if receipt.Reply != nil {
		return operationReply(receipt.Reply, receipt.Operation.ID)
	}
	backend, ok := s.deps.Backend.(mutationBackend)
	if !ok {
		return api.Operation{}, api.NotImplemented("lb-v2-secrets", "protected backend mutation serialization and metadata")
	}
	target, err := s.checkProof(ctx, scope)
	if err != nil {
		if completed, lookupErr := s.receipt(ctx, scope, false); lookupErr == nil && completed.Reply != nil {
			return operationReply(completed.Reply, completed.Operation.ID)
		}
		return api.Operation{}, err
	}
	var result api.Operation
	err = backend.WithMutation(ctx, receipt.Operation.ID, func(protected api.SecretBackend, infos []api.SecretInfo) error {
		receipt, err = s.receipt(ctx, scope, true)
		if err != nil {
			return err
		}
		if receipt.Reply != nil {
			result, err = operationReply(receipt.Reply, receipt.Operation.ID)
			return err
		}
		heads, known, err := s.heads(ctx, scope, infos)
		if err != nil {
			return err
		}
		current, exists := heads[request.Name]
		if !exists || current.Version != request.ExpectedVersion || current.Revoked {
			return wire.Error(api.CodeConflict, "secret current version differs from the requested base")
		}
		if err := reconcile(infos, known, request.Name, "", true, current); err != nil {
			return err
		}
		if err := protected.Revoke(ctx, current); err != nil {
			return err
		}
		reply, err := s.commitSecret(ctx, scope, receipt, target, "secret.revoked", current,
			api.Operation{ID: receipt.Operation.ID, Status: "succeeded"})
		if err != nil {
			return err
		}
		result, err = operationReply(reply, receipt.Operation.ID)
		return err
	})
	if err != nil {
		return api.Operation{}, err
	}
	return result, nil
}
