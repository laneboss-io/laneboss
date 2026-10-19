package approval

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

func requestKey(scope api.Scope) api.RequestKey {
	return api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey,
		RequestSHA256: scope.Request.RequestSHA256}
}

// The dispatcher reserves/serializes before invoking a mutation. A completed
// receipt is returned before module freshness/base checks; a pending receipt
// supplies the dispatcher-owned operation, not permission to execute twice.
func (s *Service) reservation(ctx context.Context, scope api.Scope) (api.MutationReceipt, error) {
	receipt, err := s.deps.Store.LookupReceipt(ctx, scope, requestKey(scope))
	if err != nil {
		return api.MutationReceipt{}, err
	}
	if receipt.Config != scope.Config || receipt.Key != requestKey(scope) || receipt.Actor != scope.Actor || !validID(receipt.Operation.ID) {
		return api.MutationReceipt{}, integrity("store returned an unrelated request reservation")
	}
	if err := deferredReceipt(receipt, nil); err != nil {
		return api.MutationReceipt{}, err
	}
	if receipt.Reply == nil && receipt.Operation.Status != "pending" && receipt.Operation.Status != "running" {
		return api.MutationReceipt{}, integrity("request reservation lacks its durable completion")
	}
	if receipt.Reply != nil && (receipt.Reply.Error == nil && receipt.Operation.Status != "succeeded" ||
		receipt.Reply.Error != nil && receipt.Operation.Status != "failed" && receipt.Operation.Status != "cancelled") {
		return api.MutationReceipt{}, integrity("request reservation completion has an inconsistent operation state")
	}
	return receipt, nil
}

func deferredReceipt(receipt api.MutationReceipt, expected *api.DeferredReply) error {
	if deferred := receipt.Deferred; deferred != nil {
		if receipt.Key.Method != "org.change.apply" || deferred.Key != receipt.Key ||
			deferred.OperationID != receipt.Operation.ID || !validID(deferred.EffectID) ||
			expected != nil && *deferred != *expected {
			return integrity("store returned an unrelated deferred publication binding")
		}
	}
	return nil
}

func stableID(operation api.ID, kind string) api.ID {
	sum := sha256.Sum256([]byte(kind + "\x00" + string(operation)))
	return api.ID(kind + "-" + hex.EncodeToString(sum[:16]))
}

func transaction(scope api.Scope) (api.Transaction, error) {
	if absent(scope.Frame) {
		return api.Transaction{}, integrity("mutation lacks its dispatcher-retained frame")
	}
	raw := append([]byte(nil), scope.Frame.Bytes()...)
	var original api.Request
	if err := api.DecodeObject(raw, &original); err != nil {
		return api.Transaction{}, integrity("mutation frame differs from the authenticated request")
	}
	originalParams, err := api.CanonicalJSON(original.Params)
	if err != nil {
		return api.Transaction{}, integrity("mutation frame has invalid original parameters")
	}
	params, err := api.CanonicalJSON(scope.Request.Params)
	if err != nil || !bytes.Equal(originalParams, params) {
		return api.Transaction{}, integrity("mutation frame differs from the authenticated parameters")
	}
	// Compare the envelope exactly after comparing parameter semantics. The
	// original transport bytes remain untouched in RawRequest.
	original.Params = scope.Request.Params
	if !reflect.DeepEqual(original, scope.Request) {
		return api.Transaction{}, integrity("mutation frame differs from the authenticated request")
	}
	return api.Transaction{Scope: scope, RawRequest: raw}, nil
}

func replyBytes(value any) (json.RawMessage, error) {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > api.MaxFrameBytes {
		return nil, integrity("approval result exceeds its typed frame bound")
	}
	return raw, nil
}

func readReply[Result any](reply *api.RPCReply) (Result, error) {
	var result Result
	if reply == nil || (reply.Error == nil) == (len(reply.Result) == 0) {
		return result, integrity("approval operation lacks one durable typed reply")
	}
	if reply.Error != nil {
		return result, reply.Error
	}
	if err := DecodeJSON(reply.Result, &result); err != nil {
		return result, integrity("approval operation returned an invalid retained result")
	}
	return result, nil
}

func (s *Service) changeEvent(ctx context.Context, scope api.Scope, operation api.ID, kind api.EventKind, value api.ChangeEvent) (api.Event, error) {
	payload, err := replyBytes(value)
	if err != nil {
		return api.Event{}, err
	}
	instant := s.deps.Clock.Now().UTC().Format("2006-01-02T15:04:05.999999999Z07:00")
	eventID := stableID(api.ID(string(operation)+"\x00"+string(kind)), "event")
	event := api.Event{Schema: api.SchemaVersion, ID: eventID, Config: scope.Config,
		Kind: kind, Actor: scope.Actor, RequestedBy: scope.Actor, RequestID: scope.Request.RequestID,
		OperationID: operation, StarterChain: []api.ID{}, RecordedAt: api.Timestamp(instant),
		RequestedAt: api.Timestamp(instant), ObservedAt: api.Timestamp(instant), Origin: "service", Payload: payload}
	if scope.Actor.Kind == "lane" {
		launch, err := s.deps.Store.Launch(ctx, scope.LaunchID)
		if err != nil {
			return api.Event{}, err
		}
		if launch.ID != scope.LaunchID || launch.Actor != scope.Actor || launch.Config != scope.Config || launch.Revoked ||
			launch.EndpointGeneration != scope.EndpointGeneration ||
			launch.Target.LifeID != scope.Actor.LifeID || launch.Target.Run == 0 {
			return api.Event{}, forbidden("org event requires the current authenticated L6 launch")
		}
		event.LifeID, event.Run = launch.Target.LifeID, launch.Target.Run
		event.ParentLifeID, event.RootLifeID = launch.ParentLifeID, launch.RootLifeID
		event.StarterChain, event.StarterEventSeq = append([]api.ID{}, launch.StarterChain...), launch.StarterEventSeq
	}
	return event, nil
}

func (s *Service) commit(ctx context.Context, scope api.Scope, operation api.ID, tx api.Transaction) (*api.RPCReply, error) {
	if err := contextFailure(ctx); err != nil {
		return nil, err
	}
	if err := api.ValidateTransactionShape(tx); err != nil {
		return nil, err
	}
	committed, err := s.deps.Store.Transact(ctx, tx)
	if err != nil {
		return nil, err
	}
	if committed.Operation.ID != operation {
		return nil, integrity("approval commit belongs to another operation")
	}
	if committed.Operation.Error != nil {
		return nil, committed.Operation.Error
	}
	if tx.Deferred == nil {
		if committed.Deferred != nil || committed.Reply == nil || committed.Operation.Status != "succeeded" {
			return nil, integrity("approval commit did not retain the required completion")
		}
		return committed.Reply, nil
	}
	if committed.Deferred == nil || *committed.Deferred != *tx.Deferred || committed.Reply != nil ||
		committed.Operation.Status != "pending" && committed.Operation.Status != "running" {
		return nil, integrity("approval commit did not retain the required completion")
	}
	// Only the outbox publisher may produce the application receipt. It owns the
	// per-org gate, durable marker, reconciliation and measured completion.
	return s.publicationReply(ctx, scope, operation, tx.Deferred)
}

func (s *Service) publicationReply(ctx context.Context, scope api.Scope, operation api.ID, deferred *api.DeferredReply) (*api.RPCReply, error) {
	receipt, err := s.deps.Store.AwaitReceipt(ctx, scope, requestKey(scope))
	if err != nil {
		return nil, operationFailure(err, operation)
	}
	if receipt.Config != scope.Config || receipt.Key != requestKey(scope) || receipt.Actor != scope.Actor || receipt.Operation.ID != operation {
		return nil, integrity("publication completion belongs to another operation")
	}
	if err := deferredReceipt(receipt, deferred); err != nil {
		return nil, err
	}
	if receipt.Reply == nil || receipt.Reply.Error == nil && receipt.Operation.Status != "succeeded" ||
		receipt.Reply.Error != nil && receipt.Operation.Status != "failed" && receipt.Operation.Status != "cancelled" {
		return nil, integrity("publication reply precedes durable operation completion")
	}
	return receipt.Reply, nil
}

func operationFailure(err error, operation api.ID) error {
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeDeadline && typed.Code != api.CodeUnavailable && typed.Code != api.CodeCancelled {
		return err
	}
	copy := *typed
	copy.OperationID = operation
	return &copy
}
