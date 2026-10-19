package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"laneboss.io/laneboss/internal/v2/api"
)

func operationError(err error, operation api.ID) error {
	var typed *api.Error
	if errors.As(err, &typed) {
		copy := *typed
		copy.OperationID = operation
		return &copy
	}
	code := api.CodeUnavailable
	if errors.Is(err, context.DeadlineExceeded) {
		code = api.CodeDeadline
	} else if errors.Is(err, context.Canceled) {
		code = api.CodeCancelled
	}
	return &api.Error{Code: code, Message: "policy operation could not commit",
		Instead: "Inspect the retained operation and retry with its original key.", OperationID: operation}
}

func decisionReply(reply *api.RPCReply) (api.PolicyDecision, error) {
	var result api.PolicyDecision
	if reply == nil || (reply.Error == nil) == (len(reply.Result) == 0) {
		return result, integrity("policy receipt has no unique typed reply")
	}
	if reply.Error != nil {
		return result, reply.Error
	}
	if api.DecodeObject(reply.Result, &result) != nil || !validID(result.ID) || !result.AuditComplete ||
		result.PolicyGeneration == 0 || !validID(result.Input.ID) || !validDigest(result.Input.SHA256) ||
		result.Input.Class != "judge_request" || result.Input.Bytes <= 0 || result.Input.Bytes > api.MaxObjectBytes ||
		(result.Result != "allow" && result.Result != "warn" && result.Result != "refuse") {
		return api.PolicyDecision{}, integrity("policy receipt has an invalid completed decision")
	}
	return result, nil
}

// The dispatcher reserves and authenticates before dispatch. This lookup binds
// the module's retained inputs/events to that actual operation and protects a
// completed retry from new source comparisons or inference.
func (s *Service) mutation(ctx context.Context, scope api.Scope, request api.PolicyEvaluateRequest) (api.MutationReceipt, error) {
	var empty api.MutationReceipt
	if scope.Request.Method != "policy.evaluate" || scope.Request.Config != scope.Config ||
		!validID(scope.Request.RequestID) || !validID(scope.Request.IdempotencyKey) || scope.Frame == nil {
		return empty, &api.Error{Code: api.CodePrerequisite, Message: "policy evaluation requires the reserved authenticated request",
			Instead: "Use the service dispatcher with the exact verified frame and retained retry key."}
	}
	if err := requestProof(scope); err != nil {
		return empty, err
	}
	digest, err := api.RequestDigest(scope.Request)
	if err != nil || digest != scope.Request.RequestSHA256 {
		return empty, integrity("policy request intent digest differs from authenticated envelope")
	}
	var framed api.Request
	if api.DecodeObject(scope.Frame.Bytes(), &framed) != nil {
		return empty, integrity("policy request lacks its exact verified frame")
	}
	frame, err := json.Marshal(framed)
	if err != nil {
		return empty, integrity("verified policy frame cannot be encoded")
	}
	envelope, err := json.Marshal(scope.Request)
	if err != nil {
		return empty, integrity("authenticated policy envelope cannot be encoded")
	}
	params, err := json.Marshal(request)
	if err != nil {
		return empty, invalid("policy request cannot be encoded")
	}
	wireParams, err := api.CanonicalJSON(scope.Request.Params)
	if err != nil {
		return empty, err
	}
	canonical, err := api.CanonicalJSON(params)
	if err != nil || !bytes.Equal(frame, envelope) || !bytes.Equal(wireParams, canonical) {
		return empty, integrity("policy request differs from the authenticated frame")
	}
	key := api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey, RequestSHA256: digest}
	receipt, err := s.deps.Store.LookupReceipt(ctx, scope, key)
	if err != nil {
		return empty, err
	}
	if receipt.Config != scope.Config || receipt.Key != key || receipt.Actor != scope.Actor || !validID(receipt.Operation.ID) {
		return empty, integrity("policy reservation differs from authenticated request")
	}
	if receipt.Reply == nil && receipt.Operation.Status != "running" && receipt.Operation.Status != "pending" {
		return empty, integrity("terminal policy operation lacks its retained typed reply")
	}
	if receipt.Reply == nil && !bytes.Equal(receipt.RawRequest, scope.Frame.Bytes()) {
		return empty, integrity("policy reservation did not retain the exact request")
	}
	return receipt, nil
}

// Preview proof shape and endpoint-class checks precede replay. A human uses
// its verified read session; policy.evaluate never consumes an operation proof.
func requestProof(scope api.Scope) error {
	proof := scope.Request.Proof
	if scope.Actor.Kind == "lane" && proof != nil {
		return &api.Error{Code: api.CodeForbidden, Message: "lane policy requests cannot carry human proof",
			Instead: "Use the lane's own policy scope without a human proof."}
	}
	if proof != nil && (!validID(proof.ID) || !validDigest(proof.RequestSHA256) || proof.RequestSHA256 != scope.Request.RequestSHA256) {
		return invalid("policy proof does not bind the exact operation")
	}
	if scope.Actor.Kind == "human" && proof != nil {
		return &api.Error{Code: api.CodeForbidden, Message: "human policy preview cannot consume an operation proof",
			Instead: "Establish human.session on this connection, then submit the preview without a proof."}
	}
	return nil
}
