package judge

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/typesafe"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/judge/wire"
	"laneboss.io/laneboss/internal/v2/objectread"
)

// CommitAudit is a trusted component completion, never a public RPC or a
// dispatch authorization. The store must authenticate its bound emitter and
// original persisted intent/claim. No call here sends to a provider. Until the
// dispatch/claim port exists, EvaluateForScope cannot produce that completion.
func (s *Service) CommitAudit(ctx context.Context, scope api.Scope, intent api.InternalIntent, request api.JudgeRequest, audit api.JudgeAudit) (api.JudgeReply, error) {
	// Completion uses current authority and must read its newly committed
	// projection, not the handler's pre-work pinned read snapshot.
	scope.ReadView = nil
	resolved, err := s.resolveRequest(ctx, scope, request)
	if err != nil {
		return api.JudgeReply{}, err
	}
	if !wire.ValidID(intent.ID) || intent.Kind != api.InternalJudgeEvaluate ||
		intent.Config != scope.Config || intent.Actor.Kind != "service" || !wire.ValidID(intent.Actor.ID) ||
		intent.RequestedBy != scope.Actor || !wire.ValidID(intent.CauseOperationID) ||
		!wire.ValidID(intent.CauseRequestID) || intent.Target != resolved.Context.Target ||
		intent.LogicalTurnID != resolved.Context.LogicalTurnID || audit.ID != resolved.ID ||
		audit.Reply.Request == nil || audit.Request != *audit.Reply.Request {
		return api.JudgeReply{}, problem(api.CodeIntegrity, "judge completion provenance differs")
	}
	started, startErr := time.Parse(time.RFC3339Nano, string(audit.StartedAt))
	completed, endErr := time.Parse(time.RFC3339Nano, string(audit.CompletedAt))
	if startErr != nil || endErr != nil || completed.Before(started) || completed.After(s.deps.Clock.Now()) {
		return api.JudgeReply{}, problem(api.CodeIntegrity, "judge audit times differ")
	}
	lane, err := s.deps.Store.Lane(ctx, scope, resolved.Context.Target)
	if err != nil {
		return api.JudgeReply{}, err
	}
	grants, err := s.deps.Store.Grants(ctx, resolved.Context.GrantSetID)
	if err != nil {
		return api.JudgeReply{}, err
	}
	if lane.LifeID != intent.Target.LifeID || lane.Run != intent.Target.Run || lane.LogicalTurnID != intent.LogicalTurnID ||
		lane.GrantSetID != resolved.Context.GrantSetID || lane.Generation == 0 ||
		lane.Level != resolved.Context.Role.Level || lane.Role != resolved.Context.Role.Role || lane.Workspace.LogicalCWD != resolved.Context.CWD ||
		lane.CancellationEpoch != intent.CancellationEpoch || lane.PolicyGeneration != scope.PolicyGeneration ||
		grants.ID != resolved.Context.GrantSetID || grants.Generation == 0 ||
		grants.PolicyGeneration != scope.PolicyGeneration || grants.SHA256 != resolved.Context.GrantsSHA256 || grants.Revoked {
		return api.JudgeReply{}, problem(api.CodeConflict, "judge completion snapshot changed")
	}
	body, _, err := wire.Payload(resolved)
	if err != nil {
		return api.JudgeReply{}, err
	}
	retained, err := s.auditObject(ctx, scope, resolved.Context.Target, audit.Request, "judge_request", api.MaxJudgeBytes)
	if err != nil {
		return api.JudgeReply{}, err
	}
	if !bytes.Equal(retained, body) {
		return api.JudgeReply{}, problem(api.CodeIntegrity, "judge audit request bytes differ")
	}
	var raw []byte
	if audit.Reply.Raw != nil {
		raw, err = s.auditObject(ctx, scope, resolved.Context.Target, *audit.Reply.Raw, "judge_raw", wire.MaxResponseBytes)
		if err != nil {
			return api.JudgeReply{}, err
		}
	}
	if err := wire.AuditReply(audit.Reply, resolved, audit.Fit, raw); err != nil {
		return api.JudgeReply{}, err
	}
	payload, err := json.Marshal(audit.Reply)
	if err != nil {
		return api.JudgeReply{}, problem(api.CodeIntegrity, "judge audit cannot be encoded")
	}
	decoded, err := typesafe.Decode(payload)
	if err != nil || wire.SensitiveStrings(decoded, "") {
		return api.JudgeReply{}, problem(api.CodeIntegrity, "judge completion metadata is not screened")
	}
	// Internal completion writes have no RPCReply. Public judge.ask has an
	// empty write row and its dispatcher must commit the final typed reply.
	internalScope := scope
	internalScope.Request, internalScope.ReadView = api.Request{}, nil
	event := api.Event{Schema: api.SchemaVersion, ID: intent.ID, Config: scope.Config,
		Kind: "judge.completed", Actor: intent.Actor, RequestedBy: intent.RequestedBy,
		RequestID: intent.CauseRequestID, OperationID: intent.CauseOperationID,
		LifeID: lane.LifeID, Run: lane.Run, LogicalTurnID: lane.LogicalTurnID,
		ParentLifeID: lane.ParentLifeID, RootLifeID: lane.RootLifeID,
		StarterChain: append([]api.ID{}, lane.StarterChain...), StarterEventSeq: lane.StarterEventSeq,
		RecordedAt: audit.CompletedAt, RequestedAt: audit.StartedAt, ObservedAt: audit.CompletedAt,
		Origin: "service", Payload: payload}
	transaction := api.Transaction{Scope: internalScope, Internal: &intent,
		Writes: api.StateWrites{JudgeAudits: []api.JudgeAudit{audit}}, Events: []api.Event{event},
		Compare: []api.Compare{{Kind: api.CompareLane, ID: lane.LifeID, Generation: lane.Generation},
			{Kind: api.CompareGrants, ID: grants.ID, Generation: grants.Generation}},
		Guards: []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: lane.LifeID, Epoch: lane.CancellationEpoch}}}}
	if err := api.ValidateTransactionShape(transaction); err != nil {
		return api.JudgeReply{}, err
	}
	commit, err := s.deps.Store.Transact(ctx, transaction)
	if err != nil {
		return api.JudgeReply{}, err
	}
	if commit.Operation.Error != nil {
		return api.JudgeReply{}, commit.Operation.Error
	}
	if commit.Operation.Status != "succeeded" || commit.Reply != nil || commit.LastSeq < commit.FirstSeq {
		return api.JudgeReply{}, problem(api.CodeIntegrity, "judge audit did not commit durably")
	}
	// Read the committed projection, including the store's provenance checks;
	// do not publish an in-memory executor report as an accepted observation.
	stored, err := s.deps.Store.JudgeAudit(ctx, scope, audit.ID)
	if err != nil {
		return api.JudgeReply{}, err
	}
	if !reflect.DeepEqual(stored, audit) {
		return api.JudgeReply{}, problem(api.CodeIntegrity, "committed judge audit differs")
	}
	return cloneReply(stored.Reply), nil
}

func (s *Service) auditObject(ctx context.Context, scope api.Scope, target api.LifeRef, ref api.BlobRef, class string, bound int) (result []byte, resultErr error) {
	if !wire.ValidID(ref.ID) || !wire.ValidDigest(ref.SHA256) || ref.Class != class || ref.Bytes < 1 || ref.Bytes > int64(bound) {
		return nil, problem(api.CodeIntegrity, "judge audit object reference differs")
	}
	scope, release, err := objectread.Bind(ctx, s.deps.Store, scope)
	if err != nil {
		return nil, err
	}
	defer release(&resultErr)
	metadata, err := s.deps.Store.ObjectMetadata(ctx, scope, ref.ID)
	if err != nil {
		return nil, err
	}
	if metadata.Ref != ref || metadata.ACL.Config != scope.Config ||
		metadata.ACL.LifeID != "" && metadata.ACL.LifeID != target.LifeID {
		return nil, problem(api.CodeIntegrity, "judge audit object metadata differs")
	}
	data := make([]byte, 0, int(ref.Bytes))
	for int64(len(data)) < ref.Bytes {
		offset := int64(len(data))
		limit := min(api.MaxChunkBytes, int(ref.Bytes-offset))
		chunk, err := s.deps.Store.Blob(ctx, scope, api.BlobReadRequest{ObjectID: ref.ID, Offset: offset, Limit: limit})
		if err != nil {
			return nil, err
		}
		if chunk.ObjectID != ref.ID || chunk.Offset != offset || len(chunk.Data) != limit || chunk.SHA256 != wire.Digest(chunk.Data) {
			return nil, problem(api.CodeIntegrity, "judge audit chunk differs")
		}
		data = append(data, chunk.Data...)
	}
	if wire.Digest(data) != ref.SHA256 {
		return nil, problem(api.CodeIntegrity, "judge audit object bytes differ")
	}
	root, err := typesafe.Decode(data)
	if err != nil {
		return nil, problem(api.CodeIntegrity, "judge audit object is not screened JSON")
	}
	sensitive := false
	if class == "judge_request" {
		sensitive = wire.RequestSensitive(root, "")
	} else {
		sensitive = wire.SensitiveResponse(root, "")
	}
	if sensitive {
		return nil, problem(api.CodeIntegrity, "judge audit object is not screened JSON")
	}
	return data, nil
}
