package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/objectread"
)

func retentionIntent(scope api.Scope, target api.LifeRef, turn, operation api.ID) (api.InternalIntent, error) {
	id, err := newID("retain")
	if err != nil {
		return api.InternalIntent{}, err
	}
	return api.InternalIntent{ID: id, Kind: api.InternalObjectRetain, Config: scope.Config,
		Actor: api.Actor{Kind: "service", ID: "lb-v2-policy"}, RequestedBy: scope.Actor,
		CauseRequestID: scope.Request.RequestID, CauseOperationID: operation,
		Target: target, LogicalTurnID: turn}, nil
}

func (s *Service) put(ctx context.Context, scope api.Scope, intent api.InternalIntent, class string, data []byte, inputs []api.BlobRef) (result api.BlobRef, resultErr error) {
	var empty api.BlobRef
	if len(data) == 0 || len(data) > api.MaxObjectBytes {
		return empty, invalid("policy object exceeds retained byte bound")
	}
	want := digestBytes(data)
	// This is the trusted store port, never public blob staging under the
	// parent policy request's idempotency key. The requester is preserved.
	object := api.ObjectWrite{ObjectKey: intent.ID, Class: class, Bytes: append([]byte{}, data...),
		SHA256: want, Origin: "service", InputRefs: append([]api.BlobRef{}, inputs...),
		ACL: api.ObjectACL{Config: scope.Config, Owner: scope.Actor, LifeID: intent.Target.LifeID,
			Audience: "owner", Participants: []api.ID{}, Generation: 1}}
	ref, err := s.deps.Store.RetainObject(ctx, scope, api.RetainObjectRequest{Intent: intent, Object: object})
	if err != nil {
		return empty, err
	}
	if !validID(ref.ID) || ref.SHA256 != want || ref.Bytes != int64(len(data)) || ref.Class != class {
		return empty, integrity("protected policy object receipt differs from input")
	}
	var release func(*error)
	// The handler's stable input view predates this committed object. Read the
	// output through a fresh authenticated view, retaining its exact byte pin.
	scope.ReadView = nil
	scope, release, err = objectread.Bind(ctx, s.deps.Store, scope)
	if err != nil {
		return empty, err
	}
	defer release(&resultErr)
	metadata, err := s.deps.Store.ObjectMetadata(ctx, scope, ref.ID)
	if err != nil {
		return empty, err
	}
	validCause := metadata.SourceOperationID == intent.CauseOperationID
	if intent.CauseOperationID == "" && scope.Request.Method == "config.read" && validID(metadata.SourceOperationID) {
		expected, causeErr := api.ReadProjectionOperationID(scope, object)
		validCause = causeErr == nil && expected == metadata.SourceOperationID
	}
	if metadata.Ref != ref || metadata.Origin != object.Origin || !validCause ||
		metadata.ACL.Config != scope.Config || metadata.ACL.Owner != scope.Actor ||
		metadata.ACL.LifeID != object.ACL.LifeID || metadata.ACL.Audience != object.ACL.Audience ||
		metadata.ACL.Generation == 0 || len(metadata.ACL.Participants) != 0 {
		return empty, integrity("protected policy object metadata differs from retention intent")
	}
	// A hash-shaped receipt alone is not evidence that the bytes were retained.
	for offset := 0; offset < len(data); {
		end := min(offset+api.MaxChunkBytes, len(data))
		chunk, err := s.deps.Store.Blob(ctx, scope, api.BlobReadRequest{
			ObjectID: ref.ID, Offset: int64(offset), Limit: end - offset,
		})
		if err != nil {
			return empty, err
		}
		if chunk.ObjectID != ref.ID || chunk.Offset != int64(offset) || len(chunk.Data) == 0 ||
			len(chunk.Data) > end-offset || chunk.SHA256 != digestBytes(chunk.Data) ||
			!bytes.Equal(chunk.Data, data[offset:offset+len(chunk.Data)]) {
			return empty, integrity("protected policy object read-back mismatch")
		}
		offset += len(chunk.Data)
	}
	end, err := s.deps.Store.Blob(ctx, scope, api.BlobReadRequest{ObjectID: ref.ID, Offset: ref.Bytes, Limit: 1})
	if err != nil {
		return empty, err
	}
	if end.ObjectID != ref.ID || end.Offset != ref.Bytes || len(end.Data) != 0 || end.SHA256 != digestBytes([]byte{}) {
		return empty, integrity("protected policy object has an unreported suffix")
	}
	return ref, nil
}

func (s *Service) audit(ctx context.Context, scope api.Scope, snapshot api.OrgSnapshotRef, lane api.Lane, grants api.GrantSet, operation api.ID, started time.Time, decision api.PolicyDecision) (api.PolicyDecision, error) {
	decision.AuditComplete = true
	payload, err := json.Marshal(decision)
	if err != nil {
		return api.PolicyDecision{}, integrity("policy decision cannot be encoded")
	}
	eventID, err := newID("event")
	if err != nil {
		return api.PolicyDecision{}, err
	}
	now := api.Timestamp(s.deps.Clock.Now().UTC().Format(time.RFC3339Nano))
	event := api.Event{
		Schema: api.SchemaVersion, ID: eventID, Config: scope.Config, Kind: "policy.evaluated",
		Actor: scope.Actor, RequestedBy: scope.Actor, RequestID: scope.Request.RequestID,
		OperationID: operation, LifeID: lane.LifeID, Run: lane.Run,
		LogicalTurnID: lane.LogicalTurnID, ParentLifeID: lane.ParentLifeID,
		RootLifeID: lane.RootLifeID, StarterChain: append([]api.ID{}, lane.StarterChain...),
		StarterEventSeq: lane.StarterEventSeq, RequestedAt: api.Timestamp(started.UTC().Format(time.RFC3339Nano)), ObservedAt: now,
		Origin: "service", Payload: payload,
	}
	commit, err := s.deps.Store.Transact(ctx, api.Transaction{
		Scope: scope, RawRequest: append([]byte{}, scope.Frame.Bytes()...),
		Reply:  &api.RPCReply{Result: append(json.RawMessage{}, payload...)},
		Guards: []api.TransactionGuard{},
		Compare: []api.Compare{
			{Kind: api.CompareOrg, ID: snapshot.OrgID, Generation: snapshot.Generation},
			{Kind: api.CompareLane, ID: lane.LifeID, Generation: lane.Generation},
			{Kind: api.CompareGrants, ID: grants.ID, Generation: grants.Generation},
		},
		Events: []api.Event{event}, Effects: []api.Effect{},
	})
	if err != nil {
		// The mutation requires a durable typed reply. An uncommitted ordinary allow
		// cannot be returned as a successful synchronous mutation or cached.
		return api.PolicyDecision{}, operationError(err, operation)
	}
	if commit.Operation.ID != operation {
		return api.PolicyDecision{}, integrity("policy commit belongs to another reserved operation")
	}
	if commit.Replayed {
		return decisionReply(commit.Reply)
	}
	if commit.FirstSeq == 0 || commit.LastSeq < commit.FirstSeq || commit.Operation.Status != "succeeded" {
		return api.PolicyDecision{}, integrity("policy audit lacks a durable event sequence")
	}
	if commit.Reply == nil || commit.Reply.Error != nil || !bytes.Equal(commit.Reply.Result, payload) {
		return api.PolicyDecision{}, integrity("policy commit differs from its exact typed reply")
	}
	return decisionReply(commit.Reply)
}
