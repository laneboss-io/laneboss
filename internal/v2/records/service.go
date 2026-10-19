// Package records serves scoped records without opening any client-selected DB
// or executing a parser, embedding model, cloud command or repository program.
package records

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/credentialtext"
	"laneboss.io/laneboss/internal/v2/api"
)

type Dependencies struct {
	Store     api.StateStore
	Worker    api.DataWorker
	Clock     api.Clock
	Records   api.RecordWorker
	Resources api.ResourceWorker
}

type Service struct{ deps Dependencies }

func New(deps Dependencies) (*Service, error) {
	if deps.Store == nil || deps.Clock == nil {
		return nil, &api.Error{Code: api.CodePrerequisite, Message: "records requires a service-owned store and clock", Instead: "Configure the composition root; no local database fallback is available."}
	}
	return &Service{deps: deps}, nil
}

var _ api.IntegrateAPI = (*Service)(nil)
var _ api.Module = (*Service)(nil)

func (s *Service) Register(registry api.Registrar) error {
	if registry == nil {
		return integrity("records registrar is missing")
	}
	entries := []struct {
		method  api.Method
		handler api.Handler
	}{
		{"records.query", typed(s.RecordsQuery)},
		{"records.get", typed(s.RecordsGet)},
		{"records.append", typed(s.RecordsAppend)},
		{"decisions.mutate", typed(s.DecisionsMutate)},
		{"records.import", typed(s.RecordsImport)},
		{"records.export", typed(s.RecordsExport)},
		{"box.launch", typed(s.BoxLaunch)},
		{"box.run", typed(s.BoxRun)},
		{"box.harvest", typed(s.BoxHarvest)},
		{"box.end", typed(s.BoxEnd)},
		{"box.list", typed(s.BoxList)},
	}
	for _, entry := range entries {
		if err := registry.Register(entry.method, entry.handler); err != nil {
			return err
		}
	}
	return nil
}

func typed[Request, Result any](call func(context.Context, api.Scope, Request) (Result, error)) api.Handler {
	return func(ctx context.Context, scope api.Scope, raw json.RawMessage) (json.RawMessage, error) {
		var request Request
		if err := api.DecodeObject(raw, &request); err != nil {
			return nil, err
		}
		result, err := call(ctx, scope, request)
		if err != nil {
			return nil, err
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			return nil, integrity("record result could not be encoded")
		}
		return encoded, nil
	}
}

func (s *Service) RecordsQuery(ctx context.Context, scope api.Scope, request api.RecordQuery) (api.RecordPage, error) {
	if err := authorizeScope(ctx, scope); err != nil {
		return api.RecordPage{}, err
	}
	if err := ValidateQueryInput(request); err != nil {
		return api.RecordPage{}, err
	}
	var page api.RecordPage
	var err error
	if request.SearchMode == "keyword" {
		page, err = s.deps.Store.Records(ctx, scope, request)
	} else {
		if s.deps.Records == nil {
			return api.RecordPage{}, api.NotImplemented("lb-v2-integrate", "confined record search")
		}
		page, err = s.deps.Records.Search(ctx, scope, request)
	}
	if err != nil {
		return api.RecordPage{}, err
	}
	if page.Records == nil || len(page.Records) > request.Limit {
		return api.RecordPage{}, integrity("record backend returned an invalid page")
	}
	for _, record := range page.Records {
		if request.RecordID != "" && record.ID != request.RecordID ||
			request.Collection != "" && record.Collection != request.Collection ||
			request.LifeID != "" && record.LifeID != request.LifeID {
			return api.RecordPage{}, integrity("record backend ignored a scope filter")
		}
		if err := validateRecord(record); err != nil {
			return api.RecordPage{}, err
		}
	}
	return page, nil
}

func (s *Service) RecordsGet(ctx context.Context, scope api.Scope, request api.RecordGetRequest) (api.Record, error) {
	if err := ValidateGetInput(request); err != nil {
		return api.Record{}, err
	}
	page, err := s.RecordsQuery(ctx, scope, api.RecordQuery{
		RecordID: request.RecordID, SearchMode: "keyword", Limit: 1,
	})
	if err != nil {
		return api.Record{}, err
	}
	if len(page.Records) == 0 {
		return api.Record{}, &api.Error{Code: api.CodeNotFound, Message: "record is absent or not visible", Instead: "Use a record visible in the current configuration and life."}
	}
	if page.Cursor != "" {
		return api.Record{}, integrity("record ID did not select one unique object")
	}
	return page.Records[0], nil
}

func (s *Service) RecordsAppend(ctx context.Context, scope api.Scope, request api.RecordAppendRequest) (api.Record, error) {
	if err := mutationScope(ctx, scope, "records.append"); err != nil {
		return api.Record{}, err
	}
	if err := ValidateAppendInput(request); err != nil {
		return api.Record{}, err
	}
	if !collection(request.Collection) {
		return api.Record{}, invalid("unknown record collection")
	}
	// Collection spelling never grants service/worker provenance. Canonical
	// decisions require verified human/D6; ledger/archive/coverage facts have
	// their own trusted outside emitters. Reports here remain observations.
	if request.Collection != "observations" && request.Collection != "reports" {
		return api.Record{}, &api.Error{Code: api.CodeForbidden, Message: "this collection requires its authoritative service operation", Instead: "Submit an observation or report upward; use human approval or D6 for canonical decisions."}
	}
	if len(request.RelatedIDs) > 200 {
		return api.Record{}, invalid("too many related records")
	}
	for _, id := range request.RelatedIDs {
		if _, err := s.RecordsGet(ctx, scope, api.RecordGetRequest{RecordID: id}); err != nil {
			return api.Record{}, err
		}
	}
	if err := s.screenBlob(ctx, scope, request.Content); err != nil {
		return api.Record{}, err
	}
	record := api.Record{
		ID: stableID(scope, "record"), Collection: request.Collection,
		LifeID: scope.Actor.LifeID, Content: request.Content, Actor: scope.Actor,
		Origin: "observation", RecordedAt: api.Timestamp(s.deps.Clock.Now().UTC().Format(time.RFC3339Nano)),
		Generation: 1, RelatedIDs: append([]api.ID(nil), request.RelatedIDs...),
	}
	if scope.Actor.Kind == "lane" {
		lane, err := s.deps.Store.Lane(ctx, scope, api.LifeRef{LifeID: scope.Actor.LifeID})
		if err != nil {
			return api.Record{}, err
		}
		record.Run = lane.Run
	}
	return s.commitRecord(ctx, scope, record, "record.appended", nil, nil, nil)
}

func (s *Service) DecisionsMutate(ctx context.Context, scope api.Scope, request api.DecisionMutateRequest) (api.Record, error) {
	if err := mutationScope(ctx, scope, "decisions.mutate"); err != nil {
		return api.Record{}, err
	}
	switch request.Action {
	case "add", "supersede", "annotate", "feedback", "embed":
	default:
		return api.Record{}, invalid("unknown decision action")
	}
	if err := ValidateDecisionInput(request); err != nil {
		return api.Record{}, err
	}
	if scope.Actor.Kind != "human" || scope.Request.Proof == nil {
		return api.Record{}, &api.Error{Code: api.CodeForbidden, Message: "canonical decisions require verified human approval or an approved L6 D6 change", Instead: "Send an inert proposal up the direct report line; L6 uses org change propose/approve/apply."}
	}
	if retained, found, err := s.replayDecision(ctx, scope, request); found || err != nil {
		return retained, err
	}
	// The dispatcher verifies/consumes the operation proof under the commit
	// lock. An L6 actor alone or a read session is never a decision approval.
	if request.Action == "embed" {
		return api.Record{}, api.NotImplemented("lb-v2-integrate", "confined decision embedding")
	}
	content, err := s.readScreenedBlob(ctx, scope, request.Content)
	if err != nil {
		return api.Record{}, err
	}
	record := api.Record{
		ID: stableID(scope, "decision"), Collection: "decisions", Content: request.Content,
		Actor: scope.Actor, Origin: "service", Generation: 1, Action: request.Action,
		RecordedAt: api.Timestamp(s.deps.Clock.Now().UTC().Format(time.RFC3339Nano)),
	}
	var compares []api.Compare
	var projections []api.DecisionProjection
	var superseded *api.Record
	if request.Action == "add" {
		if request.RecordID != "" || request.ExpectedGeneration != 0 {
			return api.Record{}, invalid("new decision requires an absent base")
		}
		compares = []api.Compare{{Kind: api.CompareRecord, ID: record.ID, Generation: 0}}
	} else {
		prior, err := s.RecordsGet(ctx, scope, api.RecordGetRequest{RecordID: request.RecordID})
		if err != nil {
			return api.Record{}, err
		}
		if prior.Collection != "decisions" || request.ExpectedGeneration == 0 || request.ExpectedGeneration >= 1<<53-1 {
			return api.Record{}, invalid("decision change requires a canonical decision and base generation")
		}
		projection, err := s.deps.Store.Decision(ctx, scope, prior.ID)
		if err != nil {
			return api.Record{}, err
		}
		if projection.RecordID != prior.ID || projection.Candidate.ID != prior.ID || projection.Status != "active" && projection.Status != "superseded" {
			return api.Record{}, integrity("decision projection differs from its canonical record")
		}
		if request.Action == "supersede" {
			if projection.Status != "active" {
				return api.Record{}, &api.Error{Code: api.CodeConflict, Message: "decision is already superseded", Instead: "Review the active replacement before proposing a new decision."}
			}
			// Keep the old content/provenance and advance its generation in the
			// same commit. A second supersession cannot pass the old record CAS.
			prior.Generation, prior.Action = request.ExpectedGeneration+1, "superseded"
			superseded = &prior
			projection.Status = "superseded"
			projections = append(projections, projection)
			record.RelatedIDs = []api.ID{prior.ID}
		} else {
			record = prior
			record.RecordedAt = api.Timestamp(s.deps.Clock.Now().UTC().Format(time.RFC3339Nano))
			record.Generation, record.Action = request.ExpectedGeneration+1, request.Action
			record.Annotations = append([]api.BlobRef(nil), prior.Annotations...)
			record.Feedback = append([]api.BlobRef(nil), prior.Feedback...)
			projections = append(projections, projection)
		}
		if request.Action == "annotate" {
			record.Content = prior.Content
			record.Annotations = append(record.Annotations, request.Content)
		} else if request.Action == "feedback" {
			record.Content = prior.Content
			record.Feedback = append(record.Feedback, request.Content)
		}
		if len(record.Annotations)+len(record.Feedback) > 200 {
			return api.Record{}, invalid("decision metadata requires a bounded revision")
		}
		compares = []api.Compare{{Kind: api.CompareRecord, ID: prior.ID, Generation: request.ExpectedGeneration}}
		if request.Action == "supersede" {
			compares = append(compares, api.Compare{Kind: api.CompareRecord, ID: record.ID, Generation: 0})
		}
	}
	if request.Action == "add" || request.Action == "supersede" {
		candidate, err := decisionCandidate(scope, record, content)
		if err != nil {
			return api.Record{}, err
		}
		projection := api.DecisionProjection{RecordID: record.ID, Candidate: candidate, Status: "active"}
		if superseded != nil {
			projection.SupersedesID = superseded.ID
		}
		projections = append(projections, projection)
	}
	return s.commitRecord(ctx, scope, record, "decision.changed", compares, projections, superseded)
}

func (s *Service) commitRecord(ctx context.Context, scope api.Scope, record api.Record, kind api.EventKind, compares []api.Compare, decisions []api.DecisionProjection, superseded *api.Record) (api.Record, error) {
	payload, err := json.Marshal(record)
	if err != nil {
		return api.Record{}, integrity("record payload could not be encoded")
	}
	now := api.Timestamp(s.deps.Clock.Now().UTC().Format(time.RFC3339Nano))
	event := api.Event{
		Schema: api.SchemaVersion, ID: stableID(scope, "event"), Config: scope.Config,
		Kind: kind, Actor: scope.Actor, RequestedBy: scope.Actor,
		RequestID: scope.Request.RequestID, OperationID: stableID(scope, "operation"),
		LifeID: record.LifeID, Run: record.Run, StarterChain: []api.ID{},
		RecordedAt: now, RequestedAt: now,
		ObservedAt: now, Origin: record.Origin, Payload: payload,
	}
	if record.LifeID != "" {
		lane, err := s.deps.Store.Lane(ctx, scope, api.LifeRef{LifeID: record.LifeID, Run: record.Run})
		if err != nil {
			return api.Record{}, err
		}
		event.ParentLifeID, event.RootLifeID = lane.ParentLifeID, lane.RootLifeID
		event.StarterChain = append([]api.ID{}, lane.StarterChain...)
		event.StarterEventSeq = lane.StarterEventSeq
	}
	transaction := api.Transaction{
		Scope: scope, Compare: compares, Events: []api.Event{event}, Reply: &api.RPCReply{Result: payload},
		Writes: api.StateWrites{Decisions: decisions},
	}
	if superseded != nil {
		priorEvent := event
		priorEvent.ID = stableID(scope, "event-superseded")
		priorEvent.Payload, err = json.Marshal(superseded)
		if err != nil {
			return api.Record{}, integrity("superseded record could not be encoded")
		}
		transaction.Events = []api.Event{priorEvent, event}
	}
	if scope.Frame != nil {
		transaction.RawRequest = append([]byte(nil), scope.Frame.Bytes()...)
	}
	if scope.Actor.Kind == "human" {
		target, err := s.deps.Store.AuthorizationTarget(ctx, scope, scope.Request)
		if err != nil {
			return api.Record{}, err
		}
		if scope.Request.Proof == nil {
			return api.Record{}, invalid("human record transaction lacks an operation proof")
		}
		transaction.Guards = []api.TransactionGuard{{Proof: &api.ProofUse{Proof: *scope.Request.Proof, Target: target}}}
	}
	commit, err := s.deps.Store.Transact(ctx, transaction)
	if err != nil {
		return api.Record{}, err
	}
	if commit.Operation.Error != nil {
		return api.Record{}, commit.Operation.Error
	}
	if commit.Operation.Status != "succeeded" {
		return api.Record{}, integrity("record transaction did not finish durably")
	}
	// A projection may have a newer generation. Return the original durable
	// receipt on replay, never that projection or a fresh in-memory proposal.
	if commit.Reply == nil {
		return api.Record{}, integrity("record transaction omitted its durable receipt")
	}
	if commit.Reply.Error != nil {
		return api.Record{}, commit.Reply.Error
	}
	var retained api.Record
	if err := api.DecodeObject(commit.Reply.Result, &retained); err != nil {
		return api.Record{}, integrity("record transaction returned an invalid typed receipt")
	}
	if retained.ID != record.ID {
		return api.Record{}, integrity("record transaction returned an unrelated receipt")
	}
	if err := validateRecord(retained); err != nil {
		return api.Record{}, err
	}
	return retained, nil
}

func (s *Service) screenBlob(ctx context.Context, scope api.Scope, ref api.BlobRef) error {
	_, err := s.readScreenedBlob(ctx, scope, ref)
	return err
}

func (s *Service) readScreenedBlob(ctx context.Context, scope api.Scope, ref api.BlobRef) ([]byte, error) {
	if err := validateContentRef(ref); err != nil {
		return nil, err
	}
	if !validID(ref.ID) || !validDigest(ref.SHA256) || ref.Bytes < 1 || ref.Bytes > api.MaxJudgeBytes || ref.Class != "record" && ref.Class != "report" {
		return nil, invalid("record content must reference bounded committed text")
	}
	metadata, err := s.deps.Store.ObjectMetadata(ctx, scope, ref.ID)
	if err != nil {
		return nil, err
	}
	if metadata.Ref != ref {
		return nil, integrity("record reference differs from committed object metadata")
	}
	chunk, err := s.deps.Store.Blob(ctx, scope, api.BlobReadRequest{ObjectID: ref.ID, Limit: int(ref.Bytes)})
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(chunk.Data)
	if chunk.ObjectID != ref.ID || chunk.Offset != 0 || int64(len(chunk.Data)) != ref.Bytes || api.Digest(hex.EncodeToString(sum[:])) != ref.SHA256 || chunk.SHA256 != ref.SHA256 {
		return nil, integrity("committed record content hash or size mismatch")
	}
	if !utf8.Valid(chunk.Data) {
		return nil, invalid("record content must be UTF-8 text")
	}
	for _, b := range chunk.Data {
		if b < 0x20 && b != '\n' && b != '\r' && b != '\t' || b == 0x7f {
			return nil, invalid("record content contains binary control bytes")
		}
	}
	if credentialtext.HasCredential(string(chunk.Data)) {
		return nil, &api.Error{Code: api.CodeForbidden, Message: "record content contains a credential shape", Instead: "Use names-only evidence; store secret values through the protected secret workflow."}
	}
	return append([]byte(nil), chunk.Data...), nil
}

func decisionCandidate(scope api.Scope, record api.Record, content []byte) (api.DecisionCandidate, error) {
	document := api.DecisionDocument{Text: string(content), EffectiveAt: record.RecordedAt,
		AppliesTo: api.DecisionApplicability{Levels: []int{}, Roles: []string{}, ProjectIDs: []api.ID{}, LifeIDs: []api.ID{}}}
	trimmed := bytes.TrimSpace(content)
	if len(trimmed) == 0 {
		return api.DecisionCandidate{}, invalid("decision text is empty")
	}
	if trimmed[0] == '{' || trimmed[0] == '[' {
		if err := api.DecodeObject(content, &document); err != nil {
			return api.DecisionCandidate{}, err
		}
		if document.Schema != "laneboss.decision.v2" || len(bytes.TrimSpace([]byte(document.Text))) == 0 {
			return api.DecisionCandidate{}, invalid("invalid structured decision schema or text")
		}
		if _, err := time.Parse(time.RFC3339Nano, string(document.EffectiveAt)); err != nil {
			return api.DecisionCandidate{}, invalid("invalid decision effective time")
		}
		applies := document.AppliesTo
		if len(applies.Levels)+len(applies.Roles)+len(applies.ProjectIDs)+len(applies.LifeIDs) > 200 {
			return api.DecisionCandidate{}, invalid("decision applicability is too large")
		}
		for _, level := range applies.Levels {
			if level < 3 || level > 6 {
				return api.DecisionCandidate{}, invalid("invalid decision level")
			}
		}
		for _, role := range applies.Roles {
			if !validID(api.ID(role)) {
				return api.DecisionCandidate{}, invalid("invalid decision role")
			}
		}
		for _, id := range append(append([]api.ID(nil), applies.ProjectIDs...), applies.LifeIDs...) {
			if !validID(id) {
				return api.DecisionCandidate{}, invalid("invalid decision applicability ID")
			}
		}
	}
	for _, char := range document.Text {
		if char < 0x20 && char != '\n' && char != '\r' && char != '\t' || char == 0x7f {
			return api.DecisionCandidate{}, invalid("decision text contains binary control bytes")
		}
	}
	if credentialtext.HasCredential(document.Text) {
		return api.DecisionCandidate{}, &api.Error{Code: api.CodeForbidden, Message: "decoded decision text contains a credential shape", Instead: "Use names-only decision text and the protected secret workflow."}
	}
	return api.DecisionCandidate{ID: record.ID, Text: document.Text, Binding: document.Binding,
		EffectiveAt: document.EffectiveAt, AppliesTo: document.AppliesTo,
		Source:    api.SourceRef{ID: record.ID, SHA256: record.Content.SHA256, Generation: record.Generation},
		Authority: api.DecisionAuthority{Kind: "human", ReceiptID: scope.Request.Proof.ID}}, nil
}

func (s *Service) replayDecision(ctx context.Context, scope api.Scope, request api.DecisionMutateRequest) (api.Record, bool, error) {
	key := api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey, RequestSHA256: scope.Request.RequestSHA256}
	receipt, err := s.deps.Store.LookupReceipt(ctx, scope, key)
	if err != nil {
		var typed *api.Error
		if errors.As(err, &typed) && typed.Code == api.CodeNotFound {
			return api.Record{}, false, nil
		}
		return api.Record{}, false, err
	}
	if !receiptMatches(scope, key, receipt) {
		return api.Record{}, true, integrity("decision receipt belongs to another request or principal")
	}
	if receipt.Operation.Status == "pending" || receipt.Operation.Status == "running" {
		receipt, err = s.deps.Store.AwaitReceipt(ctx, scope, key)
		if err != nil {
			return api.Record{}, true, err
		}
		if !receiptMatches(scope, key, receipt) {
			return api.Record{}, true, integrity("decision receipt belongs to another request or principal")
		}
	}
	if receipt.Reply == nil {
		return api.Record{}, true, integrity("decision receipt omitted its durable reply")
	}
	if receipt.Reply.Error != nil {
		return api.Record{}, true, receipt.Reply.Error
	}
	expected := request.RecordID
	if request.Action == "add" || request.Action == "supersede" {
		expected = stableID(scope, "decision")
	}
	var record api.Record
	if err := api.DecodeObject(receipt.Reply.Result, &record); err != nil || record.ID != expected {
		return api.Record{}, true, integrity("decision receipt returned an unrelated record")
	}
	return record, true, validateRecord(record)
}

func receiptMatches(scope api.Scope, key api.RequestKey, receipt api.MutationReceipt) bool {
	return receipt.Config == scope.Config && receipt.Key == key && receipt.Actor.Kind == scope.Actor.Kind &&
		receipt.Actor.ID == scope.Actor.ID && receipt.Actor.LifeID == scope.Actor.LifeID
}

func authorizeScope(ctx context.Context, scope api.Scope) error {
	if err := ctx.Err(); err != nil {
		code := api.CodeCancelled
		if errors.Is(err, context.DeadlineExceeded) {
			code = api.CodeDeadline
		}
		return &api.Error{Code: code, Message: "record operation cancelled", Instead: "Inspect the durable operation before retrying with the same key."}
	}
	if scope.Config == "" || !validID(scope.Actor.ID) || scope.Actor.Kind != "human" && scope.Actor.Kind != "lane" {
		return &api.Error{Code: api.CodeUnauthenticated, Message: "record operation requires an authenticated scope", Instead: "Use the installed endpoint for this configuration and life."}
	}
	if scope.Actor.Kind == "lane" && (!validID(scope.Actor.LifeID) || scope.Actor.Level < 3 || scope.Actor.Level > 6) {
		return &api.Error{Code: api.CodeUnauthenticated, Message: "record operation requires a current lane life", Instead: "Use the service-launched lane endpoint."}
	}
	return nil
}

func mutationScope(ctx context.Context, scope api.Scope, method api.Method) error {
	if err := authorizeScope(ctx, scope); err != nil {
		return err
	}
	request := scope.Request
	if request.Config != scope.Config || request.Protocol != api.Protocol || request.Schema != api.SchemaVersion || request.Method != method || !validID(request.RequestID) || !validID(request.IdempotencyKey) || !validDigest(request.RequestSHA256) {
		return invalid("record mutation lacks authenticated request metadata")
	}
	if scope.Actor.Kind == "human" && request.Proof == nil {
		return &api.Error{Code: api.CodeForbidden, Message: "human record mutation requires an operation-bound proof", Instead: "Confirm the exact operation through the installed human endpoint."}
	}
	if scope.Actor.Kind != "human" && request.Proof != nil {
		return &api.Error{Code: api.CodeForbidden, Message: "lane record mutation cannot carry a human proof", Instead: "Use the lane's authenticated scope; human operations use the separate human endpoint."}
	}
	digest, err := api.RequestDigest(request)
	if err != nil || digest != request.RequestSHA256 {
		return invalid("record mutation digest does not match its request")
	}
	if request.Proof != nil && (!validID(request.Proof.ID) || request.Proof.RequestSHA256 != digest) {
		return invalid("operation proof is not bound to this request")
	}
	return nil
}

func stableID(scope api.Scope, kind string) api.ID {
	// Domain-separated opaque IDs let lost-reply retries locate the same object.
	// This is not an authority token; the store still checks the full digest/key.
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s", kind, scope.Config, scope.Actor.Kind, scope.Actor.ID, scope.Actor.LifeID, scope.Request.Method, scope.Request.IdempotencyKey)))
	return api.ID(kind + "-" + hex.EncodeToString(sum[:16]))
}

func validID(id api.ID) bool {
	if len(id) < 1 || len(id) > 128 {
		return false
	}
	for _, char := range id {
		if char < 'a' || char > 'z' {
			if char < 'A' || char > 'Z' {
				if char < '0' || char > '9' {
					if char != '-' && char != '_' {
						return false
					}
				}
			}
		}
	}
	return true
}

func validDigest(digest api.Digest) bool {
	if len(digest) != 64 {
		return false
	}
	for _, char := range digest {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func collection(name string) bool {
	switch name {
	case "decisions", "observations", "ledger", "refusals", "tools", "reports", "archives", "judge_egress", "embeddings":
		return true
	}
	return false
}

// ValidateGetInput and ValidateQueryInput are local semantic preflight shared
// by the owned service and the common CLI file form. They perform no I/O.
func ValidateGetInput(request api.RecordGetRequest) error {
	if !validID(request.RecordID) {
		return invalid("invalid record ID")
	}
	return nil
}

func ValidateQueryInput(request api.RecordQuery) error {
	if request.RecordID != "" && !validID(request.RecordID) || request.LifeID != "" && !validID(request.LifeID) || request.Collection != "" && !collection(request.Collection) {
		return invalid("invalid record filter")
	}
	if request.Collection == "" && request.RecordID == "" || request.Limit < 1 || request.Limit > 200 || len(request.Query) > 8192 || len(request.Cursor) > 8192 || !utf8.ValidString(request.Query) {
		return invalid("record query requires a collection or exact ID and bounded page")
	}
	switch request.SearchMode {
	case "keyword", "vector", "hybrid":
	default:
		return invalid("unknown record search mode")
	}
	if request.RecordID != "" && (request.Query != "" || request.Cursor != "" || request.SearchMode != "keyword") {
		return invalid("exact record lookup cannot include search or cursor")
	}
	return nil
}

func validateRecord(record api.Record) error {
	if !validID(record.ID) || !collection(record.Collection) || record.Generation == 0 || !validID(record.Content.ID) || !validDigest(record.Content.SHA256) || record.Content.Bytes < 1 || record.Content.Bytes > api.MaxObjectBytes {
		return integrity("record backend returned invalid metadata")
	}
	if record.Origin != "service" && record.Origin != "observation" && record.Origin != "legacy_import" {
		return integrity("record backend returned invalid provenance")
	}
	if _, err := time.Parse(time.RFC3339Nano, string(record.RecordedAt)); err != nil {
		return integrity("record backend returned invalid timestamp")
	}
	return nil
}

func invalid(message string) *api.Error {
	return &api.Error{Code: api.CodeInvalid, Message: message, Instead: "Use the bounded typed request documented for this operation.", Owner: "lb-v2-integrate"}
}

func integrity(message string) *api.Error {
	return &api.Error{Code: api.CodeIntegrity, Message: message, Instead: "Preserve the evidence and repair the service-owned backend."}
}
