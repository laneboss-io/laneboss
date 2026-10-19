package records

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// This in-memory fixture is not an alternative product store. Embedding an
// unimplemented interface makes every unexpected dependency call fail loudly.
type memoryStore struct {
	api.StateStore
	metadata        map[api.ID]api.ObjectMetadata
	blobs           map[api.ID][]byte
	records         map[api.ID]api.Record
	decisions       map[api.ID]api.DecisionProjection
	receipts        map[receiptDomain]api.MutationReceipt
	commits         int
	queryErr        error
	badFilter       bool
	noReceipt       bool
	events          []api.Event
	blobReads       int
	lookupCalls     int
	receiptOverride *api.MutationReceipt
	awaitOverride   *api.MutationReceipt
	uploads         map[api.ID]api.UploadLease
	proofUses       int
}

type receiptDomain struct {
	Config      string
	Kind        string
	PrincipalID api.ID
	LifeID      api.ID
	Method      api.Method
	Key         api.ID
}

func receiptDomainFor(scope api.Scope, key api.RequestKey) receiptDomain {
	return receiptDomain{Config: scope.Config, Kind: scope.Actor.Kind, PrincipalID: scope.Actor.ID,
		LifeID: scope.Actor.LifeID, Method: key.Method, Key: key.IdempotencyKey}
}

type testClock struct{ now time.Time }

func (c *testClock) Now() time.Time { return c.now }

func fixture(t *testing.T) (*Service, *memoryStore, *testClock) {
	t.Helper()
	state := &memoryStore{metadata: make(map[api.ID]api.ObjectMetadata), blobs: make(map[api.ID][]byte), records: make(map[api.ID]api.Record),
		decisions: make(map[api.ID]api.DecisionProjection),
		receipts:  make(map[receiptDomain]api.MutationReceipt), uploads: make(map[api.ID]api.UploadLease)}
	clock := &testClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	service, err := New(Dependencies{Store: state, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	return service, state, clock
}

func (m *memoryStore) content(id api.ID, data string) api.BlobRef {
	m.blobs[id] = []byte(data)
	sum := sha256.Sum256([]byte(data))
	ref := api.BlobRef{ID: id, Bytes: int64(len(data)), SHA256: api.Digest(hex.EncodeToString(sum[:])), Class: "record"}
	m.metadata[id] = api.ObjectMetadata{Ref: ref, Origin: "upload"}
	return ref
}

func (m *memoryStore) ObjectMetadata(_ context.Context, _ api.Scope, id api.ID) (api.ObjectMetadata, error) {
	metadata, exists := m.metadata[id]
	if !exists {
		return api.ObjectMetadata{}, &api.Error{Code: api.CodeNotFound}
	}
	return metadata, nil
}

func (m *memoryStore) AuthorizationTarget(_ context.Context, _ api.Scope, request api.Request) (api.HumanChallengeRequest, error) {
	var body api.DecisionMutateRequest
	if err := json.Unmarshal(request.Params, &body); err != nil {
		return api.HumanChallengeRequest{}, err
	}
	target := body.RecordID
	if target == "" {
		target = "decisions"
	}
	return api.HumanChallengeRequest{Method: request.Method, TargetID: target,
		RequestSHA256: request.RequestSHA256, BaseGeneration: body.ExpectedGeneration}, nil
}

func (m *memoryStore) Blob(_ context.Context, _ api.Scope, request api.BlobReadRequest) (api.BlobChunk, error) {
	m.blobReads++
	data, exists := m.blobs[request.ObjectID]
	if !exists {
		return api.BlobChunk{}, &api.Error{Code: api.CodeNotFound}
	}
	sum := sha256.Sum256(data)
	return api.BlobChunk{ObjectID: request.ObjectID, Offset: request.Offset,
		Data: append([]byte(nil), data...), SHA256: api.Digest(hex.EncodeToString(sum[:]))}, nil
}

func (m *memoryStore) Lane(_ context.Context, scope api.Scope, request api.LifeRef) (api.Lane, error) {
	if request.LifeID != scope.Actor.LifeID {
		return api.Lane{}, &api.Error{Code: api.CodeNotFound}
	}
	return api.Lane{LifeID: request.LifeID, Run: 1, RootLifeID: request.LifeID, StarterChain: []api.ID{}}, nil
}

func (m *memoryStore) Records(_ context.Context, scope api.Scope, query api.RecordQuery) (api.RecordPage, error) {
	if m.queryErr != nil {
		return api.RecordPage{}, m.queryErr
	}
	page := api.RecordPage{Records: []api.Record{}}
	for _, record := range m.records {
		if scope.Actor.Kind == "lane" && record.LifeID != scope.Actor.LifeID {
			continue
		}
		if !m.badFilter && query.RecordID != "" && record.ID != query.RecordID {
			continue
		}
		if query.Collection != "" && record.Collection != query.Collection {
			continue
		}
		if query.LifeID != "" && record.LifeID != query.LifeID {
			continue
		}
		if query.Query != "" && !strings.Contains(string(m.blobs[record.Content.ID]), query.Query) {
			continue
		}
		page.Records = append(page.Records, record)
	}
	return page, nil
}

func (m *memoryStore) Decision(_ context.Context, scope api.Scope, id api.ID) (api.DecisionProjection, error) {
	projection, exists := m.decisions[id]
	if !exists || scope.Actor.Kind != "human" {
		return api.DecisionProjection{}, &api.Error{Code: api.CodeNotFound}
	}
	return projection, nil
}

func (m *memoryStore) LookupReceipt(_ context.Context, scope api.Scope, key api.RequestKey) (api.MutationReceipt, error) {
	m.lookupCalls++
	if m.receiptOverride != nil {
		return *m.receiptOverride, nil
	}
	receipt, exists := m.receipts[receiptDomainFor(scope, key)]
	if !exists {
		return api.MutationReceipt{}, &api.Error{Code: api.CodeNotFound}
	}
	if receipt.Key.RequestSHA256 != key.RequestSHA256 {
		return api.MutationReceipt{}, &api.Error{Code: api.CodeIdempotencyConflict}
	}
	return receipt, nil
}

func (m *memoryStore) AwaitReceipt(ctx context.Context, scope api.Scope, key api.RequestKey) (api.MutationReceipt, error) {
	if m.awaitOverride != nil {
		return *m.awaitOverride, nil
	}
	return m.LookupReceipt(ctx, scope, key)
}

func (m *memoryStore) Transact(ctx context.Context, transaction api.Transaction) (api.Commit, error) {
	if err := api.ValidateTransactionShape(transaction); err != nil {
		return api.Commit{}, err
	}
	if transaction.Scope.Actor.Kind == "human" && !api.HumanSessionMethod(transaction.Scope.Request.Method) && (len(transaction.Guards) != 1 || transaction.Guards[0].Proof == nil) {
		return api.Commit{}, &api.Error{Code: api.CodeForbidden}
	}
	requestKey := api.RequestKey{Method: transaction.Scope.Request.Method, IdempotencyKey: transaction.Scope.Request.IdempotencyKey, RequestSHA256: transaction.Scope.Request.RequestSHA256}
	key := receiptDomainFor(transaction.Scope, requestKey)
	if prior, exists := m.receipts[key]; exists {
		if prior.Key.RequestSHA256 != transaction.Scope.Request.RequestSHA256 {
			return api.Commit{}, &api.Error{Code: api.CodeIdempotencyConflict}
		}
		return api.Commit{Operation: prior.Operation, Reply: prior.Reply, FirstSeq: prior.FirstSeq, LastSeq: prior.LastSeq, Replayed: true}, nil
	}
	if transaction.Scope.Request.Method == "blob.begin" || transaction.Scope.Request.Method == "blob.chunk" || transaction.Scope.Request.Method == "blob.commit" {
		return m.uploadTransaction(ctx, transaction, requestKey, key)
	}
	for _, compare := range transaction.Compare {
		if m.records[compare.ID].Generation != compare.Generation {
			return api.Commit{}, &api.Error{Code: api.CodeConflict}
		}
	}
	if len(transaction.Events) < 1 || len(transaction.Events) > 2 || transaction.Reply == nil {
		return api.Commit{}, &api.Error{Code: api.CodeIntegrity}
	}
	var records []api.Record
	for _, event := range transaction.Events {
		var record api.Record
		if err := api.DecodeObject(event.Payload, &record); err != nil {
			return api.Commit{}, err
		}
		records = append(records, record)
	}
	record := records[len(records)-1]
	var receipt api.Record
	if err := json.Unmarshal(transaction.Reply.Result, &receipt); err != nil {
		return api.Commit{}, err
	}
	if !reflect.DeepEqual(record, receipt) {
		return api.Commit{}, &api.Error{Code: api.CodeIntegrity}
	}
	m.commits++
	for _, guard := range transaction.Guards {
		if guard.Proof != nil {
			m.proofUses++
		}
	}
	firstSeq := api.Sequence(len(m.events) + 1)
	for index, record := range records {
		m.records[record.ID] = record
		event := transaction.Events[index]
		event.Seq = api.Sequence(len(m.events) + 1)
		m.events = append(m.events, event)
	}
	for _, projection := range transaction.Writes.Decisions {
		m.decisions[projection.RecordID] = projection
	}
	commit := api.Commit{Operation: api.Operation{ID: transaction.Events[0].OperationID, Status: "succeeded"},
		FirstSeq: firstSeq, LastSeq: api.Sequence(len(m.events)), Reply: &api.RPCReply{Result: append(json.RawMessage(nil), transaction.Reply.Result...)}}
	if m.noReceipt {
		commit.Reply = nil
	}
	m.receipts[key] = api.MutationReceipt{Config: transaction.Scope.Config, Key: requestKey, Actor: transaction.Scope.Actor,
		Operation: commit.Operation, Reply: commit.Reply, FirstSeq: commit.FirstSeq, LastSeq: commit.LastSeq}
	return commit, nil
}

func scopeFor(t *testing.T, method api.Method, params any, key string, human bool) api.Scope {
	t.Helper()
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	actor := api.Actor{Kind: "lane", ID: "principal-one", LifeID: "life-one", Level: 3, Role: "executor"}
	if human {
		actor = api.Actor{Kind: "human", ID: "human-one"}
	}
	request := api.Request{Protocol: api.Protocol, Schema: 2, Config: "demo", Method: method,
		RequestID: api.ID(strings.Repeat("r", 32)), IdempotencyKey: api.ID(key), Params: raw}
	request.RequestSHA256, err = api.RequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	if human {
		request.Proof = &api.ProofRef{ID: "verified-fixture", RequestSHA256: request.RequestSHA256}
	}
	return api.Scope{Config: "demo", Actor: actor, Source: "cli", Request: request}
}

func requireCode(t *testing.T, err error, code api.ErrorCode) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("expected typed code %s, got %v", code, err)
	}
}

func appendObservation(t *testing.T, service *Service, state *memoryStore, data, key string) api.Record {
	t.Helper()
	request := api.RecordAppendRequest{Collection: "observations", Content: state.content(api.ID("blob-"+key), data), RelatedIDs: []api.ID{}}
	result, err := service.RecordsAppend(context.Background(), scopeFor(t, "records.append", request, key, false), request)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestAppendReadAndReplay(t *testing.T) {
	service, state, clock := fixture(t)
	ref := state.content("body-one", "A distinct recorded observation")
	request := api.RecordAppendRequest{Collection: "observations", Content: ref, RelatedIDs: []api.ID{}}
	scope := scopeFor(t, "records.append", request, "append-one", false)
	original, err := service.RecordsAppend(context.Background(), scope, request)
	if err != nil {
		t.Fatal(err)
	}
	if original.Actor != scope.Actor || original.Origin != "observation" || original.Content != ref || original.Run != 1 {
		t.Fatal("authentic provenance or content was lost")
	}
	clock.now = clock.now.Add(time.Hour)
	replayed, err := service.RecordsAppend(context.Background(), scope, request)
	if err != nil || !reflect.DeepEqual(replayed, original) || state.commits != 1 {
		t.Fatal("retry changed the receipt or appended twice")
	}
	got, err := service.RecordsGet(context.Background(), scope, api.RecordGetRequest{RecordID: original.ID})
	if err != nil || !reflect.DeepEqual(got, original) {
		t.Fatal("read did not find the written record")
	}
	request.Content = state.content("body-two", "A different observation")
	_, err = service.RecordsAppend(context.Background(), scopeFor(t, "records.append", request, "append-one", false), request)
	requireCode(t, err, api.CodeIdempotencyConflict)
	if state.commits != 1 {
		t.Fatal("changed retry mutated the store")
	}
}

func TestRecordAuthority(t *testing.T) {
	service, state, _ := fixture(t)
	ref := state.content("body", "Ordinary record text")
	for _, name := range []string{"decisions", "ledger", "refusals", "tools", "archives", "judge_egress", "embeddings"} {
		request := api.RecordAppendRequest{Collection: name, Content: ref, RelatedIDs: []api.ID{}}
		_, err := service.RecordsAppend(context.Background(), scopeFor(t, "records.append", request, name, false), request)
		requireCode(t, err, api.CodeForbidden)
	}
	decision := api.DecisionMutateRequest{Action: "add", Content: ref}
	_, err := service.DecisionsMutate(context.Background(), scopeFor(t, "decisions.mutate", decision, "decision-one", false), decision)
	requireCode(t, err, api.CodeForbidden)
	human := scopeFor(t, "decisions.mutate", decision, "decision-two", true)
	human.Request.Proof = nil
	_, err = service.DecisionsMutate(context.Background(), human, decision)
	requireCode(t, err, api.CodeForbidden)
	if state.commits != 0 {
		t.Fatal("refused authority claim changed state")
	}
}

func TestRecordScreening(t *testing.T) {
	service, state, _ := fixture(t)
	for name, data := range map[string]string{
		"binary":     "ordinary\x00bytes",
		"credential": "api_key = \"" + "synthetic9" + strings.Repeat("q", 20) + "\"",
	} {
		t.Run(name, func(t *testing.T) {
			request := api.RecordAppendRequest{Collection: "observations", Content: state.content(api.ID(name), data), RelatedIDs: []api.ID{}}
			_, err := service.RecordsAppend(context.Background(), scopeFor(t, "records.append", request, name, false), request)
			if err == nil {
				t.Fatal("unsafe content was stored")
			}
		})
	}
	request := api.RecordAppendRequest{Collection: "observations", Content: state.content("corrupt", "Safe bytes"), RelatedIDs: []api.ID{}}
	state.blobs["corrupt"] = []byte("Changed bytes")
	_, err := service.RecordsAppend(context.Background(), scopeFor(t, "records.append", request, "corrupt", false), request)
	requireCode(t, err, api.CodeIntegrity)
	if state.commits != 0 {
		t.Fatal("screening happened after mutation")
	}
}

func TestQueryFailsOnWrongFilter(t *testing.T) {
	service, state, _ := fixture(t)
	record := appendObservation(t, service, state, "Own visible observation", "one")
	scope := scopeFor(t, "records.get", api.RecordGetRequest{RecordID: record.ID}, "get-one", false)
	_, err := service.RecordsGet(context.Background(), scope, api.RecordGetRequest{RecordID: "absent"})
	requireCode(t, err, api.CodeNotFound)
	state.badFilter = true // Red control: backend ignores the exact ID filter.
	_, err = service.RecordsGet(context.Background(), scope, api.RecordGetRequest{RecordID: "absent"})
	requireCode(t, err, api.CodeIntegrity)
	state.badFilter = false
	state.queryErr = &api.Error{Code: api.CodeUnavailable, Message: "fixture outage"}
	_, err = service.RecordsGet(context.Background(), scope, api.RecordGetRequest{RecordID: record.ID})
	requireCode(t, err, api.CodeUnavailable)
}

func TestDecisionNotesAndCAS(t *testing.T) {
	service, state, clock := fixture(t)
	add := api.DecisionMutateRequest{Action: "add", Content: state.content("decision", "Canonical decision text")}
	first, err := service.DecisionsMutate(context.Background(), scopeFor(t, "decisions.mutate", add, "add", true), add)
	if err != nil {
		t.Fatal(err)
	}
	if state.decisions[first.ID].Candidate.Binding || state.decisions[first.ID].Candidate.Text != "Canonical decision text" || state.decisions[first.ID].Candidate.Authority.Kind != "human" {
		t.Fatal("plain text did not become an authorized nonbinding reminder")
	}
	clock.now = clock.now.Add(time.Minute)
	note := api.DecisionMutateRequest{Action: "annotate", RecordID: first.ID, ExpectedGeneration: 1, Content: state.content("note", "Explanatory note")}
	scope := scopeFor(t, "decisions.mutate", note, "note", true)
	second, err := service.DecisionsMutate(context.Background(), scope, note)
	if err != nil {
		t.Fatal(err)
	}
	if second.Content != first.Content || len(second.Annotations) != 1 || second.Annotations[0] != note.Content || second.Generation != 2 {
		t.Fatal("annotation replaced canonical text or lost CAS")
	}
	if second.RecordedAt != api.Timestamp(clock.now.UTC().Format(time.RFC3339Nano)) || second.RecordedAt == first.RecordedAt || state.decisions[first.ID].Candidate.EffectiveAt != first.RecordedAt {
		t.Fatal("decision metadata retained a stale time or changed its effective time")
	}
	feedback := api.DecisionMutateRequest{Action: "feedback", RecordID: first.ID, ExpectedGeneration: 2, Content: state.content("feedback", "A later feedback record")}
	_, err = service.DecisionsMutate(context.Background(), scopeFor(t, "decisions.mutate", feedback, "feedback", true), feedback)
	if err != nil {
		t.Fatal(err)
	}
	clock.now = clock.now.Add(2 * time.Hour)
	replay, err := service.DecisionsMutate(context.Background(), scope, note)
	if err != nil || !reflect.DeepEqual(replay, second) || state.commits != 3 {
		t.Fatal("replay returned latest projection instead of original receipt")
	}
	note.Content = state.content("stale", "A stale change")
	_, err = service.DecisionsMutate(context.Background(), scopeFor(t, "decisions.mutate", note, "new-stale-key", true), note)
	requireCode(t, err, api.CodeConflict)
}

func TestDecisionInputBoundary(t *testing.T) {
	service, state, _ := fixture(t)
	content := state.content("boundary-content", "Canonical boundary text")
	add := api.DecisionMutateRequest{Action: "add", Content: content}
	first, err := service.DecisionsMutate(context.Background(), scopeFor(t, "decisions.mutate", add, "boundary-add", true), add)
	if err != nil {
		t.Fatal(err)
	}
	for name, request := range map[string]api.DecisionMutateRequest{
		"add_record":     {Action: "add", RecordID: first.ID, Content: content},
		"add_generation": {Action: "add", ExpectedGeneration: 1, Content: content},
		"change_zero":    {Action: "annotate", RecordID: first.ID, Content: content},
		"change_limit":   {Action: "annotate", RecordID: first.ID, ExpectedGeneration: 1<<53 - 1, Content: content},
		// Embed returns before generation arithmetic and transaction JSON checks.
		// Its invalid bound must still be refused by the service input preflight.
		"embed_limit": {Action: "embed", RecordID: first.ID, ExpectedGeneration: 1<<53 - 1, Content: content},
	} {
		t.Run(name, func(t *testing.T) {
			before, uses := state.commits, state.proofUses
			_, err := service.DecisionsMutate(context.Background(), scopeFor(t, "decisions.mutate", request, "invalid-"+name, true), request)
			requireCode(t, err, api.CodeInvalid)
			if state.commits != before || state.proofUses != uses {
				t.Fatal("invalid decision shape reached the service commit")
			}
		})
	}
}

func TestDecisionStructuredSupersession(t *testing.T) {
	service, state, _ := fixture(t)
	document := api.DecisionDocument{Schema: "laneboss.decision.v2", Text: "Approved decision with explicit applicability",
		EffectiveAt: "2026-01-02T03:04:05Z", Binding: true,
		AppliesTo: api.DecisionApplicability{Levels: []int{3, 4}, Roles: []string{"executor"}, ProjectIDs: []api.ID{"project-one"}, LifeIDs: []api.ID{}}}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	add := api.DecisionMutateRequest{Action: "add", Content: state.content("structured", string(raw))}
	addScope := scopeFor(t, "decisions.mutate", add, "structured-add", true)
	first, err := service.DecisionsMutate(context.Background(), addScope, add)
	if err != nil {
		t.Fatal(err)
	}
	candidate := state.decisions[first.ID].Candidate
	if candidate.Text != document.Text || candidate.EffectiveAt != document.EffectiveAt || !candidate.Binding || !reflect.DeepEqual(candidate.AppliesTo, document.AppliesTo) || candidate.Authority.ReceiptID != addScope.Request.Proof.ID || candidate.Source.SHA256 != add.Content.SHA256 {
		t.Fatal("structured decision projection lost content, applicability or verified authority")
	}
	replace := api.DecisionMutateRequest{Action: "supersede", RecordID: first.ID, ExpectedGeneration: first.Generation, Content: state.content("replacement", "A later nonbinding reminder")}
	replaceScope := scopeFor(t, "decisions.mutate", replace, "replacement", true)
	second, err := service.DecisionsMutate(context.Background(), replaceScope, replace)
	if err != nil {
		t.Fatal(err)
	}
	prior := state.records[first.ID]
	if second.ID == first.ID || second.Generation != 1 || prior.Content != first.Content || prior.Actor != first.Actor || prior.Generation != first.Generation+1 || len(second.RelatedIDs) != 1 || second.RelatedIDs[0] != first.ID {
		t.Fatal("supersession overwrote canonical history or lost its record CAS/link")
	}
	if state.decisions[first.ID].Status != "superseded" || !reflect.DeepEqual(state.decisions[first.ID].Candidate, candidate) || state.decisions[second.ID].SupersedesID != first.ID || state.decisions[second.ID].Status != "active" || state.decisions[second.ID].Candidate.Binding {
		t.Fatal("supersession did not atomically preserve the old projection and publish the new one")
	}
	if len(state.events) != 3 || state.events[0].ID == state.events[1].ID || state.events[1].ID == state.events[2].ID {
		t.Fatal("supersession did not append both distinct history events")
	}
	replayed, err := service.DecisionsMutate(context.Background(), replaceScope, replace)
	if err != nil || !reflect.DeepEqual(replayed, second) || state.commits != 2 {
		t.Fatal("supersession retry did not return its retained new record")
	}
}

func TestDecisionDocumentValidation(t *testing.T) {
	service, state, _ := fixture(t)
	for name, content := range map[string]string{
		"missing fields": `{"schema":"laneboss.decision.v2","text":"Incomplete"}`,
		"wrong schema":   `{"schema":"other","text":"Text","effective_at":"2026-01-01T00:00:00Z","applies_to":{"levels":[],"roles":[],"project_ids":[],"life_ids":[]},"binding":false}`,
		"bad time":       `{"schema":"laneboss.decision.v2","text":"Text","effective_at":"yesterday","applies_to":{"levels":[],"roles":[],"project_ids":[],"life_ids":[]},"binding":false}`,
		"reserved level": `{"schema":"laneboss.decision.v2","text":"Text","effective_at":"2026-01-01T00:00:00Z","applies_to":{"levels":[2],"roles":[],"project_ids":[],"life_ids":[]},"binding":true}`,
		"empty text":     " \n\t",
	} {
		t.Run(name, func(t *testing.T) {
			request := api.DecisionMutateRequest{Action: "add", Content: state.content(api.ID("bad-"+strings.ReplaceAll(name, " ", "-")), content)}
			scope := scopeFor(t, "decisions.mutate", request, "invalid-"+strings.ReplaceAll(name, " ", "-"), true)
			if err := mutationScope(context.Background(), scope, "decisions.mutate"); err != nil {
				t.Fatal(err)
			}
			before := state.blobReads
			_, err := service.DecisionsMutate(context.Background(), scope, request)
			requireCode(t, err, api.CodeInvalid)
			if state.blobReads != before+1 {
				t.Fatal("decision validation was not reached")
			}
			if state.commits != 0 {
				t.Fatal("malformed decision committed before validation")
			}
		})
	}
}

func TestDecisionMetadataBoundaryReplay(t *testing.T) {
	service, state, _ := fixture(t)
	add := api.DecisionMutateRequest{Action: "add", Content: state.content("boundary-decision", "Retained canonical decision")}
	current, err := service.DecisionsMutate(context.Background(), scopeFor(t, "decisions.mutate", add, "boundary-add", true), add)
	if err != nil {
		t.Fatal(err)
	}
	note := state.content("boundary-note", "An explanatory annotation")
	var lastRequest api.DecisionMutateRequest
	var lastScope api.Scope
	for index := 0; index < 200; index++ {
		action := "annotate"
		if index == 199 {
			action = "feedback"
		}
		lastRequest = api.DecisionMutateRequest{Action: action, RecordID: current.ID, ExpectedGeneration: current.Generation, Content: note}
		lastScope = scopeFor(t, "decisions.mutate", lastRequest, fmt.Sprintf("boundary-%d", index), true)
		current, err = service.DecisionsMutate(context.Background(), lastScope, lastRequest)
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(current.Annotations)+len(current.Feedback) != 200 {
		t.Fatal("metadata bound was not reached")
	}
	replayed, err := service.DecisionsMutate(context.Background(), lastScope, lastRequest)
	if err != nil || !reflect.DeepEqual(replayed, current) || state.commits != 201 {
		t.Fatal("200th metadata retry was rejected or appended twice")
	}
	lastRequest.ExpectedGeneration = current.Generation
	_, err = service.DecisionsMutate(context.Background(), scopeFor(t, "decisions.mutate", lastRequest, "boundary-overflow", true), lastRequest)
	requireCode(t, err, api.CodeInvalid)
	if state.commits != 201 {
		t.Fatal("metadata overflow committed")
	}
}

func TestMissingReceiptIsFailure(t *testing.T) {
	service, state, _ := fixture(t)
	state.noReceipt = true // Red control: a backend claims completion without evidence.
	request := api.RecordAppendRequest{Collection: "observations", Content: state.content("body", "Recorded text"), RelatedIDs: []api.ID{}}
	_, err := service.RecordsAppend(context.Background(), scopeFor(t, "records.append", request, "missing", false), request)
	requireCode(t, err, api.CodeIntegrity)
}

func TestMissingWorkerIsFailure(t *testing.T) {
	service, _, _ := fixture(t)
	request := api.RecordQuery{Collection: "observations", SearchMode: "vector", Query: "relevant", Limit: 10}
	scope := scopeFor(t, "records.query", request, "query", false)
	_, err := service.RecordsQuery(context.Background(), scope, request)
	requireCode(t, err, api.CodeNotImplemented)
	_, err = service.BoxList(context.Background(), scope, api.ListRequest{Limit: 10})
	requireCode(t, err, api.CodeNotImplemented)
}

func decisionReplayFixture(t *testing.T) (*Service, *memoryStore, api.Scope, api.DecisionMutateRequest, api.Record) {
	t.Helper()
	service, state, _ := fixture(t)
	add := api.DecisionMutateRequest{Action: "add", Content: state.content("replay-decision", "Canonical replay evidence")}
	first, err := service.DecisionsMutate(context.Background(), scopeFor(t, "decisions.mutate", add, "replay-add", true), add)
	if err != nil {
		t.Fatal(err)
	}
	note := api.DecisionMutateRequest{Action: "annotate", RecordID: first.ID, ExpectedGeneration: first.Generation, Content: state.content("replay-note", "Independent note content")}
	scope := scopeFor(t, "decisions.mutate", note, "replay-note", true)
	retained, err := service.DecisionsMutate(context.Background(), scope, note)
	if err != nil {
		t.Fatal(err)
	}
	return service, state, scope, note, retained
}

func TestDecisionProofReplay(t *testing.T) {
	service, state, scope, note, _ := decisionReplayFixture(t)
	for name, change := range map[string]func(*api.ProofRef){
		"empty_id":     func(p *api.ProofRef) { p.ID = "" },
		"wrong_digest": func(p *api.ProofRef) { p.RequestSHA256 = api.Digest(strings.Repeat("0", 64)) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := scope
			proof := *scope.Request.Proof
			change(&proof)
			bad.Request.Proof = &proof
			before := state.lookupCalls
			_, err := service.DecisionsMutate(context.Background(), bad, note)
			if err == nil {
				t.Fatal("invalid proof replay was accepted")
			}
			requireCode(t, err, api.CodeInvalid)
			if state.lookupCalls != before {
				t.Fatal("invalid proof reached receipt lookup")
			}
		})
	}
	t.Run("lane_proof", func(t *testing.T) {
		request := api.RecordAppendRequest{Collection: "observations", Content: state.content("lane-proof", "Lane observation"), RelatedIDs: []api.ID{}}
		lane := scopeFor(t, "records.append", request, "lane-proof", false)
		// A matching digest isolates the endpoint-class refusal from shape checks.
		lane.Request.Proof = &api.ProofRef{ID: scope.Request.Proof.ID, RequestSHA256: lane.Request.RequestSHA256}
		_, err := service.RecordsAppend(context.Background(), lane, request)
		if err == nil {
			t.Fatal("lane record accepted a human proof")
		}
		requireCode(t, err, api.CodeForbidden)
	})
}

func TestReceiptDomains(t *testing.T) {
	_, state, scope, _, _ := decisionReplayFixture(t)
	key := api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey, RequestSHA256: scope.Request.RequestSHA256}
	if receipt, err := state.LookupReceipt(context.Background(), scope, key); err != nil || receipt.Config != scope.Config || receipt.Actor != scope.Actor || receipt.Key != key {
		t.Fatal("receipt fixture lost its original binding")
	}
	for name, change := range map[string]func(*api.Scope, *api.RequestKey){
		"principal": func(s *api.Scope, _ *api.RequestKey) { s.Actor.ID = "human-two" },
		"config":    func(s *api.Scope, _ *api.RequestKey) { s.Config = "another" },
		"life":      func(s *api.Scope, _ *api.RequestKey) { s.Actor.LifeID = "other-life" },
		"method":    func(_ *api.Scope, k *api.RequestKey) { k.Method = "records.append" },
	} {
		t.Run(name, func(t *testing.T) {
			foreign, altered := scope, key
			change(&foreign, &altered)
			_, err := state.LookupReceipt(context.Background(), foreign, altered)
			if err == nil {
				t.Fatal("foreign receipt domain was visible")
			}
			requireCode(t, err, api.CodeNotFound)
		})
	}
}

func TestReplayReceiptBinding(t *testing.T) {
	service, state, scope, note, retained := decisionReplayFixture(t)
	key := api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey, RequestSHA256: scope.Request.RequestSHA256}
	original, err := state.LookupReceipt(context.Background(), scope, key)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*api.MutationReceipt){
		"principal": func(r *api.MutationReceipt) { r.Actor.ID = "human-two" },
		"config":    func(r *api.MutationReceipt) { r.Config = "another" },
		"method":    func(r *api.MutationReceipt) { r.Key.Method = "records.append" },
		"key":       func(r *api.MutationReceipt) { r.Key.IdempotencyKey = "different-key" },
		"digest":    func(r *api.MutationReceipt) { r.Key.RequestSHA256 = api.Digest(strings.Repeat("0", 64)) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := original
			change(&bad)
			state.receiptOverride = &bad // Deliberate backend fault, not normal fixture lookup.
			_, err := service.DecisionsMutate(context.Background(), scope, note)
			if err == nil {
				t.Fatal("foreign receipt was replayed")
			}
			requireCode(t, err, api.CodeIntegrity)
		})
	}
	pending, foreign := original, original
	pending.Operation.Status, foreign.Actor.ID = "pending", "human-two"
	state.receiptOverride, state.awaitOverride = &pending, &foreign
	_, err = service.DecisionsMutate(context.Background(), scope, note)
	requireCode(t, err, api.CodeIntegrity)
	state.receiptOverride, state.awaitOverride = nil, nil
	replayed, err := service.DecisionsMutate(context.Background(), scope, note)
	if err != nil || !reflect.DeepEqual(replayed, retained) || state.commits != 2 {
		t.Fatal("binding checks changed the original replay")
	}
}
