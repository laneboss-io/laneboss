package messaging

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
)

// This is a recording component fixture, not an OS/authentication E2E. Its
// transaction assigns real in-memory order, enforces CAS/idempotency, and
// derives mailbox answers from the submitted events rather than test names.
type memoryStore struct {
	api.StateStore
	lanes        map[api.ID]api.Lane
	launches     map[api.ID]api.LaunchRecord
	grants       map[api.ID]api.GrantSet
	blobs        map[api.ID][]byte
	metadata     map[api.ID]api.ObjectMetadata
	channels     map[api.ID]api.EnrolledChannel
	workerLeases map[api.ID]api.WorkerLease
	effectRows   map[api.ID]api.EffectRecord
	turns        map[api.ID]api.TurnSnapshot
	proofs       map[api.ID]api.VerifiedHumanProof
	enrollments  map[api.ID]api.HumanEnrollment
	transactions []api.Transaction
	mail         map[api.ID]api.Mail
	events       []api.Event
	effects      []api.Effect
	commits      map[string]api.Commit
	receipts     map[string]api.MutationReceipt
	digests      map[string]api.Digest
	seq          api.Sequence
	beforeCommit func()
	failure      error
	leak         *api.Mail
	badChunk     bool
	commitError  *api.Error
	receiptError error
}

func (m *memoryStore) Lane(_ context.Context, scope api.Scope, target api.LifeRef) (api.Lane, error) {
	if m.failure != nil {
		return api.Lane{}, m.failure
	}
	if scope.Actor.Kind == "lane" && target.LifeID != scope.Actor.LifeID {
		return api.Lane{}, problem(api.CodeForbidden, "fixture raw life ACL excludes sibling metadata")
	}
	row, ok := m.lanes[target.LifeID]
	if !ok {
		return api.Lane{}, problem(api.CodeNotFound, "fixture life not found")
	}
	return row, nil
}

func (m *memoryStore) Relation(_ context.Context, _ api.Scope, id api.ID) (api.RelationFacts, error) {
	if m.failure != nil {
		return api.RelationFacts{}, m.failure
	}
	row, ok := m.lanes[id]
	if !ok {
		return api.RelationFacts{}, problem(api.CodeNotFound, "fixture relation not found")
	}
	return relationFacts(row), nil
}

func (m *memoryStore) ObjectMetadata(_ context.Context, scope api.Scope, id api.ID) (api.ObjectMetadata, error) {
	row, ok := m.metadata[id]
	if !ok || row.ACL.Config != scope.Config {
		return api.ObjectMetadata{}, problem(api.CodeNotFound, "fixture object metadata not found")
	}
	return row, nil
}

func (m *memoryStore) Channel(_ context.Context, scope api.Scope, id api.ID) (api.EnrolledChannel, error) {
	row, ok := m.channels[id]
	if !ok || row.Config != scope.Config {
		return api.EnrolledChannel{}, problem(api.CodeNotFound, "fixture channel not found")
	}
	return row, nil
}

func requestDomain(scope api.Scope) string {
	return strings.Join([]string{scope.Config, scope.Actor.Kind, string(scope.Actor.ID), string(scope.Actor.LifeID), string(scope.Request.Method), string(scope.Request.IdempotencyKey)}, "/")
}

func (m *memoryStore) LookupReceipt(_ context.Context, scope api.Scope, key api.RequestKey) (api.MutationReceipt, error) {
	if m.receiptError != nil {
		return api.MutationReceipt{}, m.receiptError
	}
	domain := requestDomain(scope)
	digest, ok := m.digests[domain]
	if !ok {
		return api.MutationReceipt{}, problem(api.CodeNotFound, "fixture receipt not found")
	}
	if digest != key.RequestSHA256 {
		return api.MutationReceipt{}, problem(api.CodeIdempotencyConflict, "fixture key changed content")
	}
	receipt, exists := m.receipts[domain]
	if !exists {
		return api.MutationReceipt{}, problem(api.CodeIntegrity, "fixture receipt metadata is missing")
	}
	return receipt, nil
}

func (m *memoryStore) AwaitReceipt(ctx context.Context, scope api.Scope, key api.RequestKey) (api.MutationReceipt, error) {
	receipt, err := m.LookupReceipt(ctx, scope, key)
	if err == nil && receipt.Reply == nil {
		return api.MutationReceipt{}, problem(api.CodeUnavailable, "fixture operation is still pending")
	}
	return receipt, err
}

func (m *memoryStore) AuthorizationTarget(_ context.Context, scope api.Scope, request api.Request) (api.HumanChallengeRequest, error) {
	var send api.MailSendRequest
	if request.Method != "mail.send" || api.DecodeObject(request.Params, &send) != nil || scope.Config != request.Config {
		return api.HumanChallengeRequest{}, problem(api.CodeInvalid, "fixture has no authorization target for this request")
	}
	row, ok := m.lanes[send.RecipientLifeID]
	if !ok {
		return api.HumanChallengeRequest{}, problem(api.CodeNotFound, "fixture proof target does not exist")
	}
	return api.HumanChallengeRequest{Method: request.Method, TargetID: row.LifeID, RequestSHA256: request.RequestSHA256, BaseGeneration: row.Generation}, nil
}

func (m *memoryStore) Launch(_ context.Context, id api.ID) (api.LaunchRecord, error) {
	row, ok := m.launches[id]
	if !ok {
		return api.LaunchRecord{}, problem(api.CodeNotFound, "fixture launch not found")
	}
	return row, nil
}

func (m *memoryStore) Grants(_ context.Context, id api.ID) (api.GrantSet, error) {
	row, ok := m.grants[id]
	if !ok {
		return api.GrantSet{}, problem(api.CodeNotFound, "fixture grant set not found")
	}
	return row, nil
}

func (m *memoryStore) Blob(_ context.Context, _ api.Scope, request api.BlobReadRequest) (api.BlobChunk, error) {
	data, ok := m.blobs[request.ObjectID]
	if !ok || request.Offset < 0 || request.Offset > int64(len(data)) || request.Limit < 1 || request.Limit > api.MaxChunkBytes {
		return api.BlobChunk{}, problem(api.CodeNotFound, "fixture blob range not found")
	}
	end := min(request.Offset+int64(request.Limit), int64(len(data)))
	part := append([]byte{}, data[request.Offset:end]...)
	chunk := api.BlobChunk{ObjectID: request.ObjectID, Offset: request.Offset, Data: part, SHA256: hashBytes(part)}
	if m.badChunk {
		chunk.SHA256 = hashBytes(append(part, '!'))
	}
	return chunk, nil
}

func (m *memoryStore) Mail(_ context.Context, scope api.Scope, request api.ListRequest) (api.MailPage, error) {
	if m.leak != nil {
		return api.MailPage{Messages: []api.Mail{*m.leak}}, nil
	}
	rows := []api.Mail{}
	for _, row := range m.mail {
		if scope.Actor.Kind == "lane" && row.Sender.LifeID != scope.Actor.LifeID && row.RecipientLifeID != scope.Actor.LifeID {
			continue
		}
		if request.LifeID != "" && row.Sender.LifeID != request.LifeID && row.RecipientLifeID != request.LifeID {
			continue
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].QueuedSeq < rows[j].QueuedSeq })
	start := 0
	if request.Cursor != "" {
		var err error
		start, err = strconv.Atoi(request.Cursor)
		if err != nil || start > len(rows) {
			return api.MailPage{}, problem(api.CodeInvalid, "fixture cursor is invalid")
		}
	}
	end := min(start+request.Limit, len(rows))
	page := api.MailPage{Messages: rows[start:end]}
	if end < len(rows) {
		page.Cursor = strconv.Itoa(end)
	}
	return page, nil
}

func (m *memoryStore) Events(_ context.Context, _ api.Scope, request api.EventTailRequest) (api.EventPage, error) {
	page := api.EventPage{Events: []api.Event{}, Complete: true}
	for _, event := range m.events {
		if event.LifeID == request.LifeID && (request.Run == 0 || event.Run == request.Run) {
			page.Events = append(page.Events, event)
		}
	}
	return page, nil
}

func (m *memoryStore) Transact(_ context.Context, transaction api.Transaction) (api.Commit, error) {
	if err := api.ValidateTransactionShape(transaction); err != nil {
		return api.Commit{}, err
	}
	scope := transaction.Scope
	domain, requestDigest := requestDomain(scope), scope.Request.RequestSHA256
	if transaction.Internal != nil {
		domain = scope.Config + "/internal/" + string(transaction.Internal.ID)
		raw, err := json.Marshal(struct {
			Intent api.InternalIntent
			Writes api.StateWrites
			Events []api.Event
		}{*transaction.Internal, transaction.Writes, transaction.Events})
		if err != nil {
			return api.Commit{}, err
		}
		requestDigest = hashBytes(raw)
	}
	if digest, ok := m.digests[domain]; ok {
		if digest != requestDigest {
			return api.Commit{}, problem(api.CodeIdempotencyConflict, "fixture key changed content")
		}
		commit := m.commits[domain]
		commit.Replayed = true
		return commit, nil
	}
	if m.beforeCommit != nil {
		m.beforeCommit()
		m.beforeCommit = nil
	}
	for _, compare := range transaction.Compare {
		var current api.Generation
		switch compare.Kind {
		case "lane":
			current = m.lanes[compare.ID].Generation
		case "grants":
			current = m.grants[compare.ID].Generation
		case "mail":
			current = m.mail[compare.ID].Generation
		default:
			return api.Commit{}, problem(api.CodeInvalid, "fixture compare kind is unknown")
		}
		if current != compare.Generation {
			return api.Commit{}, problem(api.CodeConflict, "fixture generation changed before commit")
		}
	}
	for _, guard := range transaction.Guards {
		if guard.Cancellation != nil && m.lanes[guard.Cancellation.LifeID].CancellationEpoch != guard.Cancellation.Epoch {
			return api.Commit{}, problem(api.CodeConflict, "fixture cancellation epoch changed before commit")
		}
		if guard.Proof != nil {
			proof, ok := m.proofs[guard.Proof.Proof.ID]
			if !ok || proof.ConsumedBy != "" || proof.Ref != guard.Proof.Proof || proof.Target != guard.Proof.Target || proof.PrincipalID != scope.Actor.ID {
				return api.Commit{}, problem(api.CodeUnauthenticated, "fixture proof was changed or already consumed")
			}
		}
	}
	if scope.Actor.Kind == "lane" && m.launches[scope.LaunchID].Revoked {
		return api.Commit{}, problem(api.CodeUnauthenticated, "fixture launch revoked before commit")
	}
	operationID := api.ID("op-" + strconv.Itoa(len(m.commits)+1))
	if transaction.Internal != nil {
		operationID = transaction.Internal.CauseOperationID
		if operationID == "" {
			operationID = transaction.Internal.ID
		}
	}
	if len(transaction.Effects) != 0 {
		operationID = transaction.Effects[0].OperationID
	}
	commit := api.Commit{Operation: api.Operation{ID: operationID, Status: "succeeded"}, FirstSeq: m.seq + 1}
	if m.commitError != nil {
		commit.Operation.Status, commit.Operation.Error = "failed", m.commitError
		commit.Reply = &api.RPCReply{Error: m.commitError}
		return commit, nil
	}
	writes := make(map[api.ID]api.Mail)
	for _, mail := range transaction.Writes.Mail {
		writes[mail.ID] = mail
	}
	events := append([]api.Event{}, transaction.Events...)
	seq := m.seq
	for i, event := range events {
		seq++
		event.Seq, event.OperationID = seq, operationID
		if event.Kind == "mail.queued" {
			var mail api.Mail
			if err := json.Unmarshal(event.Payload, &mail); err != nil {
				return api.Commit{}, err
			}
			write, exists := writes[mail.ID]
			if !exists || !reflect.DeepEqual(write, mail) {
				return api.Commit{}, problem(api.CodeIntegrity, "fixture mail event differs from its write")
			}
			mail.QueuedSeq = event.Seq
			writes[mail.ID] = mail
			var err error
			event.Payload, err = json.Marshal(mail)
			if err != nil {
				return api.Commit{}, err
			}
		}
		if event.Kind == "report.submitted" {
			var report api.Mail
			if err := json.Unmarshal(event.Payload, &report); err != nil {
				return api.Commit{}, err
			}
			var err error
			event.Payload, err = json.Marshal(writes[report.ID])
			if err != nil {
				return api.Commit{}, err
			}
		}
		events[i] = event
	}
	effects := append([]api.Effect{}, transaction.Effects...)
	for i := range effects {
		if effects[i].Deliver != nil {
			kept := writes[effects[i].Deliver.ID]
			effects[i].Deliver = &kept
		}
	}
	if transaction.Reply != nil {
		reply := *transaction.Reply
		if reply.Error == nil {
			var mail api.Mail
			if err := json.Unmarshal(reply.Result, &mail); err != nil {
				return api.Commit{}, err
			}
			var err error
			reply.Result, err = json.Marshal(writes[mail.ID])
			if err != nil {
				return api.Commit{}, err
			}
		}
		commit.Reply = &reply
	}
	for id, mail := range writes {
		m.mail[id] = mail
	}
	for _, guard := range transaction.Guards {
		if guard.Proof != nil {
			proof := m.proofs[guard.Proof.Proof.ID]
			proof.ConsumedBy = operationID
			m.proofs[proof.Ref.ID] = proof
		}
	}
	m.seq, commit.LastSeq = seq, seq
	m.events = append(m.events, events...)
	m.effects = append(m.effects, effects...)
	for _, effect := range effects {
		m.effectRows[effect.ID] = api.EffectRecord{Effect: effect, Generation: 1, State: "pending", LastSeq: seq}
	}
	m.transactions = append(m.transactions, transaction)
	m.commits[domain], m.digests[domain] = commit, requestDigest
	if transaction.Internal == nil {
		m.receipts[domain] = api.MutationReceipt{Config: scope.Config, Key: api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey, RequestSHA256: requestDigest},
			Actor: scope.Actor, Operation: commit.Operation, Reply: commit.Reply, RawRequest: append([]byte{}, transaction.RawRequest...), FirstSeq: commit.FirstSeq, LastSeq: commit.LastSeq}
	}
	return commit, nil
}

type testClock struct{ now time.Time }

func (c testClock) Now() time.Time { return c.now }

type testAuth struct {
	api.Authenticator
	store  *memoryStore
	humans map[api.ID]bool
	fail   error
}

func (a *testAuth) Authorize(_ context.Context, scope api.Scope, request api.Request) error {
	if a.fail != nil {
		return a.fail
	}
	if scope.Actor.Kind == "scheduler" || scope.Actor.Kind == "service" {
		if scope.Actor.ID == "scheduler" || scope.Actor.ID == "observer" {
			return nil
		}
	}
	if scope.Actor.Kind == "human" && a.humans[scope.Actor.ID] {
		if !api.Methods[request.Method].Mutation || request.Proof != nil && request.Proof.RequestSHA256 == request.RequestSHA256 {
			return nil
		}
	}
	launch, ok := a.store.launches[scope.LaunchID]
	if scope.Actor.Kind == "lane" && ok && !launch.Revoked && launch.Target.LifeID == scope.Actor.LifeID {
		return nil
	}
	return problem(api.CodeUnauthenticated, "fixture did not authenticate this requester")
}

type testGrants struct {
	api.GrantResolver
	store   *memoryStore
	checked []api.ID
	fail    error
}

func (g *testGrants) Revalidate(_ context.Context, grants api.GrantSet) (api.GrantSet, error) {
	g.checked = append(g.checked, grants.ID)
	if g.fail != nil {
		return api.GrantSet{}, g.fail
	}
	current, exists := g.store.grants[grants.ID]
	if !exists {
		return api.GrantSet{}, problem(api.CodeNotFound, "fixture grants disappeared")
	}
	return current, nil
}

type fixture struct {
	service *Service
	store   *memoryStore
	auth    *testAuth
	grants  *testGrants
	clock   testClock
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	memory := &memoryStore{
		lanes: map[api.ID]api.Lane{}, launches: map[api.ID]api.LaunchRecord{}, grants: map[api.ID]api.GrantSet{},
		blobs: map[api.ID][]byte{}, mail: map[api.ID]api.Mail{}, commits: map[string]api.Commit{}, digests: map[string]api.Digest{},
		receipts: map[string]api.MutationReceipt{},
		metadata: map[api.ID]api.ObjectMetadata{}, channels: map[api.ID]api.EnrolledChannel{}, workerLeases: map[api.ID]api.WorkerLease{},
		enrollments: map[api.ID]api.HumanEnrollment{},
		effectRows:  map[api.ID]api.EffectRecord{}, turns: map[api.ID]api.TurnSnapshot{}, proofs: map[api.ID]api.VerifiedHumanProof{},
	}
	f := &fixture{
		store: memory, clock: testClock{time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)},
		auth: &testAuth{store: memory, humans: map[api.ID]bool{"reviewer": true}}, grants: &testGrants{store: memory},
	}
	var err error
	f.service, err = New(Dependencies{Store: memory, Clock: f.clock, Authenticator: f.auth, Grants: f.grants, Human: &testHuman{store: memory}})
	if err != nil {
		t.Fatal(err)
	}
	f.add("root", "", 6)
	f.add("a5", "root", 5)
	f.add("b5", "root", 5)
	f.add("a4", "a5", 4)
	f.add("peer4", "a5", 4)
	f.add("b4", "b5", 4)
	f.add("a3", "a4", 3)
	f.add("peer3", "a4", 3)
	f.add("cousin3", "peer4", 3)
	f.add("direct3", "a5", 3)
	f.add("b3", "b4", 3)
	f.add("other", "", 6)
	return f
}

func (f *fixture) add(id, parent api.ID, level int) {
	taskBytes := []byte("Task for " + string(id) + "\n")
	task := api.BlobRef{ID: api.ID("task-" + string(id)), SHA256: hashBytes(taskBytes), Bytes: int64(len(taskBytes)), Class: "task"}
	f.store.blobs[task.ID] = taskBytes
	f.store.metadata[task.ID] = api.ObjectMetadata{Ref: task, ACL: api.ObjectACL{Config: "fixture", Generation: 1}, Origin: "fixture", SourceOperationID: api.ID("setup-" + string(id)), CommittedAt: api.Timestamp(f.clock.now.Format(time.RFC3339Nano))}
	row := api.Lane{
		Task: task, CancellationEpoch: 1, LaunchID: api.ID("launch-" + string(id)),
		LifeID: id, Name: string(id), ParentLifeID: parent, RootLifeID: id, StarterChain: []api.ID{},
		Level: level, Role: "executor", State: "running", Run: 1, Generation: 1, GrantSetID: api.ID("grants-" + string(id)), PolicyGeneration: 1,
	}
	if parent != "" {
		ancestor := f.store.lanes[parent]
		row.RootLifeID = ancestor.RootLifeID
		row.StarterChain = append(append([]api.ID{}, ancestor.StarterChain...), parent)
		row.StarterEventSeq = api.Sequence(len(f.store.lanes))
	}
	f.store.lanes[id] = row
	grants := api.GrantSet{ID: row.GrantSetID, LifeID: id, ParentLifeID: parent, SHA256: hashBytes([]byte(id)), Generation: 1, PolicyGeneration: 1, Channels: []api.ChannelGrant{}, ExpiresAt: api.Timestamp(f.clock.now.Add(time.Hour).Format(time.RFC3339Nano))}
	f.store.grants[grants.ID] = grants
	launchID := api.ID("launch-" + string(id))
	f.store.launches[launchID] = api.LaunchRecord{
		ID: launchID, Config: "fixture", Target: api.LifeRef{LifeID: id, Run: row.Run}, ParentLifeID: parent,
		RootLifeID: row.RootLifeID, StarterChain: row.StarterChain, StarterEventSeq: row.StarterEventSeq,
		EndpointGeneration: 1, PolicyGeneration: 1, GrantSetID: grants.ID, GrantsSHA256: grants.SHA256,
	}
}

func randomID(t *testing.T) api.ID {
	t.Helper()
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		t.Fatal(err)
	}
	return api.ID(hex.EncodeToString(data[:]))
}

func (f *fixture) blob(t *testing.T, data []byte) api.BlobRef {
	t.Helper()
	id := randomID(t)
	f.store.blobs[id] = append([]byte{}, data...)
	ref := api.BlobRef{ID: id, SHA256: hashBytes(data), Bytes: int64(len(data)), Class: "report"}
	f.store.metadata[id] = api.ObjectMetadata{Ref: ref, ACL: api.ObjectACL{Config: "fixture", Generation: 1}, Origin: "fixture", SourceOperationID: randomID(t), CommittedAt: api.Timestamp(f.clock.now.Format(time.RFC3339Nano))}
	return ref
}

func (f *fixture) scope(t *testing.T, id api.ID, method api.Method, params any) api.Scope {
	t.Helper()
	row := f.store.lanes[id]
	scope := api.Scope{Config: "fixture", Source: "cli", EndpointGeneration: 1, PolicyGeneration: 1}
	if id == "reviewer" {
		scope.Actor = api.Actor{Kind: "human", ID: id}
		scope.Source = "dashboard"
	} else if id == "scheduler" {
		scope.Actor, scope.Source = api.Actor{Kind: "scheduler", ID: id}, "scheduler"
	} else {
		scope.Actor = api.Actor{Kind: "lane", ID: id, LifeID: id, Level: row.Level, Role: row.Role}
		scope.LaunchID = api.ID("launch-" + string(id))
	}
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	scope.Request, err = client.PrepareRequest(api.Request{Config: scope.Config, Protocol: api.Protocol, Schema: api.SchemaVersion, Method: method, Params: raw, RequestID: randomID(t), IdempotencyKey: randomID(t)})
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func (f *fixture) send(t *testing.T, from, to api.ID) api.Mail {
	t.Helper()
	data := []byte("Message " + string(randomID(t)) + "\n")
	request := api.MailSendRequest{RecipientLifeID: to, Content: f.blob(t, data)}
	result, err := f.service.MailSend(context.Background(), f.scope(t, from, "mail.send", request), request)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func wantCode(t *testing.T, err error, code api.ErrorCode) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("error = %v, want code %s", err, code)
	}
}

func TestMailRelations(t *testing.T) {
	rows := []struct {
		from, to api.ID
		allowed  bool
	}{
		{"a3", "peer3", true}, {"a4", "peer4", true}, {"a5", "b5", true},
		{"a5", "a3", true}, {"a4", "a3", true}, {"a5", "direct3", true},
		{"a3", "a4", true}, {"direct3", "a5", true},
		{"a3", "cousin3", false}, {"a3", "b3", false}, {"a3", "a5", false},
		{"a4", "b3", false}, {"a5", "other", false}, {"other", "a3", false}, {"root", "other", false},
	}
	for _, row := range rows {
		t.Run(string(row.from)+"-"+string(row.to), func(t *testing.T) {
			f := newFixture(t)
			request := api.MailSendRequest{RecipientLifeID: row.to, Content: f.blob(t, []byte("Actual relation input\n")), Ask: true}
			result, err := f.service.MailSend(context.Background(), f.scope(t, row.from, "mail.send", request), request)
			if !row.allowed {
				wantCode(t, err, api.CodeForbidden)
				if len(f.store.events) != 0 || len(f.store.effects) != 0 {
					t.Fatal("a refused relation produced an event or effect")
				}
				return
			}
			if err != nil || result.Sender.LifeID != row.from || result.RecipientLifeID != row.to || result.Content != request.Content || !result.Ask || result.QueuedSeq == 0 || result.Status != "queued" {
				t.Fatalf("mail enqueue receipt = %+v, error = %v", result, err)
			}
			if len(f.store.events) != 1 || len(f.store.effects) != 1 || f.store.effects[0].Deliver == nil || f.store.events[0].Actor != result.Sender || f.store.events[0].RequestedBy != result.Sender {
				t.Fatal("mail intent, actor and delivery effect were not committed together")
			}
		})
	}
}

func TestQueueRetryAndConflict(t *testing.T) {
	f := newFixture(t)
	request := api.MailSendRequest{RecipientLifeID: "peer3", Content: f.blob(t, []byte("First immutable input\n"))}
	scope := f.scope(t, "a3", "mail.send", request)
	first, err := f.service.MailSend(context.Background(), scope, request)
	if err != nil {
		t.Fatal(err)
	}
	changed := f.store.mail[first.ID]
	changed.Status, changed.LogicalTurnID = "delivered", "turn-completed"
	f.store.mail[first.ID] = changed
	scope.Request.RequestID = randomID(t)
	second, err := f.service.MailSend(context.Background(), scope, request)
	if err != nil || !reflect.DeepEqual(first, second) || len(f.store.events) != 1 || len(f.store.effects) != 1 {
		t.Fatalf("retry did not return the original enqueue receipt: %v", err)
	}
	request.Content = f.blob(t, []byte("Different immutable input\n"))
	newScope := f.scope(t, "a3", "mail.send", request)
	newScope.Request.IdempotencyKey = scope.Request.IdempotencyKey
	_, err = f.service.MailSend(context.Background(), newScope, request)
	wantCode(t, err, api.CodeIdempotencyConflict)
	if len(f.store.events) != 1 || len(f.store.effects) != 1 {
		t.Fatal("a changed-content retry duplicated the durable effect")
	}
}

func TestCommitRechecksGeneration(t *testing.T) {
	f := newFixture(t)
	request := api.MailSendRequest{RecipientLifeID: "peer3", Content: f.blob(t, []byte("Race input"))}
	f.store.beforeCommit = func() {
		row := f.store.lanes[request.RecipientLifeID]
		row.Generation++
		f.store.lanes[row.LifeID] = row
	}
	_, err := f.service.MailSend(context.Background(), f.scope(t, "a3", "mail.send", request), request)
	wantCode(t, err, api.CodeConflict)
	if len(f.store.events) != 0 || len(f.store.effects) != 0 {
		t.Fatal("a failed compare wrote mail")
	}
}

func TestCommitErrorNeverSucceeds(t *testing.T) {
	f := newFixture(t)
	request := api.MailSendRequest{RecipientLifeID: "peer3", Content: f.blob(t, []byte("Failed operation input"))}
	f.store.commitError = problem(api.CodeUnavailable, "fixture durable operation failed")
	result, err := f.service.MailSend(context.Background(), f.scope(t, "a3", "mail.send", request), request)
	if err != f.store.commitError || result.ID != "" {
		t.Fatalf("failed durable operation returned a successful mail receipt: %v", err)
	}
}

func TestHumanMailNeedsProof(t *testing.T) {
	f := newFixture(t)
	request := api.MailSendRequest{RecipientLifeID: "a3", Content: f.blob(t, []byte("Human message\n"))}
	scope := f.scope(t, "reviewer", "mail.send", request)
	wantCode(t, f.service.authorize(context.Background(), scope, "mail.send", request), api.CodeUnauthenticated)
	_, err := f.service.MailSend(context.Background(), scope, request)
	wantCode(t, err, api.CodeUnauthenticated)
	if len(f.store.events) != 0 {
		t.Fatal("an unsigned human request queued mail")
	}
	scope.Request.Proof = &api.ProofRef{ID: "proof", RequestSHA256: scope.Request.RequestSHA256, ExpiresAt: api.Timestamp(f.clock.now.Add(time.Minute).Format(time.RFC3339Nano))}
	f.confirmProof(t, scope)
	result, err := f.service.MailSend(context.Background(), scope, request)
	if err != nil || result.Sender.Kind != "human" || result.Source != "dashboard" || result.RecipientLifeID != "a3" || result.Content != request.Content {
		t.Fatalf("verified human mail = %+v, error = %v", result, err)
	}
	f.auth.fail = problem(api.CodeUnauthenticated, "fixture human session revoked")
	_, err = f.service.MailSend(context.Background(), scope, request)
	wantCode(t, err, api.CodeUnauthenticated)
}

func TestBoundariesPropagateErrors(t *testing.T) {
	f := newFixture(t)
	request := api.MailSendRequest{RecipientLifeID: "peer3", Content: f.blob(t, []byte("Boundary input"))}
	scope := f.scope(t, "a3", "mail.send", request)
	f.store.failure = api.NotImplemented("lb-v2-service", "store.Lane")
	_, err := f.service.MailSend(context.Background(), scope, request)
	if err != f.store.failure {
		t.Fatalf("store failure was changed or swallowed: %v", err)
	}
	f.store.failure = nil
	f.grants.fail = api.NotImplemented("lb-v2-grants", "grants.Revalidate")
	_, err = f.service.MailSend(context.Background(), scope, request)
	if err != f.grants.fail || len(f.store.events) != 0 {
		t.Fatalf("grant failure was changed or mail was queued: %v", err)
	}
}

func TestChannelAndArtifactGates(t *testing.T) {
	for _, id := range []api.ID{"a3", "a4", "a5", "root"} {
		t.Run(string(id), func(t *testing.T) {
			f := newFixture(t)
			row := f.store.lanes[id]
			grants := f.store.grants[row.GrantSetID]
			grants.Channels = []api.ChannelGrant{{ID: "channel-grant", ChannelID: "sink", ExpiresAt: grants.ExpiresAt}}
			f.store.grants[grants.ID] = grants
			f.enroll(t, "sink")
			request := api.MailSendRequest{ChannelGrantID: "channel-grant", Content: f.blob(t, []byte("Channel input"))}
			mail, err := f.service.MailSend(context.Background(), f.scope(t, id, "mail.send", request), request)
			if row.Level < 5 {
				wantCode(t, err, api.CodeForbidden)
				if len(f.store.effects) != 0 || len(f.store.events) != 0 {
					t.Fatal("a forbidden channel created a delivery")
				}
			} else {
				wantCode(t, err, api.CodeNotImplemented)
				if mail.ID != "" || len(f.store.events) != 0 || len(f.store.effects) != 0 || err.Error() != "not_implemented: channel.job.prepare is not implemented" {
					t.Fatalf("unavailable channel worker created a broken intent: %v", err)
				}
			}
		})
	}
	f := newFixture(t)
	request := api.ReportRequest{Content: f.blob(t, []byte("Report with artifact")), Ask: true, Artifacts: []api.BlobRef{f.typedBlob(t, []byte("artifact"), "artifact")}}
	mail, err := f.service.ReportSubmit(context.Background(), f.scope(t, "a3", "report.submit", request), request)
	if err != nil || !mail.Ask || !reflect.DeepEqual(mail.Artifacts, request.Artifacts) || len(f.store.events) != 2 || !reflect.DeepEqual(f.store.effects[0].Deliver.Artifacts, request.Artifacts) {
		t.Fatalf("report dropped its artifacts or question: %v", err)
	}
}

func TestDirectReportAndReply(t *testing.T) {
	f := newFixture(t)
	question := f.send(t, "a5", "direct3")
	request := api.ReportRequest{Content: f.blob(t, []byte("Actual answer")), Artifacts: []api.BlobRef{}, ReplyTo: question.ID}
	result, err := f.service.ReportSubmit(context.Background(), f.scope(t, "direct3", "report.submit", request), request)
	if err != nil || result.RecipientLifeID != "a5" || result.ReplyTo != question.ID {
		t.Fatalf("direct report/reply = %+v, error = %v", result, err)
	}
	if len(f.store.events) != 3 || f.store.events[2].Kind != "report.submitted" {
		t.Fatal("report did not retain both queue and report events")
	}
	request.ReplyTo = question.ID
	_, err = f.service.ReportSubmit(context.Background(), f.scope(t, "a3", "report.submit", request), request)
	wantCode(t, err, api.CodeNotFound)
}

func TestLifeReuseAndLaunchDrift(t *testing.T) {
	f := newFixture(t)
	old := f.store.lanes["peer3"]
	old.Cleaned, old.Generation = true, old.Generation+1
	f.store.lanes[old.LifeID] = old
	f.add("replacement", "b4", 3)
	replacement := f.store.lanes["replacement"]
	replacement.Name = old.Name
	f.store.lanes[replacement.LifeID] = replacement
	request := api.MailSendRequest{RecipientLifeID: old.LifeID, Content: f.blob(t, []byte("Old rights must not transfer"))}
	_, err := f.service.MailSend(context.Background(), f.scope(t, "a3", "mail.send", request), request)
	wantCode(t, err, api.CodeForbidden)
	request.RecipientLifeID = replacement.LifeID
	_, err = f.service.MailSend(context.Background(), f.scope(t, "a3", "mail.send", request), request)
	wantCode(t, err, api.CodeForbidden)
	request.RecipientLifeID = "a4"
	scope := f.scope(t, "a3", "mail.send", request)
	launch := f.store.launches[scope.LaunchID]
	launch.EndpointGeneration++
	f.store.launches[scope.LaunchID] = launch
	_, err = f.service.MailSend(context.Background(), scope, request)
	wantCode(t, err, api.CodeUnauthenticated)
	launch.EndpointGeneration--
	launch.GrantsSHA256 = hashBytes([]byte("changed launch scope"))
	f.store.launches[scope.LaunchID] = launch
	_, err = f.service.MailSend(context.Background(), scope, request)
	wantCode(t, err, api.CodeUnauthenticated)
	if len(f.store.events) != 0 {
		t.Fatal("reused names or stale endpoints conferred mail rights")
	}
}

func TestTurnChecksEverySender(t *testing.T) {
	f := newFixture(t)
	first, second := f.send(t, "a5", "a3"), f.send(t, "peer3", "a3")
	scope, request := f.delivery(t, first, second)
	grants := f.store.grants[f.store.lanes["peer3"].GrantSetID]
	grants.Revoked = true
	f.store.grants[grants.ID] = grants
	_, err := f.service.BeginDelivery(context.Background(), scope, request)
	wantCode(t, err, api.CodeForbidden)
	if f.store.mail[first.ID].Status != "queued" || f.store.mail[second.ID].Status != "queued" {
		t.Fatal("a later invalid sender changed the leased batch")
	}
	grants.Revoked = false
	f.store.grants[grants.ID] = grants
	before := scope.Actor
	batch, err := f.service.BeginDelivery(context.Background(), scope, request)
	if err != nil || len(batch.Mail) != 2 || batch.Mail[0].Sender.LifeID != "a5" || batch.Mail[1].Sender.LifeID != "peer3" || scope.Actor != before || batch.Intent.Actor != before || batch.Intent.RequestedBy == first.Sender {
		t.Fatalf("carried senders or actual turn requester changed: %v", err)
	}
	if len(f.store.events) != 2 {
		t.Fatal("begin delivery prematurely acknowledged mail")
	}
	other := newFixture(t)
	old, later := other.send(t, "a5", "a3"), other.send(t, "peer3", "a3")
	reverseScope, reverse := other.delivery(t, later, old)
	_, err = other.service.BeginDelivery(context.Background(), reverseScope, reverse)
	wantCode(t, err, api.CodeConflict)
}

func TestPrivateMailbox(t *testing.T) {
	f := newFixture(t)
	mail := f.send(t, "a3", "peer3")
	request := api.ListRequest{Limit: 1}
	scope := f.scope(t, "a3", "mail.list", request)
	page, err := f.service.MailList(context.Background(), scope, request)
	if err != nil || len(page.Messages) != 1 || page.Messages[0].ID != mail.ID {
		t.Fatalf("own mailbox = %+v, error = %v", page, err)
	}
	f.store.leak = &mail
	_, err = f.service.MailList(context.Background(), f.scope(t, "b3", "mail.list", request), request)
	wantCode(t, err, api.CodeIntegrity)
	request.LifeID = "a3"
	_, err = f.service.MailList(context.Background(), f.scope(t, "b3", "mail.list", request), request)
	wantCode(t, err, api.CodeForbidden)
}

func TestReceiptUsesLogicalCompletion(t *testing.T) {
	f := newFixture(t)
	mail := f.send(t, "a5", "a3")
	mail.Status, mail.LogicalTurnID = "delivering", "logical-turn"
	f.store.mail[mail.ID] = mail
	target := api.LifeRef{LifeID: "a3", Run: 2}
	zero, survivors := 0, uint64(0)
	observed := api.Timestamp(f.clock.now.Format(time.RFC3339Nano))
	turn := api.TurnEvent{Trigger: api.Trigger{Kind: "mail", MailIDs: []api.ID{mail.ID}, CausingSeqs: []api.Sequence{mail.QueuedSeq}}, Prompt: mail.Content, Status: "written", MailIDs: []api.ID{mail.ID}}
	turnRaw, err := json.Marshal(turn)
	if err != nil {
		t.Fatal(err)
	}
	end := api.RunEndEvent{LaunchID: "launch-end", Reason: "exit", Observation: api.ProcessObservation{Handle: api.ProcessHandle{ID: "process", Target: target, ContainmentID: "containment", Generation: "epoch"}, State: "exited", ExitCode: &zero, Survivors: &survivors, PromptStatus: "completed", ObservedAt: observed}}
	endRaw, err := json.Marshal(end)
	if err != nil {
		t.Fatal(err)
	}
	makeEvent := func(kind api.EventKind, seq api.Sequence, run api.RunNumber, payload json.RawMessage) api.Event {
		return api.Event{Schema: api.SchemaVersion, ID: api.ID("event-" + strconv.Itoa(int(seq))), Config: "fixture", Kind: kind, LifeID: target.LifeID, Run: run, LogicalTurnID: mail.LogicalTurnID, Origin: "service", Seq: seq, Payload: payload}
	}
	f.store.events = append(f.store.events, makeEvent("lane.turn", 2, 1, turnRaw), makeEvent("lane.ended", 3, target.Run, endRaw))
	scope := api.Scope{Config: "fixture", Source: "worker", Actor: api.Actor{Kind: "service", ID: "observer"}}
	receipt := api.MailReceipt{MailID: mail.ID, Target: target, LogicalTurnID: mail.LogicalTurnID, Status: "delivered", PromptStatus: "completed", Cause: "exit", ObservedAt: observed}
	if err := f.service.ValidateReceipt(context.Background(), scope, receipt); err != nil {
		t.Fatal(err)
	}
	completed, observer, delivery := completedDelivery(t)
	if _, err := completed.service.RecordDelivery(context.Background(), observer, delivery); err != nil || completed.store.mail[delivery.MailID].Status != "delivered" {
		t.Fatalf("receipt persistence did not update mail: %v", err)
	}
	end.Reason, end.ProfileContinuation = "limit", true
	endRaw, err = json.Marshal(end)
	if err != nil {
		t.Fatal(err)
	}
	f.store.events[len(f.store.events)-1].Payload = endRaw
	receipt.Cause = "limit"
	wantCode(t, f.service.ValidateReceipt(context.Background(), scope, receipt), api.CodeConflict)
	receipt.Status = "returned"
	wantCode(t, f.service.ValidateReceipt(context.Background(), scope, receipt), api.CodeConflict)
	f.store.events[len(f.store.events)-1].Origin = "legacy_import"
	wantCode(t, f.service.ValidateReceipt(context.Background(), scope, receipt), api.CodeConflict)
	if f.store.mail[mail.ID].Status != "delivering" {
		t.Fatal("validation changed the mail outcome")
	}
}

func TestBlobBoundsAndHash(t *testing.T) {
	for _, size := range []int{32, MaxMailBytes} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			f := newFixture(t)
			data := []byte(strings.Repeat("m", size))
			ref := f.blob(t, data)
			request := api.MailSendRequest{RecipientLifeID: "peer3", Content: ref}
			scope := f.scope(t, "a3", "mail.send", request)
			kept, err := f.service.content(context.Background(), scope, ref)
			if err != nil || !reflect.DeepEqual(kept, data) {
				t.Fatalf("original blob bytes changed: %v", err)
			}
			f.store.blobs[ref.ID] = append(data, 'x')
			_, err = f.service.content(context.Background(), scope, ref)
			wantCode(t, err, api.CodeIntegrity)
			f.store.blobs[ref.ID] = data
			f.store.badChunk = true
			_, err = f.service.content(context.Background(), scope, ref)
			wantCode(t, err, api.CodeIntegrity)
		})
	}
}

func TestExpiredAndBorrowedGrants(t *testing.T) {
	f := newFixture(t)
	request := api.MailSendRequest{RecipientLifeID: "peer3", Content: f.blob(t, []byte("Expired grant input"))}
	row := f.store.lanes["a3"]
	grants := f.store.grants[row.GrantSetID]
	grants.ExpiresAt = api.Timestamp(f.clock.now.Add(-time.Minute).Format(time.RFC3339Nano))
	f.store.grants[grants.ID] = grants
	_, err := f.service.MailSend(context.Background(), f.scope(t, "a3", "mail.send", request), request)
	wantCode(t, err, api.CodeForbidden)
	grants.ExpiresAt = api.Timestamp(f.clock.now.Add(time.Hour).Format(time.RFC3339Nano))
	grants.LifeID = "a5"
	f.store.grants[grants.ID] = grants
	_, err = f.service.MailSend(context.Background(), f.scope(t, "a3", "mail.send", request), request)
	wantCode(t, err, api.CodeUnauthenticated)
	if len(f.store.events) != 0 || len(f.store.effects) != 0 {
		t.Fatal("expired or borrowed rights reached the outbox")
	}
}

func TestInternalChannelStaysClosed(t *testing.T) {
	err := RunInternal(context.Background(), "fixture", []string{"--channel", "sink", "--from", "human"})
	wantCode(t, err, api.CodeNotImplemented)
}
