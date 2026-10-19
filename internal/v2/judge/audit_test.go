package judge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
	"laneboss.io/laneboss/internal/v2/judge/wire"
)

// This store is an explicit in-memory completion fixture. It enforces the
// draft.4 shape and current fence and records the exact transaction submitted.
// It is not the missing production dispatch/reservation implementation.
type auditStore struct {
	*scopedStore
	objects     map[api.ID][]byte
	refs        map[api.ID]api.BlobRef
	transaction api.Transaction
	stored      api.JudgeAudit
	failCommit  error
	dropWrite   bool
	badRead     bool
	reads       int
}

func (s *auditStore) ObjectMetadata(ctx context.Context, scope api.Scope, id api.ID) (api.ObjectMetadata, error) {
	if ref, ok := s.refs[id]; ok {
		return api.ObjectMetadata{Ref: ref, ACL: api.ObjectACL{Config: scope.Config, LifeID: s.lane.LifeID}}, nil
	}
	return s.scopedStore.ObjectMetadata(ctx, scope, id)
}

func (s *auditStore) Blob(ctx context.Context, scope api.Scope, request api.BlobReadRequest) (api.BlobChunk, error) {
	if data, ok := s.objects[request.ObjectID]; ok {
		s.reads++
		if request.Offset < 0 || request.Offset >= int64(len(data)) || request.Limit < 1 || request.Limit > api.MaxChunkBytes {
			return api.BlobChunk{}, problem(api.CodeInvalid, "fixture audit blob bounds differ")
		}
		part := bytes.Clone(data[int(request.Offset):min(len(data), int(request.Offset)+request.Limit)])
		return api.BlobChunk{ObjectID: request.ObjectID, Offset: request.Offset, Data: part, SHA256: wire.Digest(part)}, ctx.Err()
	}
	return s.scopedStore.Blob(ctx, scope, request)
}

func (s *auditStore) Transact(ctx context.Context, transaction api.Transaction) (api.Commit, error) {
	s.transaction = transaction
	if s.failCommit != nil {
		return api.Commit{}, s.failCommit
	}
	if err := api.ValidateTransactionShape(transaction); err != nil {
		return api.Commit{}, err
	}
	if transaction.Internal == nil || transaction.Internal.Kind != api.InternalJudgeEvaluate || transaction.Reply != nil ||
		len(transaction.Writes.JudgeAudits) != 1 || len(transaction.Events) != 1 || transaction.Events[0].Kind != "judge.completed" ||
		len(transaction.Guards) != 1 || transaction.Guards[0].Cancellation == nil ||
		transaction.Guards[0].Cancellation.Epoch != s.lane.CancellationEpoch {
		return api.Commit{}, problem(api.CodeIntegrity, "fixture audit write matrix differs")
	}
	if !s.dropWrite {
		s.stored = transaction.Writes.JudgeAudits[0]
		s.stored.Reply = cloneReply(s.stored.Reply)
	}
	return api.Commit{Operation: api.Operation{ID: transaction.Internal.CauseOperationID, Status: "succeeded"}, FirstSeq: 1, LastSeq: 1}, ctx.Err()
}

func (s *auditStore) JudgeAudit(ctx context.Context, scope api.Scope, id api.ID) (api.JudgeAudit, error) {
	if scope.ReadView != nil {
		return api.JudgeAudit{}, problem(api.CodeNotFound, "fixture snapshot predates audit")
	}
	if s.stored.ID != id {
		return api.JudgeAudit{}, problem(api.CodeNotFound, "fixture audit missing")
	}
	audit := s.stored
	audit.Reply = cloneReply(audit.Reply)
	if s.badRead {
		audit.Reply.SelectedModel = "changed-model"
	}
	return audit, ctx.Err()
}

type auditReadView struct{ snapshot api.ReadSnapshot }

func (v *auditReadView) Snapshot() api.ReadSnapshot { return v.snapshot }
func (v *auditReadView) Close() error               { v.snapshot = api.ReadSnapshot{}; return nil }

func auditFixture(t *testing.T) (*Service, *auditStore, api.Scope, api.InternalIntent, api.JudgeRequest, api.JudgeAudit) {
	t.Helper()
	s, base, _, scope, request := serviceFixture(t)
	request, err := s.resolveRequest(context.Background(), scope, request)
	if err != nil {
		t.Fatal(err)
	}
	// Use the shared correlation-ID encoding without retries or filtering.
	// Short textual IDs have a separate scored structured-metadata control.
	request.ID, err = client.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	store := &auditStore{scopedStore: base, objects: map[api.ID][]byte{}, refs: map[api.ID]api.BlobRef{}}
	s.deps.Store = store
	responses := make(chan []byte, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Error(err)
			return
		}
		var root struct {
			Model     string
			Questions map[string]json.RawMessage
		}
		if err := json.Unmarshal(body, &root); err != nil {
			t.Error(err)
			return
		}
		answers := map[string]any{}
		for id := range root.Questions {
			answers[id] = map[string]any{"type": "noul", "noul": float64(len(body)) / float64(len(body)+1)}
		}
		response := map[string]any{"model": root.Model, "answers": answers,
			"usage":   map[string]any{"input_tokens": len(body), "output_tokens": 0},
			"request": "fixture-provider-a"}
		raw, err := json.Marshal(response)
		if err != nil {
			t.Error(err)
			return
		}
		// Keep a multi-chunk raw response using legal JSON whitespace.
		// Unknown members such as note violate the closed response schema.
		raw = append(raw, strings.Repeat(" \t", 135000)...)
		responses <- bytes.Clone(raw)
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(raw); err != nil {
			t.Errorf("audit fixture reply failed: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	fit := func(ctx context.Context, body []byte) (api.TokenFit, error) {
		return api.TokenFit{Proved: true, InputBytes: len(body), InputTokens: len(body),
			ContextTokens: request.Config.ContextTokens, TokenizerSHA256: request.Config.TokenizerSHA256}, ctx.Err()
	}
	keep := func(ctx context.Context, class string, data []byte) (api.BlobRef, error) {
		id := api.ID(class + "-a")
		ref := api.BlobRef{ID: id, Class: class, Bytes: int64(len(data)), SHA256: wire.Digest(data)}
		store.objects[id], store.refs[id] = bytes.Clone(data), ref
		return ref, ctx.Err()
	}
	provider, err := wire.New(wire.Options{Endpoint: server.URL, Config: request.Config,
		Fit: fit, SafetyTokens: 32, Retain: keep, Cost: func(in, out int64) (int64, error) { return in + out, nil },
		ReserveMicros: request.MaxCostMicros})
	if err != nil {
		t.Fatal(err)
	}
	reply, err := provider.Evaluate(context.Background(), request)
	if err != nil {
		t.Fatalf("audit fixture exchange failed: %v", err)
	}
	if reply.Status != "scored" {
		t.Fatalf("audit fixture exchange failed: "+
			"status=%s error=%v reason=%s", reply.Status, err, reply.UnavailableReason)
	}
	var observed []byte
	select {
	case observed = <-responses:
	default:
		t.Fatal("audit fixture HTTP was not observed")
	}
	if len(observed) <= api.MaxChunkBytes || reply.Raw == nil ||
		reply.Raw.Bytes != int64(len(observed)) || reply.Raw.SHA256 != wire.Digest(observed) ||
		!bytes.Equal(store.objects[reply.Raw.ID], observed) {
		t.Fatal("audit fixture raw bytes differ")
	}
	body, _, err := wire.Payload(request)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := fit(context.Background(), body)
	if err != nil {
		t.Fatal(err)
	}
	now := s.deps.Clock.Now()
	audit := api.JudgeAudit{ID: request.ID, Request: *reply.Request, Reply: reply, Fit: proof,
		StartedAt:   api.Timestamp(now.Add(-time.Second).UTC().Format(time.RFC3339Nano)),
		CompletedAt: api.Timestamp(now.UTC().Format(time.RFC3339Nano))}
	intent := api.InternalIntent{ID: "judge-completion-a", Kind: api.InternalJudgeEvaluate, Config: scope.Config,
		Actor: api.Actor{Kind: "service", ID: "judge"}, RequestedBy: scope.Actor,
		CauseOperationID: "operation-a", CauseRequestID: "request-a", Target: request.Context.Target,
		LogicalTurnID: request.Context.LogicalTurnID, CancellationEpoch: base.lane.CancellationEpoch}
	return s, store, scope, intent, request, audit
}

func TestAuditWriteMatrix(t *testing.T) {
	s, store, scope, intent, request, audit := auditFixture(t)
	scope.ReadView = &auditReadView{snapshot: api.ReadSnapshot{ID: "before-audit", Config: scope.Config, PolicyGeneration: scope.PolicyGeneration}}
	got, err := s.CommitAudit(context.Background(), scope, intent, request, audit)
	if err != nil {
		t.Fatalf("audit completion write was lost: %v", err)
	}
	if !reflect.DeepEqual(got, audit.Reply) || store.reads < 3 ||
		!reflect.DeepEqual(store.transaction.Writes.JudgeAudits, []api.JudgeAudit{audit}) ||
		store.transaction.Scope.Request.Method != "" || store.transaction.Reply != nil ||
		len(store.transaction.Compare) != 2 {
		t.Fatal("audit completion write was lost")
	}
	public := store.transaction
	public.Internal, public.Scope.Request.Method = nil, "judge.ask"
	result, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	public.Reply = &api.RPCReply{Result: result}
	if api.ValidateTransactionShape(public) == nil {
		t.Fatal("public method accepted audit writes")
	}
	public.Writes, public.Events, public.Guards, public.Compare = api.StateWrites{}, nil, nil, nil
	if err := api.ValidateTransactionShape(public); err != nil {
		t.Fatal(err)
	}
	public.Reply = nil
	if api.ValidateTransactionShape(public) == nil {
		t.Fatal("mutation accepted a missing reply")
	}
	*got.Results[0].Probability = 0
	if *store.stored.Reply.Results[0].Probability == 0 {
		t.Fatal("audit result aliases stored score")
	}
}

func TestAuditRejectsChangedEvidence(t *testing.T) {
	for _, name := range []string{"kind", "requester", "epoch", "time", "request-bytes", "raw-bytes", "probability", "fit", "commit", "dropped", "readback"} {
		t.Run(name, func(t *testing.T) {
			s, store, scope, intent, request, audit := auditFixture(t)
			want := api.CodeIntegrity
			switch name {
			case "kind":
				intent.Kind = api.InternalEffectComplete
			case "requester":
				intent.RequestedBy.ID = "another-principal"
			case "epoch":
				intent.CancellationEpoch++
				want = api.CodeConflict
			case "time":
				audit.CompletedAt = audit.StartedAt
				audit.StartedAt = "2100-01-01T00:00:00Z"
			case "request-bytes":
				store.objects[audit.Request.ID][0] = 'x'
			case "raw-bytes":
				store.objects[audit.Reply.Raw.ID][0] = 'x'
			case "probability":
				*audit.Reply.Results[0].Probability = 0.125
			case "fit":
				audit.Fit.TokenizerSHA256 = wire.Digest([]byte("other tokenizer"))
			case "commit":
				store.failCommit = problem(api.CodeUnavailable, "fixture commit unavailable")
				want = api.CodeUnavailable
			case "dropped":
				store.dropWrite = true
				want = api.CodeNotFound
			case "readback":
				store.badRead = true
			}
			_, err := s.CommitAudit(context.Background(), scope, intent, request, audit)
			errorCode(t, err, want)
		})
	}
}

func TestAuditUnscreenedMetadata(t *testing.T) {
	for _, name := range []string{"joined-id", "reason", "literal-id"} {
		t.Run(name, func(t *testing.T) {
			s, store, scope, intent, request, audit := auditFixture(t)
			switch name {
			case "joined-id":
				// The old screen manufactured a credential by joining this
				// benign ID to unrelated object classes and digest metadata.
				request.ID, audit.ID, audit.Reply.ID = "ask-one", "ask-one", "ask-one"
				joined := string(audit.Reply.ID) + audit.Reply.Raw.Class +
					string(audit.Reply.Raw.ID) + string(audit.Reply.Raw.SHA256)
				if wire.Sensitive(string(request.ID), "") || !wire.Sensitive(joined, "") {
					t.Fatal("metadata join canary changed")
				}
			case "literal-id":
				id := api.ID("ask-" + strings.Repeat("a1", 16))
				request.ID, audit.ID, audit.Reply.ID = id, id, id
			case "reason":
				credential := "Bearer " + strings.Repeat("a1", 16)
				audit.Reply.Status, audit.Reply.UnavailableReason = "unavailable", credential
				for i := range audit.Reply.Results {
					audit.Reply.Results[i].Status = "unscored"
					audit.Reply.Results[i].Probability = nil
					audit.Reply.Results[i].Reason = credential
				}
			}
			// The canary must pass the actual prior byte/fit/score validation,
			// so a different refusal cannot stand in for metadata screening.
			raw := store.objects[audit.Reply.Raw.ID]
			if err := wire.AuditReply(audit.Reply, request, audit.Fit, raw); err != nil {
				t.Fatalf("metadata canary preflight failed: %v", err)
			}
			got, err := s.CommitAudit(context.Background(), scope, intent, request, audit)
			if name == "joined-id" {
				if err != nil || got.Status != "scored" || !reflect.DeepEqual(got.Results, audit.Reply.Results) ||
					store.stored.ID != request.ID || len(store.transaction.Writes.JudgeAudits) != 1 {
					t.Fatalf("benign metadata join withheld: %v", err)
				}
				return
			}
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeIntegrity ||
				typed.Message != "judge completion metadata "+"is not screened" {
				t.Fatalf("metadata escaped completion screen: %v", err)
			}
			if store.transaction.Internal != nil || store.stored.ID != "" {
				t.Fatal("unscreened completion was committed")
			}
		})
	}
}
