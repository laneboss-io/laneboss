package migration

import (
	"archive/tar"
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/eventstore"
	"laneboss.io/laneboss/internal/v2/api"
)

type memStore struct {
	api.StateStore
	blobs        map[api.ID][]byte
	transactions []api.Transaction
	events       []api.Event
	records      []api.Record
	mail         []api.Mail
	objects      map[api.ID]api.ObjectMetadata
	deployments  map[api.ID]api.DeploymentPlan
	backups      map[api.ID]api.FrozenBackup
	effects      map[api.ID]api.EffectRecord
	receipts     map[string]api.MutationReceipt
	consumed     map[api.ID]bool
	decisions    map[api.ID]api.DecisionProjection
}

func newMemStore() *memStore {
	return &memStore{blobs: make(map[api.ID][]byte), objects: make(map[api.ID]api.ObjectMetadata),
		deployments: make(map[api.ID]api.DeploymentPlan), backups: make(map[api.ID]api.FrozenBackup),
		effects: make(map[api.ID]api.EffectRecord), receipts: make(map[string]api.MutationReceipt),
		consumed: make(map[api.ID]bool), decisions: make(map[api.ID]api.DecisionProjection)}
}

func (m *memStore) putBlob(id string, data []byte, class string) api.BlobRef {
	bid := api.ID(id)
	cp := append([]byte(nil), data...)
	m.blobs[bid] = cp
	return api.BlobRef{
		ID:     bid,
		SHA256: DigestBytes(cp),
		Bytes:  int64(len(cp)),
		Class:  class,
	}
}

func (m *memStore) Transact(_ context.Context, tx api.Transaction) (api.Commit, error) {
	if err := api.ValidateTransactionShape(tx); err != nil {
		return api.Commit{}, err
	}
	for _, compare := range tx.Compare {
		var generation api.Generation
		switch compare.Kind {
		case api.CompareUpgrade:
			generation = m.deployments[compare.ID].Generation
		case api.CompareRecord:
			for _, record := range m.records {
				if record.ID == compare.ID {
					generation = record.Generation
				}
			}
		default:
			return api.Commit{}, invalidErr("fixture received an unsupported comparison")
		}
		if generation != compare.Generation {
			return api.Commit{}, conflictErr("fixture generation comparison failed")
		}
	}
	for _, guard := range tx.Guards {
		if guard.Proof != nil && m.consumed[guard.Proof.Proof.ID] {
			return api.Commit{}, forbiddenErr("proof already consumed at commit")
		}
	}
	for _, object := range tx.Writes.Objects {
		if DigestBytes(object.Bytes) != object.SHA256 {
			return api.Commit{}, integrityErr("fixture object bytes do not match their digest")
		}
	}
	var operation api.Operation
	if tx.Reply != nil {
		if tx.Reply.Error != nil {
			return api.Commit{Reply: tx.Reply}, nil
		}
		if err := api.DecodeObject(tx.Reply.Result, &operation); err != nil {
			return api.Commit{}, err
		}
	} else {
		operation.ID = tx.Internal.CauseOperationID
		operation.Status = "running"
	}
	m.transactions = append(m.transactions, tx)
	baseSeq := api.Sequence(len(m.events))
	for i := range tx.Events {
		ev := tx.Events[i]
		ev.Seq = baseSeq + api.Sequence(i+1)
		m.events = append(m.events, ev)
		switch ev.Kind {
		case "record.appended", "decision.changed":
			var rec api.Record
			if err := api.DecodeObject(ev.Payload, &rec); err != nil {
				return api.Commit{}, err
			}
			m.records = append(m.records, rec)
		case "mail.queued":
			var ml api.Mail
			if err := json.Unmarshal(ev.Payload, &ml); err == nil {
				m.mail = append(m.mail, ml)
			}
		}
	}
	for _, object := range tx.Writes.Objects {
		ref := m.putBlob(string(object.ObjectKey), object.Bytes, object.Class)
		m.objects[ref.ID] = api.ObjectMetadata{Ref: ref, ACL: object.ACL, Origin: object.Origin, SourceOperationID: operation.ID}
	}
	for _, deployment := range tx.Writes.Deployments {
		m.deployments[deployment.ID] = deployment
	}
	for _, effect := range tx.Effects {
		m.effects[effect.ID] = api.EffectRecord{Effect: effect, Generation: 1, State: "pending"}
	}
	for _, guard := range tx.Guards {
		if guard.Proof != nil {
			m.consumed[guard.Proof.Proof.ID] = true
		}
	}
	operation.FirstSeq, operation.LastSeq = baseSeq, api.Sequence(len(m.events))
	var reply *api.RPCReply
	if tx.Reply != nil {
		raw, err := json.Marshal(operation)
		if err != nil {
			return api.Commit{}, err
		}
		reply = &api.RPCReply{Result: raw}
		key := api.RequestKey{Method: tx.Scope.Request.Method, IdempotencyKey: tx.Scope.Request.IdempotencyKey, RequestSHA256: tx.Scope.Request.RequestSHA256}
		m.receipts[receiptDomain(tx.Scope, key)] = api.MutationReceipt{Config: tx.Scope.Config, Key: key, Actor: tx.Scope.Actor,
			Operation: operation, Reply: reply, RawRequest: append([]byte(nil), tx.RawRequest...), FirstSeq: operation.FirstSeq, LastSeq: operation.LastSeq}
	}
	return api.Commit{Reply: reply, Operation: operation, FirstSeq: operation.FirstSeq, LastSeq: operation.LastSeq}, nil
}

func receiptDomain(scope api.Scope, key api.RequestKey) string {
	return fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s\x00%s", scope.Config, scope.Actor.Kind, scope.Actor.ID, scope.Actor.LifeID, key.Method, key.IdempotencyKey)
}

func (m *memStore) LookupReceipt(_ context.Context, scope api.Scope, key api.RequestKey) (api.MutationReceipt, error) {
	receipt, exists := m.receipts[receiptDomain(scope, key)]
	if !exists {
		return api.MutationReceipt{}, &api.Error{Code: api.CodeNotFound, Message: "no receipt in this domain"}
	}
	if receipt.Key.RequestSHA256 != key.RequestSHA256 {
		return api.MutationReceipt{}, &api.Error{Code: api.CodeIdempotencyConflict, Message: "same key has different content"}
	}
	return receipt, nil
}

func (m *memStore) AwaitReceipt(ctx context.Context, scope api.Scope, key api.RequestKey) (api.MutationReceipt, error) {
	return m.LookupReceipt(ctx, scope, key)
}

func (m *memStore) ObjectMetadata(_ context.Context, _ api.Scope, id api.ID) (api.ObjectMetadata, error) {
	metadata, exists := m.objects[id]
	if !exists {
		return api.ObjectMetadata{}, &api.Error{Code: api.CodeNotFound, Message: "no retained object metadata"}
	}
	return metadata, nil
}

func (m *memStore) Deployment(_ context.Context, scope api.Scope, id api.ID) (api.DeploymentPlan, error) {
	plan, exists := m.deployments[id]
	if !exists || plan.Config != scope.Config {
		return api.DeploymentPlan{}, &api.Error{Code: api.CodeNotFound, Message: "no deployment"}
	}
	return plan, nil
}

func (m *memStore) FrozenBackup(_ context.Context, _ api.Scope, id api.ID) (api.FrozenBackup, error) {
	backup, exists := m.backups[id]
	if !exists {
		return api.FrozenBackup{}, &api.Error{Code: api.CodeNotFound, Message: "no frozen backup"}
	}
	return backup, nil
}

func (m *memStore) Effect(_ context.Context, _ api.Scope, id api.ID) (api.EffectRecord, error) {
	effect, exists := m.effects[id]
	if !exists {
		return api.EffectRecord{}, &api.Error{Code: api.CodeNotFound, Message: "no effect"}
	}
	return effect, nil
}

func (m *memStore) CompleteEffect(_ context.Context, _ api.Scope, outcome api.EffectOutcome) (api.Commit, error) {
	effect, exists := m.effects[outcome.EffectID]
	if !exists || effect.Generation != outcome.ExpectedGeneration || effect.ClaimID != outcome.ClaimID {
		return api.Commit{}, conflictErr("effect claim changed")
	}
	switch outcome.Status {
	case "succeeded":
		effect.State = api.EffectCompleted
	case "failed":
		effect.State = api.EffectFailed
	default:
		return api.Commit{}, invalidErr("fixture effect outcome must be terminal")
	}
	effect.Outcome = &outcome
	m.effects[outcome.EffectID] = effect
	return api.Commit{Operation: api.Operation{ID: effect.Effect.OperationID, Status: outcome.Status, LastSeq: api.Sequence(len(m.events))}}, nil
}

func (m *memStore) Decision(_ context.Context, _ api.Scope, id api.ID) (api.DecisionProjection, error) {
	decision, exists := m.decisions[id]
	if !exists {
		return api.DecisionProjection{}, &api.Error{Code: api.CodeNotFound, Message: "no canonical decision"}
	}
	return decision, nil
}

func (m *memStore) Operation(_ context.Context, _ api.Scope, id api.ID) (api.Operation, error) {
	for _, effect := range m.effects {
		if effect.Effect.OperationID == id {
			status := "pending"
			if effect.Outcome != nil {
				status = effect.Outcome.Status
			}
			return api.Operation{ID: id, Status: status, LastSeq: api.Sequence(len(m.events))}, nil
		}
	}
	return api.Operation{}, &api.Error{Code: api.CodeNotFound, Message: "no operation"}
}

func (m *memStore) Lane(_ context.Context, _ api.Scope, _ api.LifeRef) (api.Lane, error) {
	return api.Lane{}, api.NotImplemented("lb-v2-service", "store.Lane")
}

func (m *memStore) Lanes(_ context.Context, _ api.Scope, _ api.ListRequest) (api.LanePage, error) {
	return api.LanePage{Lanes: []api.Lane{}}, nil
}

func (m *memStore) Events(_ context.Context, _ api.Scope, _ api.EventTailRequest) (api.EventPage, error) {
	return api.EventPage{Events: m.events, Complete: true}, nil
}

func (m *memStore) Records(_ context.Context, _ api.Scope, q api.RecordQuery) (api.RecordPage, error) {
	var out []api.Record
	for _, r := range m.records {
		if (q.Collection == "" || r.Collection == q.Collection) && (q.RecordID == "" || r.ID == q.RecordID) {
			out = append(out, r)
		}
	}
	return api.RecordPage{Records: out}, nil
}

func (m *memStore) Blob(_ context.Context, _ api.Scope, req api.BlobReadRequest) (api.BlobChunk, error) {
	data, ok := m.blobs[req.ObjectID]
	if !ok {
		return api.BlobChunk{}, &api.Error{Code: api.CodeNotFound, Message: "blob not found"}
	}
	if req.Offset < 0 || req.Offset > int64(len(data)) {
		return api.BlobChunk{}, &api.Error{Code: api.CodeInvalid, Message: "invalid blob offset"}
	}
	end := int(req.Offset) + req.Limit
	if end > len(data) || req.Limit <= 0 {
		end = len(data)
	}
	slice := data[req.Offset:end]
	return api.BlobChunk{
		ObjectID: req.ObjectID,
		Offset:   req.Offset,
		Data:     slice,
		SHA256:   DigestBytes(slice),
	}, nil
}

func (m *memStore) Launch(_ context.Context, _ api.ID) (api.LaunchRecord, error) {
	return api.LaunchRecord{}, &api.Error{Code: api.CodeNotFound, Message: "no active launch"}
}

func (m *memStore) Grants(_ context.Context, _ api.ID) (api.GrantSet, error) {
	return api.GrantSet{}, nil
}

func (m *memStore) Policy(_ context.Context, _ api.Scope) (api.EffectivePolicy, error) {
	return api.EffectivePolicy{}, nil
}

func (m *memStore) Mail(_ context.Context, _ api.Scope, _ api.ListRequest) (api.MailPage, error) {
	return api.MailPage{Messages: m.mail}, nil
}

func (m *memStore) Change(_ context.Context, _ api.Scope, _ api.ID) (api.ChangeRequest, error) {
	return api.ChangeRequest{}, nil
}

func (m *memStore) PendingEffects(_ context.Context, _ api.CursorRequest) ([]api.Effect, error) {
	var out []api.Effect
	for _, tx := range m.transactions {
		out = append(out, tx.Effects...)
	}
	return out, nil
}

func (m *memStore) Verify(_ context.Context, _ api.VerifyRequest) (api.Verification, error) {
	problems := []string{}
	for index, event := range m.events {
		if event.Seq != api.Sequence(index+1) {
			problems = append(problems, "event sequence gap")
		}
	}
	for id, metadata := range m.objects {
		if data, exists := m.blobs[id]; !exists || DigestBytes(data) != metadata.Ref.SHA256 || int64(len(data)) != metadata.Ref.Bytes {
			problems = append(problems, "retained object mismatch")
		}
	}
	return api.Verification{
		OK:       len(problems) == 0,
		Objects:  uint64(len(m.blobs)),
		Events:   uint64(len(m.events)),
		Problems: problems,
	}, nil
}

type memHuman struct {
	consumed map[api.ID]bool
	checks   int
}

func newMemHuman() *memHuman {
	return &memHuman{consumed: make(map[api.ID]bool)}
}

func (h *memHuman) Challenge(_ context.Context, scope api.Scope, req api.HumanChallengeRequest) (api.HumanChallenge, error) {
	return api.HumanChallenge{
		ID:             "chal-1",
		Challenge:      []byte("nonce"),
		Config:         scope.Config,
		Method:         req.Method,
		TargetID:       req.TargetID,
		RequestSHA256:  req.RequestSHA256,
		BaseGeneration: req.BaseGeneration,
		ExpiresAt:      "2099-01-01T00:00:00Z",
	}, nil
}

func (h *memHuman) Confirm(_ context.Context, _ api.Scope, _ api.HumanConfirmRequest) (api.ProofRef, error) {
	return api.ProofRef{ID: "proof-1", ExpiresAt: "2099-01-01T00:00:00Z"}, nil
}

func (h *memHuman) CheckProof(_ context.Context, scope api.Scope, proof api.ProofRef, target api.HumanChallengeRequest) (api.VerifiedHumanProof, error) {
	if proof.ID == "" || proof.RequestSHA256 != target.RequestSHA256 {
		return api.VerifiedHumanProof{}, &api.Error{Code: api.CodeForbidden, Message: "proof digest mismatch"}
	}
	if h.consumed[proof.ID] {
		return api.VerifiedHumanProof{}, &api.Error{Code: api.CodeConflict, Message: "proof already consumed"}
	}
	h.checks++ // Verification is non-consuming; only Transact consumes the nonce.
	return api.VerifiedHumanProof{
		EndpointClass:      api.EndpointHuman,
		EndpointGeneration: scope.EndpointGeneration,
		Ref:                proof,
		Config:             scope.Config,
		PrincipalID:        scope.Actor.ID,
		CredentialID:       "cred-1",
		NonceID:            "nonce-1",
		Target:             target,
		VerifiedAt:         "2026-10-16T00:00:00Z",
	}, nil
}

type memWorker struct{}

var _ api.DataWorker = (*memWorker)(nil)

func (w *memWorker) MaterializeLaunch(context.Context, api.LaunchDataRequest) (api.LaunchData, error) {
	return api.LaunchData{}, api.NotImplemented("lb-v2-migration", "migration fixture launch materialization")
}

func (w *memWorker) Render(_ context.Context, req api.ChangeRequest) (api.ChangeRequest, error) {
	return req, nil
}

func (w *memWorker) Materialize(_ context.Context, grants api.GrantSet) (api.Materialization, error) {
	return api.Materialization{
		GrantSetID: grants.ID,
		Manifest: api.BlobRef{
			ID:     "blob-mat-1",
			SHA256: DigestBytes([]byte("materialized")),
			Bytes:  12,
			Class:  "manifest",
		},
		Objects: []api.MaterializedObject{},
	}, nil
}

func (w *memWorker) TestChild(_ context.Context, _ api.TestChildRequest, _ api.GrantSet) (api.Operation, error) {
	return api.Operation{ID: "op-test-1", Status: "succeeded"}, nil
}

func (w *memWorker) Archive(_ context.Context, req api.ArchiveRequest) (api.ArchiveReceipt, error) {
	return api.ArchiveReceipt{ID: "arc-1", LifeID: req.Target.LifeID}, nil
}

type memRegistrar struct {
	handlers map[api.Method]api.Handler
}

func (r *memRegistrar) Register(m api.Method, h api.Handler) error {
	if r.handlers == nil {
		r.handlers = make(map[api.Method]api.Handler)
	}
	if _, exists := r.handlers[m]; exists {
		return fmt.Errorf("duplicate method %s", m)
	}
	r.handlers[m] = h
	return nil
}

func (r *memRegistrar) RegisterStream(_ api.Method, _ api.StreamHandler) error {
	return nil
}

func buildFixtureInStore(t *testing.T, ms *memStore, version, cfgName string) (api.MigrationPlanRequest, string) {
	t.Helper()
	tmpDir := t.TempDir()
	_ = os.Chmod(tmpDir, 0o700)
	storeID := strings.Repeat("ab12cd34", 4)
	createdAt := "2026-10-15T00:00:00.000000Z"

	briefIn := []byte("# Bootstrap lane\n")
	briefSHA := string(DigestBytes(briefIn))
	protoIn := []byte("# Protocol 1.1.0\n")
	protoSHA := string(DigestBytes(protoIn))
	renderedIn := []byte("# Rendered Brief\n")
	renderedSHA := string(DigestBytes(renderedIn))
	renderedPath := fmt.Sprintf("/state/lanes/alpha/rendered/%s.md", renderedSHA)

	renderedBetaIn := []byte("# Rendered Beta Brief\n")
	renderedBetaSHA := string(DigestBytes(renderedBetaIn))
	renderedBetaPath := fmt.Sprintf("/state/lanes/beta/rendered/%s.md", renderedBetaSHA)

	mail1 := []byte("Delivered message 1\n")
	mail1SHA := string(DigestBytes(mail1))
	mail2 := []byte("Waiting message 2\n")
	mail2SHA := string(DigestBytes(mail2))

	launch1 := strings.Repeat("11223344", 4)
	launch2 := strings.Repeat("22334455", 4)
	launch3 := strings.Repeat("33445566", 4)
	sessUUID := "12345678-1234-4234-8234-123456789abc"
	rfID := "rf-" + strings.Repeat("012345", 4)
	cmdTxt := "printf blocked"
	msgTxt := "refused by guard"

	startAlpha := map[string]any{
		"run":            1,
		"how":            "start",
		"launch":         launch1,
		"runner":         "claudock",
		"model":          "claude-sonnet-4-20250514",
		"effort":         "high",
		"account":        "main",
		"chosen_by":      map[string]any{"runner": "supervisor", "model": "supervisor", "effort": "supervisor", "account": "supervisor"},
		"difficulty":     "standard",
		"project":        "demo",
		"worktree":       "/state/lanes/alpha/worktree",
		"branch":         "alpha",
		"base":           strings.Repeat("deadbeef", 5),
		"repository":     "/work/demo",
		"budget_minutes": 30,
		"quiet_seconds":  60,
		"brief":          map[string]any{"path": renderedPath, "sha256": renderedSHA},
		"log":            "/state/lanes/alpha/output.log",
		"session":        map[string]any{"socket": "/tmp/sock", "name": "alpha"},
		"touches":        []any{},
		"claims":         nil,
	}
	if version == "1.0.0-candidate" {
		startAlpha["level"] = 3
		startAlpha["level_source"] = "org"
		startAlpha["starter"] = "supervisor:top"
	}

	rawEvents := []map[string]any{
		{
			"seq":              int64(1),
			"id":               "ev-brief-1",
			"kind":             "brief.rendered",
			"lane":             "alpha",
			"actor":            "laneboss",
			"occurred_at":      nil,
			"protocol_version": "1.1.0",
			"recorded_at":      "2026-10-15T00:00:30.000000Z",
			"payload": map[string]any{
				"inputs": []any{
					map[string]any{"role": "brief", "path": "brief.md", "sha256": briefSHA, "copy": "lanes/alpha/inputs/" + briefSHA},
					map[string]any{"role": "protocol", "version": "1.1.0", "sha256": protoSHA, "copy": "lanes/alpha/inputs/" + protoSHA},
				},
				"output":           map[string]any{"path": renderedPath, "sha256": renderedSHA},
				"project":          "demo",
				"touches":          []any{},
				"launcher_version": "0.7.0",
			},
		},
		{
			"seq":              int64(2),
			"id":               "ev-alpha-start",
			"kind":             "lane.started",
			"lane":             "alpha",
			"actor":            "laneboss",
			"occurred_at":      nil,
			"protocol_version": "1.1.0",
			"recorded_at":      "2026-10-15T00:01:00.000000Z",
			"payload":          startAlpha,
		},
		{
			"seq":              int64(3),
			"id":               "ev-alpha-refusal",
			"kind":             "lane.refusal",
			"lane":             "alpha",
			"actor":            "laneboss",
			"occurred_at":      nil,
			"protocol_version": "1.2.0",
			"recorded_at":      "2026-10-15T00:01:10.000000Z",
			"payload": map[string]any{
				"run":                 1,
				"refusal":             rfID,
				"guard":               "raw-git-push",
				"kind":                "hook",
				"format":              "claude-code",
				"via":                 "hook",
				"hook":                map[string]any{"event": "PreToolUse", "name": "orghook"},
				"tool":                "Bash",
				"at":                  "2026-10-15T00:01:09Z",
				"command":             map[string]any{"text": cmdTxt, "withheld": false, "length": len(cmdTxt), "sha256": string(DigestBytes([]byte(cmdTxt)))},
				"message":             map[string]any{"text": msgTxt, "withheld": false, "length": len(msgTxt), "sha256": string(DigestBytes([]byte(msgTxt)))},
				"targets":             []any{"/work/demo/a.txt"},
				"call":                map[string]any{"id": "c1", "record": map[string]any{"path": "/work/demo/r.jsonl", "line": 1, "offset": 0, "item": 0}},
				"record":              map[string]any{"path": "/work/demo/r.jsonl", "line": 1, "offset": 0, "item": 0},
				"workarounds_checked": true,
			},
		},
		{
			"seq":              int64(4),
			"id":               "ev-alpha-end",
			"kind":             "lane.ended",
			"lane":             "alpha",
			"actor":            "laneboss",
			"occurred_at":      nil,
			"protocol_version": "1.2.0",
			"recorded_at":      "2026-10-15T00:02:00.000000Z",
			"payload": map[string]any{
				"run":              1,
				"reason":           "exit",
				"exit_code":        0,
				"signal":           nil,
				"duration_seconds": 60,
				"pattern":          nil,
				"classification":   nil,
				"survivors":        0,
			},
		},
		{
			"seq":              int64(5),
			"id":               "ev-alpha-state",
			"kind":             "lane.state",
			"lane":             "alpha",
			"actor":            "human",
			"occurred_at":      nil,
			"protocol_version": "1.3.0",
			"recorded_at":      "2026-10-15T00:03:00.000000Z",
			"payload":          map[string]any{"state": "merged"},
		},
		{
			"seq":              int64(6),
			"id":               "ev-alpha-clean",
			"kind":             "lane.cleaned",
			"lane":             "alpha",
			"actor":            "human",
			"occurred_at":      nil,
			"protocol_version": "1.3.0",
			"recorded_at":      "2026-10-15T00:04:00.000000Z",
			"payload": map[string]any{
				"removed": []any{map[string]any{"item": "branch", "name": "alpha"}},
				"kept":    []any{map[string]any{"item": "lane-directory", "path": "/state/lanes/alpha", "why": "record"}},
			},
		},
		{
			"seq":              int64(7),
			"id":               "ev-beta-start-1",
			"kind":             "lane.started",
			"lane":             "beta",
			"actor":            "laneboss",
			"occurred_at":      nil,
			"protocol_version": "1.2.0",
			"recorded_at":      "2026-10-15T00:05:00.000000Z",
			"payload": map[string]any{
				"run":            1,
				"how":            "start",
				"launch":         launch2,
				"runner":         "claudock",
				"model":          "claude-sonnet-4-20250514",
				"effort":         nil,
				"account":        nil,
				"chosen_by":      map[string]any{"runner": "supervisor", "model": "supervisor", "effort": nil, "account": nil},
				"difficulty":     nil,
				"project":        nil,
				"worktree":       "/state/lanes/beta/worktree",
				"branch":         nil,
				"base":           strings.Repeat("deadbeef", 5),
				"repository":     nil,
				"budget_minutes": 15,
				"quiet_seconds":  60,
				"brief":          map[string]any{"path": renderedBetaPath, "sha256": renderedBetaSHA},
				"log":            "/state/lanes/beta/output.log",
				"session":        map[string]any{"socket": "/tmp/sock", "name": "beta"},
				"session_id":     sessUUID,
				"mail":           []any{},
				"idle_seconds":   nil,
				"touches":        []any{},
				"claims":         nil,
			},
		},
		{
			"seq":              int64(8),
			"id":               "ev-beta-end-1",
			"kind":             "lane.ended",
			"lane":             "beta",
			"actor":            "laneboss",
			"occurred_at":      nil,
			"protocol_version": "1.2.0",
			"recorded_at":      "2026-10-15T00:06:00.000000Z",
			"payload": map[string]any{
				"run":              1,
				"reason":           "exit",
				"exit_code":        0,
				"signal":           nil,
				"duration_seconds": 10,
				"pattern":          nil,
				"classification":   nil,
				"survivors":        0,
				"prompt":           map[string]any{"state": "written", "bytes": 16, "length": 16},
			},
		},
		{
			"seq":              int64(9),
			"id":               "ev-beta-mail-1",
			"kind":             "lane.mailed",
			"lane":             "beta",
			"actor":            "human",
			"occurred_at":      nil,
			"protocol_version": "1.2.0",
			"recorded_at":      "2026-10-15T00:07:00.000000Z",
			"payload": map[string]any{
				"sequence": 1,
				"sender":   "human",
				"sha256":   mail1SHA,
				"bytes":    len(mail1),
			},
		},
		{
			"seq":              int64(10),
			"id":               "ev-beta-start-2",
			"kind":             "lane.started",
			"lane":             "beta",
			"actor":            "laneboss",
			"occurred_at":      nil,
			"protocol_version": "1.2.0",
			"recorded_at":      "2026-10-15T00:08:00.000000Z",
			"payload": map[string]any{
				"run":            2,
				"how":            "resume",
				"launch":         launch3,
				"runner":         "claudock",
				"model":          "claude-sonnet-4-20250514",
				"effort":         nil,
				"account":        nil,
				"chosen_by":      map[string]any{"runner": "previous", "model": "previous", "effort": nil, "account": nil},
				"difficulty":     nil,
				"project":        nil,
				"worktree":       "/state/lanes/beta/worktree",
				"branch":         nil,
				"base":           strings.Repeat("deadbeef", 5),
				"repository":     nil,
				"budget_minutes": 15,
				"quiet_seconds":  60,
				"brief":          map[string]any{"path": renderedBetaPath, "sha256": renderedBetaSHA},
				"log":            "/state/lanes/beta/output.log",
				"session":        map[string]any{"socket": "/tmp/sock", "name": "beta"},
				"session_id":     sessUUID,
				"mail":           []any{1},
				"idle_seconds":   nil,
				"touches":        []any{},
				"claims":         nil,
			},
		},
		{
			"seq":              int64(11),
			"id":               "ev-beta-end-2",
			"kind":             "lane.ended",
			"lane":             "beta",
			"actor":            "laneboss",
			"occurred_at":      nil,
			"protocol_version": "1.2.0",
			"recorded_at":      "2026-10-15T00:09:00.000000Z",
			"payload": map[string]any{
				"run":              2,
				"reason":           "exit",
				"exit_code":        0,
				"signal":           nil,
				"duration_seconds": 10,
				"pattern":          nil,
				"classification":   nil,
				"survivors":        0,
				"prompt":           map[string]any{"state": "written", "bytes": len(mail1), "length": len(mail1)},
			},
		},
		{
			"seq":              int64(12),
			"id":               "ev-beta-deliv-1",
			"kind":             "lane.delivered",
			"lane":             "beta",
			"actor":            "laneboss",
			"occurred_at":      nil,
			"protocol_version": "1.2.0",
			"recorded_at":      "2026-10-15T00:09:05.000000Z",
			"payload":          map[string]any{"run": 2, "sequences": []any{1}},
		},
		{
			"seq":              int64(13),
			"id":               "ev-beta-mail-2",
			"kind":             "lane.mailed",
			"lane":             "beta",
			"actor":            "human",
			"occurred_at":      nil,
			"protocol_version": "1.3.0",
			"recorded_at":      "2026-10-15T00:10:00.000000Z",
			"payload": map[string]any{
				"sequence": 2,
				"sender":   "human",
				"sha256":   mail2SHA,
				"bytes":    len(mail2),
			},
		},
	}

	var chainParts []string
	for _, ev := range rawEvents {
		h := string(DigestBytes([]byte(eventstore.Canonical(ev))))
		ev["sha256"] = h
		chainParts = append(chainParts, fmt.Sprintf("%d:%s:%s", ev["seq"], ev["id"], h))
	}

	projs := map[string]map[string]any{
		"alpha": {
			"lane":      "alpha",
			"state":     "merged",
			"state_at":  "2026-10-15T00:03:00.000000Z",
			"times":     map[string]any{"planned": nil, "started": "2026-10-15T00:01:00.000000Z", "ended": "2026-10-15T00:02:00.000000Z", "timeout": nil, "stuck": nil, "resumed": nil, "lost": nil, "cleaned": "2026-10-15T00:04:00.000000Z"},
			"landing":   map[string]any{"merged": nil, "deployed": nil, "landed": nil},
			"run":       1,
			"running":   false,
			"runner":    "claudock",
			"model":     "claude-sonnet-4-20250514",
			"effort":    "high",
			"account":   "main",
			"worktree":  "/state/lanes/alpha/worktree",
			"branch":    "alpha",
			"reason":    "exit",
			"exit_code": 0,
			"resumes":   0,
			"lost":      0,
			"cleaned":   true,
			"events":    5,
			"last_seq":  6,
			"refusals": map[string]any{
				"recorded":   map[string]any{rfID: map[string]any{"run": 1, "seq": 3, "guard": "raw-git-push", "tool": "Bash"}},
				"suspected":  map[string]any{},
				"verdicts":   []any{},
				"unreviewed": []any{},
			},
		},
		"beta": {
			"lane":      "beta",
			"state":     "waiting",
			"state_at":  "2026-10-15T00:09:00.000000Z",
			"times":     map[string]any{"planned": nil, "started": "2026-10-15T00:08:00.000000Z", "ended": "2026-10-15T00:09:00.000000Z", "timeout": nil, "stuck": nil, "resumed": nil, "lost": nil, "cleaned": nil},
			"landing":   map[string]any{"merged": nil, "deployed": nil, "landed": nil},
			"run":       2,
			"running":   false,
			"runner":    "claudock",
			"model":     "claude-sonnet-4-20250514",
			"effort":    nil,
			"account":   nil,
			"worktree":  "/state/lanes/beta/worktree",
			"branch":    nil,
			"reason":    "exit",
			"exit_code": 0,
			"resumes":   0,
			"lost":      0,
			"cleaned":   false,
			"events":    7,
			"last_seq":  13,
			"mail": map[string]any{
				"turn_based":   true,
				"idle_seconds": nil,
				"last":         2,
				"waiting":      []any{2},
				"returned":     []any{},
				"in_flight":    nil,
				"delivered":    1,
				"settled":      map[string]any{"run": 2, "outcome": "delivered", "reason": nil, "sequences": []any{1}, "announced": true},
			},
		},
	}

	dbPath := filepath.Join(tmpDir, "events.sqlite")
	writeEventsSQLite(t, dbPath, cfgName, storeID, createdAt, rawEvents, projs)
	dbBytes, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}

	markerObj := map[string]any{
		"config": cfgName,
		"format": 2,
		"store":  map[string]any{"id": storeID, "created_at": createdAt},
	}
	markerBytes := []byte(eventstore.Canonical(markerObj) + "\n")

	decBytes := buildPortableDecisionsBytes(t)
	arcTar, arcMan, arcRec, stem := buildArchiveBytes(t)
	ownerQueue := []byte(eventstore.Canonical(map[string]any{"from": "supervisor:top", "to": "human", "text": "Owner status 1"}) + "\n")

	fileMap := map[string][]byte{
		"config/config.toml":                                   []byte(fmt.Sprintf("schema_version = 1\nname = %q\n[runners.claudock]\ncommand = [\"claudock\"]\nresume = [\"claudock\"]\nprompt = \"stdin\"\n", cfgName)),
		"state/.laneboss-state":                                markerBytes,
		"state/events.sqlite":                                  dbBytes,
		"state/decisions.jsonl":                                decBytes,
		"state/lanes/alpha/inputs/" + briefSHA:                 briefIn,
		"state/lanes/alpha/inputs/" + protoSHA:                 protoIn,
		"state/lanes/alpha/rendered/" + renderedSHA + ".md":    renderedIn,
		"state/lanes/beta/rendered/" + renderedBetaSHA + ".md": renderedBetaIn,
		"state/lanes/beta/mail/000000001-" + mail1SHA:          mail1,
		"state/lanes/beta/mail/000000002-" + mail2SHA:          mail2,
		"state/lanes/beta/session/history.jsonl":               []byte("{\"turn\":1,\"text\":\"beta work\"}\n"),
		"state/lanes/beta/worktree/main.go":                    []byte("package main\n"),
		"state/archives/" + stem + ".tar":                      arcTar,
		"state/archives/" + stem + ".manifest.json":            arcMan,
		"state/archives/" + stem + ".receipt.json":             arcRec,
		"state/owner/queue.jsonl":                              ownerQueue,
	}

	backupDir := filepath.Join(tmpDir, "backup")
	var entries []api.ObjectEntry
	for pathKey, content := range fileMap {
		full := filepath.Join(backupDir, filepath.FromSlash(pathKey))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, content, 0o600); err != nil {
			t.Fatal(err)
		}
		ref := ms.putBlob(string(DeterministicID("b-", version, pathKey)), content, "archive")
		entries = append(entries, api.ObjectEntry{
			Path:    pathKey,
			Kind:    "file",
			Mode:    0o600,
			Content: &ref,
		})
	}

	qReceipt := QuiescenceReceipt{
		Schema:          SchemaQuiescence,
		Config:          cfgName,
		SourceVersion:   version,
		DispatchFrozen:  true,
		LoopStopped:     true,
		ActiveWriters:   0,
		Survivors:       0,
		RunningLanes:    []string{},
		UnfinishedLanes: []string{"beta"},
		ObservedAt:      "2026-10-15T00:15:00Z",
	}
	qBytes, _ := CanonicalJCS(qReceipt)
	if err := os.WriteFile(filepath.Join(backupDir, "quiescence.json"), qBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	qRef := ms.putBlob(string(DeterministicID("blob-q-", version)), qBytes, "manifest")

	vReceipt := VerificationReceipt{
		Schema:            SchemaVerification,
		OK:                true,
		Config:            cfgName,
		StoreID:           storeID,
		Events:            len(rawEvents),
		Lanes:             len(projs),
		EventsChainSHA256: string(DigestBytes([]byte(strings.Join(chainParts, "\n")))),
		DecisionsSHA256:   string(DigestBytes(decBytes)),
	}
	vBytes, _ := CanonicalJCS(vReceipt)
	if err := os.WriteFile(filepath.Join(backupDir, "verification.json"), vBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	vRef := ms.putBlob(string(DeterministicID("blob-v-", version)), vBytes, "manifest")

	manifest := api.MigrationManifest{
		Schema:         SchemaMigrationManifest,
		SourceVersion:  version,
		SourceProtocol: "1.3.0",
		SourceRevision: "d6f2a96",
		Inventory: api.ObjectManifest{
			Schema:  SchemaObjectManifest,
			Entries: entries,
		},
		Quiescence:   qRef,
		Verification: vRef,
	}
	manBytes, _ := CanonicalJCS(manifest)
	manRef := ms.putBlob(string(DeterministicID("blob-man-", version)), manBytes, "manifest")

	return api.MigrationPlanRequest{
		SourceVersion:  version,
		SourceManifest: manRef,
	}, backupDir
}

func writeEventsSQLite(
	t *testing.T,
	dbPath, cfgName, storeID, createdAt string,
	events []map[string]any,
	projs map[string]map[string]any,
) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	stmts := []string{
		"CREATE TABLE meta (\n    key TEXT PRIMARY KEY,\n    value TEXT NOT NULL\n)",
		"CREATE TABLE events (\n    seq INTEGER PRIMARY KEY AUTOINCREMENT,\n    id TEXT NOT NULL UNIQUE,\n    kind TEXT NOT NULL,\n    lane TEXT,\n    actor TEXT NOT NULL,\n    occurred_at TEXT,\n    payload TEXT NOT NULL,\n    protocol_version TEXT NOT NULL,\n    recorded_at TEXT NOT NULL,\n    sha256 TEXT NOT NULL\n)",
		"CREATE TABLE lanes (\n    lane TEXT PRIMARY KEY,\n    projection TEXT NOT NULL\n)",
		"CREATE TRIGGER events_no_update BEFORE UPDATE ON events\nBEGIN\n    SELECT RAISE(ABORT, 'events are append-only');\nEND",
		"CREATE TRIGGER events_no_delete BEFORE DELETE ON events\nBEGIN\n    SELECT RAISE(ABORT, 'events are append-only');\nEND",
		"CREATE TRIGGER events_no_replace BEFORE INSERT ON events\nWHEN EXISTS (SELECT 1 FROM events WHERE seq = NEW.seq OR id = NEW.id)\nBEGIN\n    SELECT RAISE(ABORT, 'events are append-only');\nEND",
		"CREATE TRIGGER meta_no_update BEFORE UPDATE ON meta\nBEGIN\n    SELECT RAISE(ABORT, 'store metadata is immutable');\nEND",
		"CREATE TRIGGER meta_no_delete BEFORE DELETE ON meta\nBEGIN\n    SELECT RAISE(ABORT, 'store metadata is immutable');\nEND",
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	for _, kv := range [][2]string{
		{"config", cfgName},
		{"created_at", createdAt},
		{"format", "event-store"},
		{"store_id", storeID},
	} {
		if _, err := db.Exec("INSERT INTO meta (key, value) VALUES (?, ?)", kv[0], kv[1]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec("CREATE TRIGGER meta_no_insert BEFORE INSERT ON meta\nBEGIN\n    SELECT RAISE(ABORT, 'store metadata is immutable');\nEND"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("PRAGMA user_version = 1"); err != nil {
		t.Fatal(err)
	}
	for _, ev := range events {
		if _, err := db.Exec(
			"INSERT INTO events (seq, id, kind, lane, actor, occurred_at, payload, protocol_version, recorded_at, sha256) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			ev["seq"], ev["id"], ev["kind"], ev["lane"], ev["actor"], ev["occurred_at"],
			eventstore.Canonical(ev["payload"]), ev["protocol_version"], ev["recorded_at"], ev["sha256"],
		); err != nil {
			t.Fatal(err)
		}
	}
	for laneName, p := range projs {
		if _, err := db.Exec("INSERT INTO lanes (lane, projection) VALUES (?, ?)", laneName, eventstore.Canonical(p)); err != nil {
			t.Fatal(err)
		}
	}
}

func buildPortableDecisionsBytes(t *testing.T) []byte {
	t.Helper()
	verbatim := "Blacklist only, never an allowlist."
	lineTxt := "R48: Blacklist only"
	rec := map[string]any{
		"id":             "dec-r48",
		"kind":           "owner-decision",
		"schema_version": 1,
		"asked_at":       "2026-10-10T08:00:00+00:00",
		"answered_at":    "2026-10-10T08:05:00+00:00",
		"project":        "laneboss",
		"area":           "policy",
		"topics":         []any{"blacklist", "isolation"},
		"question": map[string]any{
			"text":       "Should commands use a blacklist or allowlist?",
			"background": "Isolation policy design.",
		},
		"answer": map[string]any{
			"verbatim":   verbatim,
			"channel":    "owner",
			"message_id": nil,
			"sha256":     string(DigestBytes([]byte(verbatim))),
		},
		"scope":   map[string]any{"applies_to": []any{"org", "lanes"}},
		"status":  "in_force",
		"outcome": map[string]any{},
		"provenance": map[string]any{
			"recorded_by": "human",
			"recorded_at": "2026-10-10T08:06:00+00:00",
			"sources": []any{
				map[string]any{
					"path":           "owner/decisions.md",
					"line":           1,
					"line_text":      lineTxt,
					"sha256_of_line": string(DigestBytes([]byte(lineTxt))),
				},
			},
		},
	}
	firstSHA := string(DigestBytes([]byte(eventstore.Canonical(rec))))
	modelMeta := map[string]any{"model": "fake-embed-1", "provider": "fake", "dimension": 2}
	modelMeta["entry_sha256"] = string(DigestBytes([]byte(eventstore.Canonical(modelMeta))))

	qText := "Should commands use a blacklist or allowlist?\nIsolation policy design.\n\n\nblacklist\nisolation"
	qSHA := string(DigestBytes([]byte(qText)))
	vecBytes := make([]byte, 8)
	binary.LittleEndian.PutUint32(vecBytes[0:4], math.Float32bits(0.5))
	binary.LittleEndian.PutUint32(vecBytes[4:8], math.Float32bits(0.75))

	egress := map[string]any{
		"id":                    1,
		"record_id":             "dec-r48",
		"which_text":            "q_text",
		"text":                  qText,
		"text_sha256":           qSHA,
		"model":                 "fake-embed-1",
		"at":                    "2026-10-10T08:07:00+00:00",
		"endpoint_host":         "127.0.0.1",
		"input_type":            "document",
		"previous_entry_sha256": "",
	}
	egress["entry_sha256"] = string(DigestBytes([]byte(eventstore.Canonical(egress))))

	vec := map[string]any{
		"record_id":     "dec-r48",
		"which_text":    "q_text",
		"model":         "fake-embed-1",
		"dimension":     2,
		"text":          qText,
		"text_sha256":   qSHA,
		"vector_sha256": string(DigestBytes(vecBytes)),
		"created_at":    "2026-10-10T08:07:01+00:00",
	}
	vec["entry_sha256"] = string(DigestBytes([]byte(eventstore.Canonical(vec))))
	vec["vector"] = base64.StdEncoding.EncodeToString(vecBytes)

	manifest := map[string]any{
		"type":           "manifest",
		"format":         "laneboss-decisions-jsonl",
		"schema_version": 1,
		"first_written":  1,
		"counts":         map[string]any{"records": 1, "models": 1, "vectors": 1, "egress": 1},
	}

	lines := []string{
		eventstore.Canonical(manifest),
		eventstore.Canonical(map[string]any{"type": "record", "record": rec, "first_written_sha256": firstSHA}),
		eventstore.Canonical(map[string]any{"type": "model", "model": modelMeta}),
		eventstore.Canonical(map[string]any{"type": "vector", "vector": vec}),
		eventstore.Canonical(map[string]any{"type": "egress", "egress": egress}),
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

func buildArchiveBytes(t *testing.T) ([]byte, []byte, []byte, string) {
	t.Helper()
	logData := []byte("run alpha\nexample-agent: done\n")
	repData := []byte("# Alpha Report\n")
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, item := range []struct {
		name string
		data []byte
	}{
		{"lane/output.log", logData},
		{"lane/report.md", repData},
	} {
		if err := tw.WriteHeader(&tar.Header{
			Name:     item.name,
			Mode:     0o600,
			Size:     int64(len(item.data)),
			Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(item.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	tarBytes := buf.Bytes()
	tarSHA := string(DigestBytes(tarBytes))
	stem := "alpha-" + strings.Repeat("1a2b3c4d", 4)

	manObj := map[string]any{
		"format": 1,
		"entries": []any{
			map[string]any{"path": "lane/output.log", "type": "file", "size": len(logData), "mode": 0o600, "sha256": string(DigestBytes(logData))},
			map[string]any{"path": "lane/report.md", "type": "file", "size": len(repData), "mode": 0o600, "sha256": string(DigestBytes(repData))},
		},
		"remove_paths":        []any{},
		"remove_paths_sha256": string(DigestBytes([]byte("[]"))),
	}
	manBytes, _ := json.MarshalIndent(manObj, "", "  ")
	manBytes = append(manBytes, '\n')
	manSHA := string(DigestBytes(manBytes))

	recObj := map[string]any{
		"lane":                "alpha",
		"run":                 1,
		"tar":                 stem + ".tar",
		"sha256":              tarSHA,
		"manifest":            stem + ".manifest.json",
		"manifest_sha256":     manSHA,
		"read_back":           true,
		"remote_sha256":       nil,
		"remove_paths_sha256": string(DigestBytes([]byte("[]"))),
		"remove_count":        0,
	}
	recBytes := []byte(eventstore.Canonical(recObj) + "\n")
	return tarBytes, manBytes, recBytes, stem
}

func TestNewAndRegisterValidation(t *testing.T) {
	if _, err := New(Dependencies{}); err == nil {
		t.Fatal("expected nil dependencies to fail")
	}
	ms := newMemStore()
	mh := newMemHuman()
	mw := &memWorker{}
	svc, err := New(Dependencies{Store: ms, Human: mh, Worker: mw})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Register(nil); err == nil {
		t.Fatal("expected nil registrar to fail")
	}
	reg := &memRegistrar{}
	if err := svc.Register(reg); err != nil {
		t.Fatal(err)
	}
	if len(reg.handlers) != 2 || reg.handlers["migration.plan"] == nil || reg.handlers["migration.apply"] == nil {
		t.Fatalf("unexpected registered handlers: %v", reg.handlers)
	}
}

type migrationFailingBlobStore struct {
	api.StateStore
	failure error
	reads   []api.BlobReadRequest
	scopes  []api.Scope
}

func (store *migrationFailingBlobStore) Blob(_ context.Context, scope api.Scope, request api.BlobReadRequest) (api.BlobChunk, error) {
	store.reads = append(store.reads, request)
	store.scopes = append(store.scopes, scope)
	return api.BlobChunk{}, store.failure
}

func TestStubDependencyPropagation(t *testing.T) {
	scope := api.Scope{
		Config: "demo",
		Actor:  api.Actor{Kind: "human", ID: "human-1"},
	}
	req := api.MigrationPlanRequest{
		SourceVersion: "0.7.0",
		SourceManifest: api.BlobRef{
			ID:     "blob-1",
			SHA256: DigestBytes([]byte("{}")),
			Bytes:  2,
			Class:  "manifest",
		},
	}
	for _, code := range []api.ErrorCode{api.CodeNotImplemented, api.CodeUnavailable, api.CodeForbidden, api.CodeCancelled} {
		t.Run(string(code), func(t *testing.T) {
			failure := &api.Error{Code: code, Message: "controlled migration blob dependency failure",
				Instead: "Repair the injected blob dependency.", Retryable: true, OperationID: "dependency-operation", Owner: "lb-v2-migration-fixture"}
			wantFailure := *failure
			dependency := &migrationFailingBlobStore{failure: failure}
			service, err := New(Dependencies{Store: dependency, Human: newMemHuman(), Worker: &memWorker{}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = service.MigrationPlan(context.Background(), scope, req)
			if err != failure || *failure != wantFailure {
				t.Fatalf("migration changed the injected typed dependency error: got %v, want %+v", err, failure)
			}
			if len(dependency.reads) != 1 || dependency.reads[0].ObjectID != req.SourceManifest.ID || dependency.reads[0].Offset != 0 || dependency.reads[0].Limit != int(req.SourceManifest.Bytes) || len(dependency.scopes) != 1 || dependency.scopes[0].Config != scope.Config || dependency.scopes[0].Actor != scope.Actor {
				t.Fatalf("dependency failure did not originate at the scoped source read: %+v", dependency.reads)
			}
		})
	}
}

func TestMigratePlanAndApplyEndToEnd(t *testing.T) {
	for _, ver := range []string{"0.7.0", "1.0.0-candidate"} {
		t.Run(ver, func(t *testing.T) {
			ms := newMemStore()
			mh := newMemHuman()
			mw := &memWorker{}
			svc, err := New(Dependencies{Store: ms, Human: mh, Worker: mw})
			if err != nil {
				t.Fatal(err)
			}

			planReq, backupDir := buildFixtureInStore(t, ms, ver, "demo")
			scope := api.Scope{
				Config: "demo",
				Actor:  api.Actor{Kind: "human", ID: "human-1"},
			}

			plan, err := svc.MigrationPlan(context.Background(), scope, planReq)
			if err != nil {
				t.Fatalf("MigrationPlan(%s) failed: %v", ver, err)
			}
			if plan.TargetSchema != api.SchemaVersion || len(plan.Problems) != 0 {
				t.Fatalf("unexpected plan: %+v", plan)
			}
			if len(plan.RequiresRelaunch) != 1 || plan.RequiresRelaunch[0] != "relaunch-beta" {
				t.Fatalf("expected requires_relaunch=[relaunch-beta], got %v", plan.RequiresRelaunch)
			}

			applyReq := api.MigrationApplyRequest{PlanID: plan.ID}
			reqDigest, err := RequestDigest("demo", "migration.apply", applyReq)
			if err != nil {
				t.Fatal(err)
			}
			proof := &api.ProofRef{
				ID:            DeterministicID("proof-", ver),
				RequestSHA256: reqDigest,
				ExpiresAt:     "2099-01-01T00:00:00Z",
			}
			applyScope := scope
			applyScope.Request = api.Request{
				Protocol:       api.Protocol,
				Schema:         api.SchemaVersion,
				Config:         "demo",
				RequestID:      DeterministicID("req-apply-", ver),
				IdempotencyKey: DeterministicID("idem-apply-", ver),
				RequestSHA256:  reqDigest,
				Method:         "migration.apply",
				Proof:          proof,
			}
			applyScope = boundApplyScope(applyScope)

			op, err := svc.MigrationApply(context.Background(), applyScope, applyReq)
			if err != nil {
				t.Fatalf("MigrationApply(%s) failed: %v", ver, err)
			}
			if op.Status != "pending" || len(ms.records) != 0 || len(ms.events) != 0 {
				t.Fatalf("public apply must queue a pending effect without importing history: %+v", op)
			}
			if len(ms.transactions) != 1 || ms.transactions[0].Reply == nil || len(ms.transactions[0].Guards) != 1 || ms.transactions[0].Guards[0].Proof == nil {
				t.Fatal("public apply omitted its atomic reply or proof guard")
			}
			completed := finishMigration(t, svc, ms, applyScope, plan)
			if completed.ID != op.ID || completed.Status != "succeeded" {
				t.Fatalf("internal migration completion failed: %+v", completed)
			}

			// Verify idempotent retry with identical key and digest returns the same Operation without duplicating events.
			evCountBefore := len(ms.events)
			opReplay, err := svc.MigrationApply(context.Background(), applyScope, applyReq)
			if err != nil {
				t.Fatalf("idempotent replay failed: %v", err)
			}
			if !reflect.DeepEqual(opReplay, op) || len(ms.events) != evCountBefore {
				t.Fatalf("idempotent replay duplicated state: %+v vs %+v", opReplay, op)
			}
			// A new service instance has no in-memory plan or idempotency cache.
			restarted, err := New(Dependencies{Store: ms, Human: mh, Worker: mw})
			if err != nil {
				t.Fatal(err)
			}
			checksBefore := mh.checks
			restartedReplay, err := restarted.MigrationApply(context.Background(), applyScope, applyReq)
			if err != nil || !reflect.DeepEqual(restartedReplay, op) || mh.checks != checksBefore {
				t.Fatalf("restart replay changed the exact receipt or rechecked a consumed proof: %+v, %v", restartedReplay, err)
			}

			// Verify reusing idempotency key with different content fails with idempotency_conflict.
			badReq := api.MigrationApplyRequest{PlanID: "migplan-other"}
			badDigest, _ := RequestDigest("demo", "migration.apply", badReq)
			conflictScope := applyScope
			conflictScope.Request.RequestSHA256 = badDigest
			changedProof := *proof
			changedProof.RequestSHA256 = badDigest
			conflictScope.Request.Proof = &changedProof
			if _, err := svc.MigrationApply(context.Background(), conflictScope, badReq); err == nil {
				t.Fatal("expected idempotency_conflict on changed request under same key")
			} else {
				var typed *api.Error
				if !asAPIError(err, &typed) || typed.Code != api.CodeIdempotencyConflict {
					t.Fatalf("changed request failed for the wrong reason: %v", err)
				}
			}

			// Verify no imported active authority (no identity.bound, no ParentLifeID or StarterChain on imported events).
			for _, ev := range ms.events {
				if ev.Kind == "identity.bound" {
					t.Fatal("migration synthesized active identity.bound authority")
				}
				if ev.ParentLifeID != "" || len(ev.StarterChain) != 0 {
					t.Fatalf("migration synthesized active starter graph on event %s: parent=%s chain=%v", ev.ID, ev.ParentLifeID, ev.StarterChain)
				}
			}

			// Verify no duplicate delivered mail in outbox effects.
			effects, _ := ms.PendingEffects(context.Background(), api.CursorRequest{Limit: 100})
			for _, eff := range effects {
				if eff.Deliver != nil {
					t.Fatalf("migration queued a duplicate mail delivery effect: %+v", eff.Deliver)
				}
			}
			deliveredCount := 0
			queuedCount := 0
			if len(ms.mail) != 0 {
				t.Fatal("legacy mail became active mail projections")
			}
			for _, record := range ms.records {
				if !strings.HasPrefix(string(record.ID), "mail-mig-") {
					continue
				}
				switch record.Action {
				case "delivered":
					deliveredCount++
				case "queued":
					queuedCount++
				}
			}
			if deliveredCount != 1 || queuedCount != 1 {
				t.Fatalf("expected 1 delivered and 1 queued mail, got delivered=%d queued=%d", deliveredCount, queuedCount)
			}
			report, err := svc.VerifyMigratedState(context.Background(), scope, plan.ID)
			if err != nil || !report.Verified || report.MailDelivered != 1 || report.MailPending != 1 || report.DecisionsMatched != 1 || report.VectorsMatched != 1 || report.EgressMatched != 1 || report.ArchivesMatched != 1 {
				t.Fatalf("incomplete migration read-back: %+v, %v", report, err)
			}

			// Relaunch unfinished session beta in new confinement.
			relaunch, err := svc.PrepareRelaunch(context.Background(), scope, RelaunchOptions{
				PlanID:         plan.ID,
				Lane:           "beta",
				Level:          3,
				Role:           "executor",
				Driver:         api.DriverClaudock,
				ProfileGrantID: "pgrant-1",
				Task: api.BlobRef{
					ID:     "blob-task-1",
					SHA256: DigestBytes([]byte("continue work")),
					Bytes:  13,
					Class:  "task",
				},
				Budget: api.Budget{
					WallMS:      60000,
					CPUSeconds:  60,
					MemoryBytes: 1024 * 1024 * 512,
					Processes:   32,
					DiskBytes:   1024 * 1024 * 512,
					Currency:    "USD",
				},
			})
			if err != nil {
				t.Fatalf("PrepareRelaunch failed: %v", err)
			}
			if relaunch.Manifest.Schema != SchemaAdoptionManifest || relaunch.AdoptRequest.Driver != api.DriverClaudock {
				t.Fatalf("unexpected relaunch manifest: %+v", relaunch)
			}

			// Execute rollback and verify matched old state + binary are restored after retaining new work.
			oldBin := filepath.Join(t.TempDir(), "laneboss-old")
			oldBinBytes := []byte("#!/bin/sh\necho 0.7.0\n")
			if err := os.WriteFile(oldBin, oldBinBytes, 0o700); err != nil {
				t.Fatal(err)
			}
			restoreDir := filepath.Join(t.TempDir(), "restored")
			retainedDir := filepath.Join(t.TempDir(), "retained")

			// First verify relinking old binary onto v2 store is refused.
			if _, err := svc.ExecuteRollback(context.Background(), scope, RollbackRequest{
				Config:               "demo",
				TargetVersion:        ver,
				OldBinaryPath:        oldBin,
				ExpectedBinarySHA256: DigestBytes(oldBinBytes),
				FrozenBackupDir:      backupDir,
				ActiveV2StateDir:     t.TempDir(),
				RestoreTargetDir:     restoreDir,
				RetainedWorkDir:      retainedDir,
				V2Quiescent:          true,
				RelinkOntoV2Store:    true,
			}); err == nil {
				t.Fatal("expected RelinkOntoV2Store to be refused")
			}

			// Verify rolling back to 0.5.0 on a 1.2.0/1.3.0 turn-based store is refused.
			if _, err := svc.ExecuteRollback(context.Background(), scope, RollbackRequest{
				Config:               "demo",
				TargetVersion:        "0.5.0",
				OldBinaryPath:        oldBin,
				ExpectedBinarySHA256: DigestBytes(oldBinBytes),
				FrozenBackupDir:      backupDir,
				ActiveV2StateDir:     t.TempDir(),
				RestoreTargetDir:     restoreDir,
				RetainedWorkDir:      retainedDir,
				V2Quiescent:          true,
			}); err == nil {
				t.Fatal("expected rollback to 0.5.0 against incompatible turn-based store to fail")
			}

			// Valid rollback to matched version succeeds.
			rbReceipt, err := svc.ExecuteRollback(context.Background(), scope, RollbackRequest{
				Config:               "demo",
				TargetVersion:        ver,
				OldBinaryPath:        oldBin,
				ExpectedBinarySHA256: DigestBytes(oldBinBytes),
				FrozenBackupDir:      backupDir,
				ActiveV2StateDir:     t.TempDir(),
				RestoreTargetDir:     restoreDir,
				RetainedWorkDir:      retainedDir,
				V2Quiescent:          true,
			})
			if err != nil {
				t.Fatalf("ExecuteRollback failed: %v", err)
			}
			if !rbReceipt.Verified || rbReceipt.RetainedV2Events != len(ms.events) {
				t.Fatalf("unexpected rollback receipt: %+v", rbReceipt)
			}
		})
	}
}

func TestRedControls(t *testing.T) {
	scope := api.Scope{
		Config: "demo",
		Actor:  api.Actor{Kind: "human", ID: "human-1"},
	}

	t.Run("missing-blob", func(t *testing.T) {
		ms := newMemStore()
		svc, _ := New(Dependencies{Store: ms, Human: newMemHuman(), Worker: &memWorker{}})
		planReq, _ := buildFixtureInStore(t, ms, "0.7.0", "demo")
		// Delete one kept input blob from the store.
		for id := range ms.blobs {
			if strings.HasPrefix(string(id), "b-") {
				delete(ms.blobs, id)
				break
			}
		}
		_, err := svc.MigrationPlan(context.Background(), scope, planReq)
		var apiErr *api.Error
		if !asAPIError(err, &apiErr) || apiErr.Code != api.CodeIntegrity {
			t.Fatalf("expected integrity error for missing blob, got %v", err)
		}
	})

	t.Run("missing-brief", func(t *testing.T) {
		ms := newMemStore()
		svc, _ := New(Dependencies{Store: ms, Human: newMemHuman(), Worker: &memWorker{}})
		planReq, _ := buildFixtureInStore(t, ms, "0.7.0", "demo")
		manBytes := ms.blobs[planReq.SourceManifest.ID]
		var man api.MigrationManifest
		_ = json.Unmarshal(manBytes, &man)
		var filtered []api.ObjectEntry
		for _, ent := range man.Inventory.Entries {
			if strings.HasPrefix(ent.Path, "state/lanes/beta/rendered/") {
				continue
			}
			filtered = append(filtered, ent)
		}
		man.Inventory.Entries = filtered
		newManBytes, _ := CanonicalJCS(man)
		planReq.SourceManifest = ms.putBlob("blob-man-nobrief", newManBytes, "manifest")
		_, err := svc.MigrationPlan(context.Background(), scope, planReq)
		var apiErr *api.Error
		if !asAPIError(err, &apiErr) || apiErr.Code != api.CodeIntegrity || !strings.Contains(apiErr.Message, "missing rendered brief") {
			t.Fatalf("expected missing rendered brief integrity error, got %v", err)
		}
	})

	t.Run("active-writer", func(t *testing.T) {
		ms := newMemStore()
		svc, _ := New(Dependencies{Store: ms, Human: newMemHuman(), Worker: &memWorker{}})
		planReq, _ := buildFixtureInStore(t, ms, "0.7.0", "demo")
		manBytes := ms.blobs[planReq.SourceManifest.ID]
		var man api.MigrationManifest
		_ = json.Unmarshal(manBytes, &man)
		walRef := ms.putBlob("blob-wal", []byte("wal"), "archive")
		man.Inventory.Entries = append(man.Inventory.Entries, api.ObjectEntry{
			Path:    "state/events.sqlite-wal",
			Kind:    "file",
			Mode:    0o600,
			Content: &walRef,
		})
		newManBytes, _ := CanonicalJCS(man)
		planReq.SourceManifest = ms.putBlob("blob-man-wal", newManBytes, "manifest")
		_, err := svc.MigrationPlan(context.Background(), scope, planReq)
		var apiErr *api.Error
		if !asAPIError(err, &apiErr) || apiErr.Code != api.CodeConflict {
			t.Fatalf("expected conflict error for active WAL sidecar, got %v", err)
		}
	})

	t.Run("rehashed-hist", func(t *testing.T) {
		ms := newMemStore()
		svc, _ := New(Dependencies{Store: ms, Human: newMemHuman(), Worker: &memWorker{}})
		planReq, _ := buildFixtureInStore(t, ms, "0.7.0", "demo")
		manBytes := ms.blobs[planReq.SourceManifest.ID]
		var man api.MigrationManifest
		_ = json.Unmarshal(manBytes, &man)

		// Corrupt verification chain digest to simulate rehashed event history.
		vBytes := ms.blobs[man.Verification.ID]
		var vr VerificationReceipt
		_ = json.Unmarshal(vBytes, &vr)
		vr.EventsChainSHA256 = strings.Repeat("ff", 32)
		newVBytes, _ := CanonicalJCS(vr)
		man.Verification = ms.putBlob("blob-v-rehashed", newVBytes, "manifest")
		newManBytes, _ := CanonicalJCS(man)
		planReq.SourceManifest = ms.putBlob("blob-man-rehashed", newManBytes, "manifest")
		_, err := svc.MigrationPlan(context.Background(), scope, planReq)
		var apiErr *api.Error
		if !asAPIError(err, &apiErr) || apiErr.Code != api.CodeIntegrity {
			t.Fatalf("expected integrity error for rehashed bad history, got %v", err)
		}
	})

	t.Run("inplace-owner", func(t *testing.T) {
		ms := newMemStore()
		svc, _ := New(Dependencies{Store: ms, Human: newMemHuman(), Worker: &memWorker{}})
		planReq, _ := buildFixtureInStore(t, ms, "0.7.0", "demo")
		manBytes := ms.blobs[planReq.SourceManifest.ID]
		var man api.MigrationManifest
		_ = json.Unmarshal(manBytes, &man)

		qBytes := ms.blobs[man.Quiescence.ID]
		var qr QuiescenceReceipt
		_ = json.Unmarshal(qBytes, &qr)
		qr.InPlaceOwnership = true
		newQBytes, _ := CanonicalJCS(qr)
		man.Quiescence = ms.putBlob("blob-q-inplace", newQBytes, "manifest")
		newManBytes, _ := CanonicalJCS(man)
		planReq.SourceManifest = ms.putBlob("blob-man-inplace", newManBytes, "manifest")
		_, err := svc.MigrationPlan(context.Background(), scope, planReq)
		var apiErr *api.Error
		if !asAPIError(err, &apiErr) || apiErr.Code != api.CodeConflict {
			t.Fatalf("expected conflict error for in-place ownership change, got %v", err)
		}
	})

	t.Run("label-parent", func(t *testing.T) {
		ms := newMemStore()
		svc, _ := New(Dependencies{Store: ms, Human: newMemHuman(), Worker: &memWorker{}})
		planReq, _ := buildFixtureInStore(t, ms, "1.0.0-candidate", "demo")
		plan, err := svc.MigrationPlan(context.Background(), scope, planReq)
		if err != nil {
			t.Fatal(err)
		}
		_, err = svc.PrepareRelaunch(context.Background(), scope, RelaunchOptions{
			PlanID:         plan.ID,
			Lane:           "beta",
			Level:          3,
			Role:           "executor",
			Driver:         api.DriverClaudock,
			ProfileGrantID: "pgrant-1",
			Task: api.BlobRef{
				ID:     "blob-task-1",
				SHA256: DigestBytes([]byte("continue work")),
				Bytes:  13,
				Class:  "task",
			},
			Budget: api.Budget{
				WallMS:      60000,
				CPUSeconds:  60,
				MemoryBytes: 1024 * 1024 * 512,
				Processes:   32,
				DiskBytes:   1024 * 1024 * 512,
				Currency:    "USD",
			},
			UseLegacyLabelsForParent: true,
		})
		var apiErr *api.Error
		if !asAPIError(err, &apiErr) || apiErr.Code != api.CodeForbidden {
			t.Fatalf("expected forbidden error for label-derived parent in PrepareRelaunch, got %v", err)
		}
	})
}

func TestMutSkipHashCompare(t *testing.T) {
	scope := api.Scope{
		Config: "demo",
		Actor:  api.Actor{Kind: "human", ID: "human-1"},
	}
	ms := newMemStore()
	svc, _ := New(Dependencies{Store: ms, Human: newMemHuman(), Worker: &memWorker{}})
	planReq, _ := buildFixtureInStore(t, ms, "0.7.0", "demo")

	// Modify the worktree file blob ("state/lanes/beta/worktree/main.go") to valid
	// UTF-8 of the same length ("package fake\n") without updating its BlobRef.SHA256
	// in the manifest inventory, so only readBlobFull's source hash comparison catches it.
	wtBlobID := DeterministicID("b-", "0.7.0", "state/lanes/beta/worktree/main.go")
	if _, exists := ms.blobs[wtBlobID]; !exists {
		t.Fatalf("expected worktree blob %s in store", wtBlobID)
	}
	ms.blobs[wtBlobID] = []byte("package fake\n")

	_, err := svc.MigrationPlan(context.Background(), scope, planReq)
	var apiErr *api.Error
	if !asAPIError(err, &apiErr) || apiErr.Code != api.CodeIntegrity || !strings.Contains(apiErr.Message, "content size or sha256 mismatch") {
		t.Fatalf("expected source blob sha256 mismatch integrity failure, got %v", err)
	}
}

func TestMutSkipReadbackVerify(t *testing.T) {
	scope := api.Scope{
		Config: "demo",
		Actor:  api.Actor{Kind: "human", ID: "human-1"},
	}
	ms := newMemStore()
	svc, _ := New(Dependencies{Store: ms, Human: newMemHuman(), Worker: &memWorker{}})
	planReq, _ := buildFixtureInStore(t, ms, "0.7.0", "demo")
	plan, err := svc.MigrationPlan(context.Background(), scope, planReq)
	if err != nil {
		t.Fatal(err)
	}
	applyReq := api.MigrationApplyRequest{PlanID: plan.ID}
	reqDigest, _ := RequestDigest("demo", "migration.apply", applyReq)
	applyScope := scope
	applyScope.Request = api.Request{
		Protocol:       api.Protocol,
		Schema:         api.SchemaVersion,
		Config:         "demo",
		RequestID:      "req-rb-1",
		IdempotencyKey: "idem-rb-1",
		RequestSHA256:  reqDigest,
		Method:         "migration.apply",
		Proof:          &api.ProofRef{ID: "proof-rb-1", RequestSHA256: reqDigest, ExpiresAt: "2099-01-01T00:00:00Z"},
	}
	applyScope = boundApplyScope(applyScope)
	if _, err := svc.MigrationApply(context.Background(), applyScope, applyReq); err != nil {
		t.Fatal(err)
	}
	finishMigration(t, svc, ms, applyScope, plan)
	// Tamper with a committed record's SHA256 in the store and verify VerifyMigratedState fails.
	if len(ms.records) == 0 {
		t.Fatal("expected committed records")
	}
	original := ms.records[0]
	ms.records[0].Content.SHA256 = api.Digest(strings.Repeat("00", 32))
	if _, err := svc.VerifyMigratedState(context.Background(), scope, plan.ID); err == nil {
		t.Fatal("expected VerifyMigratedState to fail when read-back record hash differs")
	}
	ms.records[0] = original
	ms.records[0].Origin = "observation"
	if _, err := svc.VerifyMigratedState(context.Background(), scope, plan.ID); err == nil {
		t.Fatal("expected VerifyMigratedState to fail when read-back origin differs")
	}
}

func TestMutDuplicateDeliveredMail(t *testing.T) {
	scope := api.Scope{
		Config: "demo",
		Actor:  api.Actor{Kind: "human", ID: "human-1"},
	}
	ms := newMemStore()
	svc, _ := New(Dependencies{Store: ms, Human: newMemHuman(), Worker: &memWorker{}})
	planReq, _ := buildFixtureInStore(t, ms, "0.7.0", "demo")
	plan, err := svc.MigrationPlan(context.Background(), scope, planReq)
	if err != nil {
		t.Fatal(err)
	}
	applyReq := api.MigrationApplyRequest{PlanID: plan.ID}
	reqDigest, _ := RequestDigest("demo", "migration.apply", applyReq)
	applyScope := scope
	applyScope.Request = api.Request{
		Protocol:       api.Protocol,
		Schema:         api.SchemaVersion,
		Config:         "demo",
		RequestID:      "req-dm-1",
		IdempotencyKey: "idem-dm-1",
		RequestSHA256:  reqDigest,
		Method:         "migration.apply",
		Proof:          &api.ProofRef{ID: "proof-dm-1", RequestSHA256: reqDigest, ExpiresAt: "2099-01-01T00:00:00Z"},
	}
	applyScope = boundApplyScope(applyScope)
	if _, err := svc.MigrationApply(context.Background(), applyScope, applyReq); err != nil {
		t.Fatalf("MigrationApply failed: %v", err)
	}
	serviceScope, lease := primeMigrationCompletion(t, svc, ms, applyScope, plan)
	tx, err := buildImportTransaction(serviceScope, plan, svc.plans[plan.ID].bundle, *lease.Record.Effect.Context, ms.deployments[plan.ID])
	if err != nil {
		t.Fatal(err)
	}
	if len(tx.Events) == 0 {
		t.Fatal("migration constructed no historical records")
	}
	for _, tx := range []api.Transaction{tx} {
		for _, eff := range tx.Effects {
			if eff.Deliver != nil {
				t.Fatalf("unexpected duplicate mail delivery effect: %+v", eff.Deliver)
			}
		}
	}
}

func TestMutImportActiveAuthority(t *testing.T) {
	scope := api.Scope{
		Config: "demo",
		Actor:  api.Actor{Kind: "human", ID: "human-1"},
	}
	ms := newMemStore()
	svc, _ := New(Dependencies{Store: ms, Human: newMemHuman(), Worker: &memWorker{}})
	planReq, _ := buildFixtureInStore(t, ms, "1.0.0-candidate", "demo")
	plan, err := svc.MigrationPlan(context.Background(), scope, planReq)
	if err != nil {
		t.Fatal(err)
	}
	applyReq := api.MigrationApplyRequest{PlanID: plan.ID}
	reqDigest, _ := RequestDigest("demo", "migration.apply", applyReq)
	applyScope := scope
	applyScope.Request = api.Request{
		Protocol:       api.Protocol,
		Schema:         api.SchemaVersion,
		Config:         "demo",
		RequestID:      "req-ia-1",
		IdempotencyKey: "idem-ia-1",
		RequestSHA256:  reqDigest,
		Method:         "migration.apply",
		Proof:          &api.ProofRef{ID: "proof-ia-1", RequestSHA256: reqDigest, ExpiresAt: "2099-01-01T00:00:00Z"},
	}
	applyScope = boundApplyScope(applyScope)
	if _, err := svc.MigrationApply(context.Background(), applyScope, applyReq); err != nil {
		t.Fatalf("MigrationApply failed: %v", err)
	}
	serviceScope, lease := primeMigrationCompletion(t, svc, ms, applyScope, plan)
	tx, err := buildImportTransaction(serviceScope, plan, svc.plans[plan.ID].bundle, *lease.Record.Effect.Context, ms.deployments[plan.ID])
	if err != nil {
		t.Fatal(err)
	}
	if len(tx.Events) == 0 {
		t.Fatal("migration constructed no historical events")
	}
	for _, ev := range tx.Events {
		if ev.Kind == "identity.bound" {
			t.Fatal("migration emitted forbidden identity.bound event")
		}
		if ev.ParentLifeID != "" || len(ev.StarterChain) != 0 {
			t.Fatalf("migration synthesized parent_life_id=%s starter_chain=%v", ev.ParentLifeID, ev.StarterChain)
		}
	}
}

func TestMutRelaunchUnconfined(t *testing.T) {
	scope := api.Scope{
		Config: "demo",
		Actor:  api.Actor{Kind: "human", ID: "human-1"},
	}
	ms := newMemStore()
	svc, _ := New(Dependencies{Store: ms, Human: newMemHuman(), Worker: &memWorker{}})
	planReq, _ := buildFixtureInStore(t, ms, "0.7.0", "demo")
	plan, err := svc.MigrationPlan(context.Background(), scope, planReq)
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.PrepareRelaunch(context.Background(), scope, RelaunchOptions{
		PlanID:         plan.ID,
		Lane:           "beta",
		Level:          3,
		Role:           "executor",
		Driver:         api.DriverClaudock,
		ProfileGrantID: "pgrant-1",
		Task: api.BlobRef{
			ID:     "blob-task-1",
			SHA256: DigestBytes([]byte("continue work")),
			Bytes:  13,
			Class:  "task",
		},
		Budget: api.Budget{
			WallMS:      60000,
			CPUSeconds:  60,
			MemoryBytes: 1024 * 1024 * 512,
			Processes:   32,
			DiskBytes:   1024 * 1024 * 512,
			Currency:    "USD",
		},
		UseSharedLastHome: true,
	})
	var apiErr *api.Error
	if !asAPIError(err, &apiErr) || apiErr.Code != api.CodeInvalid {
		t.Fatalf("expected shared --last home relaunch to be rejected, got %v", err)
	}
}

func TestMutRollbackRelinkOld(t *testing.T) {
	scope := api.Scope{
		Config: "demo",
		Actor:  api.Actor{Kind: "human", ID: "human-1"},
	}
	ms := newMemStore()
	svc, _ := New(Dependencies{Store: ms, Human: newMemHuman(), Worker: &memWorker{}})
	_, backupDir := buildFixtureInStore(t, ms, "0.7.0", "demo")
	oldBin := filepath.Join(t.TempDir(), "laneboss-old")
	oldBinBytes := []byte("#!/bin/sh\necho 0.7.0\n")
	if err := os.WriteFile(oldBin, oldBinBytes, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := svc.ExecuteRollback(context.Background(), scope, RollbackRequest{
		Config:               "demo",
		TargetVersion:        "0.7.0",
		OldBinaryPath:        oldBin,
		ExpectedBinarySHA256: DigestBytes(oldBinBytes),
		FrozenBackupDir:      backupDir,
		ActiveV2StateDir:     t.TempDir(),
		RestoreTargetDir:     filepath.Join(t.TempDir(), "restored"),
		RetainedWorkDir:      filepath.Join(t.TempDir(), "retained"),
		V2Quiescent:          true,
		RelinkOntoV2Store:    true,
	})
	var apiErr *api.Error
	if !asAPIError(err, &apiErr) || apiErr.Code != api.CodeConflict {
		t.Fatalf("expected RelinkOntoV2Store to fail with conflict, got %v", err)
	}
}
