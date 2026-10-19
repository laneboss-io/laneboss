//go:build linux

package store

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type changePublisher interface {
	PublishChange(context.Context, api.Scope, api.PublishChangeRequest) (api.ChangeReceipt, error)
	ReconcileChange(context.Context, api.Scope, api.PublishChangeRequest) (api.ChangeReceipt, error)
}

func publicationClaim(t *testing.T, s *Service, tx api.Transaction) (api.Scope, api.EffectLease, api.PublishChangeRequest) {
	t.Helper()
	scope := api.Scope{Config: tx.Scope.Config, Actor: api.Actor{Kind: "service", ID: testID(t)}}
	lease, err := s.ClaimEffect(context.Background(), scope, api.EffectClaimRequest{EffectID: tx.Deferred.EffectID, ExpectedGeneration: 1, ClaimantID: scope.Actor.ID, Deadline: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))})
	if err != nil {
		t.Fatal(err)
	}
	var job orgApply
	if err := storedProjection(context.Background(), s.db, "org_apply", tx.Deferred.OperationID, &job); err != nil {
		t.Fatal(err)
	}
	return scope, lease, orgPublishRequest(lease, job.Change, job.Approval.ID)
}

func publicationOutcome(t *testing.T, tx api.Transaction, lease api.EffectLease, receipt api.ChangeReceipt) api.EffectOutcome {
	t.Helper()
	return api.EffectOutcome{EffectID: lease.Record.Effect.ID, ClaimID: lease.ClaimID, ExpectedGeneration: lease.Record.Generation, Status: "succeeded", Publication: &receipt, Reply: &api.DeferredCompletion{Deferred: *tx.Deferred, Reply: api.RPCReply{Result: enrollmentJSON(t, receipt)}}}
}

func TestChangePublicationLifecycle(t *testing.T) {
	s, deps, tx := deferredChangeFixture(t)
	ctx := context.Background()
	if _, err := s.Transact(ctx, tx); err != nil {
		t.Fatal(err)
	}
	publisher, ok := any(s).(changePublisher)
	if !ok {
		t.Fatal("canonical publication and reconciliation ports are missing")
	}
	scope, lease, request := publicationClaim(t, s, tx)
	result, err := publisher.PublishChange(ctx, scope, request)
	if err != nil {
		t.Fatal("actual canonical generation publication failed", err)
	}
	var job orgApply
	if err := storedProjection(ctx, s.db, "org_apply", tx.Deferred.OperationID, &job); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(deps.Directory, "org", "current", job.Change.Files[0].Path))
	if err != nil || testDigest(data) != job.Change.Files[0].After.SHA256 {
		t.Fatal("published pointer did not expose the approved actual bytes", err)
	}
	retained, err := s.LookupReceipt(ctx, tx.Scope, tx.Deferred.Key)
	if err != nil || retained.Reply != nil {
		t.Fatal("filesystem publication completed the public request before store readback", err)
	}
	again, err := publisher.ReconcileChange(ctx, scope, request)
	if err != nil || again != result {
		t.Fatal("publication recovery changed the original marker/receipt", err)
	}
	outcome := publicationOutcome(t, tx, lease, result)
	commit, err := s.CompleteEffect(ctx, scope, outcome)
	if err != nil || commit.Reply == nil || commit.Operation.Status != "succeeded" {
		t.Fatal("measured publication did not seal its original deferred reply", err)
	}
	replay, err := s.CompleteEffect(ctx, scope, outcome)
	if err != nil || !replay.Replayed || replay.LastSeq != commit.LastSeq || !reflect.DeepEqual(replay.Reply, commit.Reply) {
		t.Fatal("duplicate publication completion wrote a second result", err)
	}
	retained, err = s.AwaitReceipt(ctx, tx.Scope, tx.Deferred.Key)
	if err != nil || retained.Reply == nil || retained.Deferred == nil || *retained.Deferred != *tx.Deferred {
		t.Fatal("original public waiter did not receive its sole publication reply", err)
	}
	var actual api.ChangeReceipt
	if err := json.Unmarshal(retained.Reply.Result, &actual); err != nil || actual != result {
		t.Fatal("public reply differs from measured publication", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(deps)
	if err != nil {
		t.Fatal("completed publication failed reopen integrity", err)
	}
	defer reopened.Close()
	if check, err := reopened.Verify(ctx, api.VerifyRequest{Scope: "all"}); err != nil || !check.OK {
		t.Fatal("publication failed store verification", err)
	}
	retained, err = reopened.LookupReceipt(ctx, tx.Scope, tx.Deferred.Key)
	if err != nil || !reflect.DeepEqual(retained.Reply, commit.Reply) {
		t.Fatal("reopened publication reply changed", err)
	}
}

func TestChangePublicationFences(t *testing.T) {
	for _, defect := range []string{"foreign_scope", "foreign_claimant", "stale_claim", "foreign_manifest", "foreign_renderer", "missing_marker", "tampered_bytes"} {
		t.Run(defect, func(t *testing.T) {
			s, deps, tx := deferredChangeFixture(t)
			ctx := context.Background()
			if _, err := s.Transact(ctx, tx); err != nil {
				t.Fatal(err)
			}
			publisher, ok := any(s).(changePublisher)
			if !ok {
				t.Fatal("canonical publication and reconciliation ports are missing")
			}
			scope, lease, request := publicationClaim(t, s, tx)
			if defect == "missing_marker" {
				madeup := api.ChangeReceipt{ID: testID(t), ChangeID: request.ChangeID, ApprovalID: request.ApprovalID, OldGeneration: 1, NewGeneration: 2, ManifestSHA256: request.ManifestSHA256, AppliedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}
				if _, err := s.CompleteEffect(ctx, scope, publicationOutcome(t, tx, lease, madeup)); err == nil {
					t.Fatal("completion accepted a receipt without a filesystem marker")
				}
				return
			}
			if defect == "tampered_bytes" {
				actual, err := publisher.PublishChange(ctx, scope, request)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(deps.Directory, "org", "current", "shared/scripts/check.sh"), []byte("unreviewed change"), 0755); err != nil {
					t.Fatal(err)
				}
				if _, err := s.CompleteEffect(ctx, scope, publicationOutcome(t, tx, lease, actual)); err == nil {
					t.Fatal("publisher completion ignored changed canonical bytes")
				}
				return
			}
			switch defect {
			case "foreign_scope":
				scope.Config = "foreign-case"
			case "foreign_claimant":
				scope.Actor.ID = testID(t)
			case "stale_claim":
				request.Lease.Record.Generation++
			case "foreign_manifest":
				request.ManifestSHA256 = testDigest([]byte("other manifest"))
			case "foreign_renderer":
				request.Renderer.SHA256 = testDigest([]byte("other renderer"))
			}
			if _, err := publisher.PublishChange(ctx, scope, request); err == nil {
				t.Fatal("publication accepted " + defect)
			}
			if _, err := os.Lstat(filepath.Join(deps.Directory, "org", "current")); !os.IsNotExist(err) {
				t.Fatal("refused publisher changed the canonical pointer", err)
			}
		})
	}
}
