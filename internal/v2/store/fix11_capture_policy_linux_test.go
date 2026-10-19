//go:build linux

package store

import (
	"context"
	"laneboss.io/laneboss/internal/v2/api"
	"testing"
	"time"
)

func TestCaptureRefusalD6Provenance(t *testing.T) {
	for _, fault := range []string{"valid", "missing_use", "foreign_manifest", "missing_event", "foreign_generation", "event_receipt", "event_change", "event_origin", "event_approval"} {
		t.Run(fault, func(t *testing.T) {
			s, _ := testStore(t)
			ctx := context.Background()
			operation := testID(t)
			approval := api.ChangeApproval{ID: testID(t), ChangeID: testID(t), RequesterLifeID: testID(t), ApproverKeyID: testID(t), NonceID: testID(t), ApprovedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano)), ManifestSHA256: testDigest([]byte("approved manifest")), BaseGeneration: 1, ExpiresAt: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))}
			application := api.ChangeReceipt{ID: testID(t), ChangeID: approval.ChangeID, ApprovalID: approval.ID, OldGeneration: 1, NewGeneration: 2, ManifestSHA256: approval.ManifestSHA256, AppliedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}
			policy := api.EffectivePolicy{Generation: 2, SHA256: testDigest([]byte("approved capture policy")), AllowCaptureRefusal: true, CaptureRefusalApprovalID: approval.ID}
			actor := api.Actor{Kind: "service", ID: testID(t)}
			// Primitive already-approved publication records isolate this store
			// provenance check; they do not prove a human/D6 ceremony.
			tx, err := s.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if err := put(ctx, tx, "approval", approval.ID, 1, approval); err != nil {
				t.Fatal(err)
			}
			if fault != "missing_use" {
				if err := s.guards(ctx, tx, api.Transaction{Scope: api.Scope{Config: s.deps.Config, Actor: actor}, Guards: []api.TransactionGuard{{Approval: &api.ApprovalUse{ApprovalID: approval.ID, ChangeID: approval.ChangeID, ManifestSHA256: approval.ManifestSHA256, BaseGeneration: 1}}}}, operation); err != nil {
					t.Fatal(err)
				}
			}
			if fault == "foreign_manifest" {
				application.ManifestSHA256 = testDigest([]byte("other manifest"))
			}
			if fault == "foreign_generation" {
				application.NewGeneration++
			}
			if err := put(ctx, tx, "application", application.ChangeID, 1, application); err != nil {
				t.Fatal(err)
			}
			if fault != "missing_event" {
				evidence := []byte("publication evidence")
				ref := api.BlobRef{ID: testID(t), Class: "artifact", Bytes: int64(len(evidence)), SHA256: testDigest(evidence)}
				change := api.ChangeRequest{Config: s.deps.Config, ID: application.ChangeID, OrgID: testID(t), Requester: actor, BaseGeneration: application.OldGeneration, ManifestSHA256: application.ManifestSHA256, Status: "applied", Reason: ref, Diff: ref, OwnershipManifest: ref,
					SourceSnapshot: api.OrgSnapshotRef{OrgID: testID(t), Generation: application.OldGeneration, ManifestSHA256: application.ManifestSHA256}, Files: []api.ResourceDelta{}, Derived: []api.ResourceDelta{}, Renderer: api.Executable{ID: testID(t), SHA256: testDigest([]byte("renderer fixture")), Version: "component-v1"}, CreatedAt: application.AppliedAt, ExpiresAt: approval.ExpiresAt}
				change.SourceSnapshot.OrgID = change.OrgID
				applied := application
				approved := approval
				payload := api.ChangeEvent{Change: change, Approval: &approved, Receipt: &applied, Reason: "component approved publication"}
				if fault == "event_receipt" {
					payload.Receipt.NewGeneration++
				}
				if fault == "event_change" {
					payload.Change.ID = testID(t)
				}
				if fault == "event_approval" {
					payload.Approval.ID = testID(t)
				}
				event := api.Event{Schema: api.SchemaVersion, ID: testID(t), Config: s.deps.Config, Kind: "org.change.applied", Actor: actor, RequestedBy: actor, OperationID: operation, RequestID: testID(t), Origin: "service", Payload: enrollmentJSON(t, payload), StarterChain: []api.ID{}}
				if fault == "event_origin" {
					event.Origin = "observation"
				}
				if _, err := appendPrivateEvent(ctx, tx, event, api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))); err != nil {
					t.Fatal(err)
				}
			}
			if err := put(ctx, tx, "policy", api.ID(s.deps.Config), 2, policy); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			binding := api.CaptureBinding{ID: testID(t), Config: s.deps.Config, ReservationID: testID(t), Target: api.LifeRef{LifeID: testID(t), Run: 1}, LaunchID: testID(t), HelperLeaseID: testID(t), OperationID: operation, RequestID: testID(t), RequestedBy: actor, Generation: 1, Status: "refused", Streams: []api.CaptureStreamBinding{}, Refusal: api.NotImplemented("lb-v2-admin", "component capture unavailable"), RefusalPolicy: &api.CaptureRefusalPolicy{Allowed: true, PolicyGeneration: 2, ApprovalID: approval.ID}}
			binding.Refusal.OperationID = operation
			err = s.currentCapturePolicy(ctx, s.db, binding)
			if fault == "valid" {
				if err != nil {
					t.Fatal("actual consumed publication did not authorize capture refusal", err)
				}
				return
			}
			if err == nil {
				t.Fatal("capture refusal accepted unproved D6 " + fault)
			}
		})
	}
}
