package store

import (
	"bytes"
	"context"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/reviewjob"
)

// Verify retained review causality without reauthorizing historical grants or
// inventing a native observation after restart. Current execution fences live
// in reviewClaim/ReviewSnapshot; this read checks the durable immutable joins.
func (s *Service) verifyReviews(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, "SELECT data FROM projections WHERE kind='review_snapshot' ORDER BY id")
	if err != nil {
		return err
	}
	var snapshots []reviewFrozen
	for rows.Next() {
		var raw []byte
		var frozen reviewFrozen
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return err
		}
		if err := decodeStored(raw, &frozen); err != nil {
			rows.Close()
			return err
		}
		snapshots = append(snapshots, frozen)
	}
	readErr, closeErr := rows.Err(), rows.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	for _, frozen := range snapshots {
		if frozen.Intent.Request.Target != frozen.Subject.Target || frozen.Intent.EndEventID != frozen.Subject.EndEventID || frozen.Intent.EndSeq != frozen.Subject.EndSeq || frozen.Subject.CaptureBindingID != frozen.Capture.Binding.ID {
			return fault(api.CodeIntegrity, "retained review freeze lost its original end or capture")
		}
		if frozen.Phase == "freezing" {
			continue
		}
		if frozen.Phase != "sealed" {
			return fault(api.CodeIntegrity, "retained review freeze has an unknown phase")
		}
		meta, raw, err := objectRow(ctx, s.db, frozen.Freeze.Snapshot.ID)
		if err != nil {
			return err
		}
		if meta.Ref != frozen.Freeze.Snapshot || meta.SourceOperationID != frozen.Intent.OperationID || meta.Origin != "service" {
			return fault(api.CodeIntegrity, "native review snapshot lost its immutable source provenance")
		}
		var tree api.ObjectManifest
		if api.DecodeObject(raw, &tree) != nil {
			return fault(api.CodeIntegrity, "native review snapshot is not a retained manifest")
		}
		for i := range tree.Entries {
			if tree.Entries[i].Path == "workspace" {
				tree.Entries[i].Path = "work"
			} else if strings.HasPrefix(tree.Entries[i].Path, "workspace/") {
				tree.Entries[i].Path = "work/" + strings.TrimPrefix(tree.Entries[i].Path, "workspace/")
			}
		}
		expected, err := canonicalValue(tree)
		if err != nil {
			return err
		}
		meta, raw, err = objectRow(ctx, s.db, frozen.Subject.Snapshot.ID)
		if err != nil {
			return err
		}
		if meta.Ref != frozen.Subject.Snapshot || meta.SourceOperationID != frozen.Intent.OperationID || !bytes.Equal(raw, expected) {
			return fault(api.CodeIntegrity, "review verifier snapshot differs from its exact normalized native tree")
		}
	}
	rows, err = s.db.QueryContext(ctx, "SELECT data FROM projections WHERE kind='review_job' ORDER BY id")
	if err != nil {
		return err
	}
	var records []reviewRecord
	for rows.Next() {
		var raw []byte
		var record reviewRecord
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return err
		}
		if err := decodeStored(raw, &record); err != nil {
			rows.Close()
			return err
		}
		records = append(records, record)
	}
	readErr, closeErr = rows.Err(), rows.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	for _, r := range records {
		if r.Test != nil && r.Preparation != nil {
			return fault(api.CodeIntegrity, "retained test job has conflicting native protocols")
		}
		if r.Test != nil {
			if err := s.verifyTestRecord(ctx, r); err != nil {
				return err
			}
			continue
		}
		validInput := r.Request.Method == "lane.review" && r.Job.Lease.Kind == "export" && r.Input.Schema == "laneboss.review-input.v2"
		var sealed any = r.Input
		if r.Preparation != nil {
			validInput = r.Request.Method == "grants.test-child" && r.Job.Lease.Kind == "test" && reviewjob.ValidateCheckInput(*r.Preparation, r.Job.Lease, r.Job.Plan) == nil
			sealed = r.Preparation
		}
		if !validInput || r.Job.Lease.OperationID != r.Job.Intent.OperationID || r.Job.Plan.Input != r.Job.Lease.Input || r.Job.Plan.Kind != r.Job.Lease.Kind || r.Input.Subject.Target != r.Job.Lease.Target {
			return fault(api.CodeIntegrity, "retained review job lost its original operation or fixed input")
		}
		meta, raw, err := objectRow(ctx, s.db, r.Job.Lease.Input.ID)
		if err != nil {
			return err
		}
		if meta.Ref != r.Job.Lease.Input || meta.SourceOperationID != r.Job.Intent.OperationID || meta.Origin != "service" || meta.ACL.Audience != "private" || !sameDataBytes(raw, sealed) {
			return fault(api.CodeIntegrity, "retained review input bytes changed")
		}
		if _, err := s.retainedReviewLease(ctx, s.db, r); err != nil {
			return err
		}
		effect, err := effectRow(ctx, s.db, r.Job.Lease.EffectID)
		if err != nil {
			return err
		}
		if effect.Effect.OperationID != r.Job.Intent.OperationID || effect.Effect.Worker == nil || !sameValue(*effect.Effect.Worker, r.Job.Plan) {
			return fault(api.CodeIntegrity, "retained review lost its sole original verifier effect")
		}
		if r.Ack != nil {
			meta, raw, err := objectRow(ctx, s.db, r.Ack.Receipt.Result.ID)
			if err != nil {
				return err
			}
			if meta.Ref != r.Ack.Receipt.Result || meta.SourceOperationID != r.Job.Intent.OperationID || !bytes.Equal(raw, r.Ack.Submission.Result) {
				return fault(api.CodeIntegrity, "retained review acknowledgement lost its exact result bytes")
			}
			if err := validateReviewOutput(r, raw); err != nil {
				return err
			}
		}
		if effect.Outcome != nil {
			if err := s.validateReviewOutcome(ctx, s.db, effect, *effect.Outcome); err != nil {
				return err
			}
		}
	}
	return nil
}
