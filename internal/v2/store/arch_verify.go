package store

import (
	"context"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
)

// Verify immutable archive causality after restart without treating historical
// grant expiry as corruption or manufacturing new execution authority.
func (s *Service) verifyArchives(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, "SELECT data FROM projections WHERE kind='archive_job' ORDER BY id")
	if err != nil {
		return err
	}
	records := []archiveRecord{}
	for rows.Next() {
		var raw []byte
		var r archiveRecord
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return err
		}
		if err := decodeStored(raw, &r); err != nil {
			rows.Close()
			return err
		}
		records = append(records, r)
	}
	readErr, closeErr := rows.Err(), rows.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	for _, r := range records {
		if r.Request.Method != "lane.archive" || r.Job.Intent.OperationID == "" || r.Request.Config != s.deps.Config || r.Input.JobID != r.Job.ID || r.Input.Intent != r.Job.Intent || r.Input.StoreID != s.storeID {
			return fault(api.CodeIntegrity, "retained archive lost its original operation and request")
		}
		switch r.Phase {
		case "failed":
			if r.Failure == nil || r.Commit == nil || r.Commit.Operation.Status != "failed" || r.Commit.Operation.Error == nil {
				return fault(api.CodeIntegrity, "failed archive lost its terminal outcome")
			}
			continue
		case "freezing":
			if r.Commit != nil || r.Ack != nil || len(r.Parts) != 0 {
				return fault(api.CodeIntegrity, "unsealed archive published completion")
			}
			continue
		case "sealed", "verified":
		default:
			return fault(api.CodeIntegrity, "retained archive has an unknown phase")
		}
		if _, _, err := s.archiveRefs(ctx, s.db, r); err != nil {
			return err
		}
		effect, err := effectRow(ctx, s.db, r.Job.Lease.EffectID)
		if err != nil {
			return err
		}
		if effect.Effect.OperationID != r.Job.Intent.OperationID || effect.Effect.Worker == nil || !sameValue(*effect.Effect.Worker, r.Job.Plan) {
			return fault(api.CodeIntegrity, "retained archive lost its fixed worker effect")
		}
		if r.Ack != nil {
			meta, raw, err := objectRow(ctx, s.db, r.Ack.Receipt.Result.ID)
			if err != nil {
				return err
			}
			if meta.Ref != r.Ack.Receipt.Result || meta.SourceOperationID != r.Job.Intent.OperationID || string(raw) != string(r.Ack.Submission.Result) {
				return fault(api.CodeIntegrity, "retained archive acknowledgement lost its exact result bytes")
			}
			if _, err := s.verifyArchiveBytes(ctx, s.db, r, raw); err != nil {
				return err
			}
		}
		if r.Phase == "verified" {
			if r.Commit == nil || r.Ack == nil || effect.Outcome == nil || effect.State != api.EffectCompleted || effect.Outcome.Status != "succeeded" || effect.Outcome.Output == nil || *effect.Outcome.Output != r.Ack.Receipt.Result || effect.Outcome.Observation == nil || effect.Outcome.Observation.Handle != r.Process {
				return fault(api.CodeIntegrity, "verified archive lacks its atomic original effect completion")
			}
			var raw []byte
			if err := s.db.QueryRowContext(ctx, "SELECT data FROM events WHERE seq=?", uint64(r.Commit.FirstSeq)).Scan(&raw); err != nil {
				return err
			}
			var event api.Event
			var receipt api.ArchiveReceipt
			var completion struct {
				Receipt api.ArchiveReceipt
				Archive api.ObjectAssembly
			}
			if decodeStored(raw, &event) != nil || api.DecodeObject(event.Payload, &receipt) != nil || json.Unmarshal(r.Ack.Submission.Result, &completion) != nil || event.Kind != "archive.verified" || event.OperationID != r.Job.Intent.OperationID || event.RequestID != r.Request.RequestID || receipt != completion.Receipt {
				return fault(api.CodeIntegrity, "verified archive differs from its atomic verification event")
			}
			public, err := s.lookupReceipt(ctx, s.db, r.Scope, requestKey(r.Request))
			if err != nil {
				return err
			}
			if public.Reply == nil || public.Reply.Error != nil || !sameValue(public.Reply.Result, receipt) || !sameValue(public.Operation, r.Commit.Operation) {
				return fault(api.CodeIntegrity, "verified archive differs from its original typed public reply")
			}
		} else if r.Commit != nil {
			return fault(api.CodeIntegrity, "unverified archive has a completion receipt")
		}
	}
	return nil
}

func (s *Service) verifyCollections(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, "SELECT data FROM projections WHERE kind='collection_delete' ORDER BY id")
	if err != nil {
		return err
	}
	deletions := []collectionDeletion{}
	for rows.Next() {
		var raw []byte
		var d collectionDeletion
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return err
		}
		if err := decodeStored(raw, &d); err != nil {
			rows.Close()
			return err
		}
		deletions = append(deletions, d)
	}
	readErr, closeErr := rows.Err(), rows.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	for _, d := range deletions {
		var metadata api.ObjectMetadata
		if decodeStored([]byte(d.Metadata), &metadata) != nil || metadata.Ref != d.Object.Ref || objectIdentity(metadata) != d.Object.Identity || d.Result.ObjectID != metadata.Ref.ID || d.Result.Action != "remove" || d.Result.Reason != "unreferenced" || d.Result.Before.State != "present" || d.Result.After.State != "absent" || d.Result.Before.SHA256 != metadata.Ref.SHA256 || d.Result.Before.Bytes != metadata.Ref.Bytes {
			return fault(api.CodeIntegrity, "collected object lost its exact protected deletion journal")
		}
		var count int
		if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM objects WHERE id=?", string(d.Object.Ref.ID)).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return fault(api.CodeIntegrity, "collected object reappeared in its SQL namespace")
		}
	}
	rows, err = s.db.QueryContext(ctx, "SELECT data FROM projections WHERE kind='collection' ORDER BY id")
	if err != nil {
		return err
	}
	records := []collectionRecord{}
	for rows.Next() {
		var raw []byte
		var r collectionRecord
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return err
		}
		if err := decodeStored(raw, &r); err != nil {
			rows.Close()
			return err
		}
		records = append(records, r)
	}
	readErr, closeErr = rows.Err(), rows.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	for _, r := range records {
		job := api.CleanupJob{Intent: r.Intent}
		if r.Inventory != nil {
			meta, raw, err := objectRow(ctx, s.db, r.Inventory.Manifest.ID)
			if err != nil {
				return err
			}
			body, _, err := api.CleanupInventoryBytes(*r.Inventory)
			if err != nil || meta.Ref != r.Inventory.Manifest || string(body) != string(raw) {
				return fault(api.CodeIntegrity, "retained cleanup inventory bytes changed")
			}
		}
		if r.Receipt != nil {
			if _, err := s.readCollectionReceipt(ctx, s.db, job, *r.Receipt); err != nil {
				return err
			}
		}
		if r.Commit != nil {
			if r.Inventory == nil || r.Receipt == nil || r.Evidence.ID == "" {
				return fault(api.CodeIntegrity, "completed collection omitted its inventory, receipt or fresh verification")
			}
			meta, _, err := objectRow(ctx, s.db, r.Evidence.ID)
			if err != nil {
				return err
			}
			if meta.Ref != r.Evidence || meta.SourceOperationID != r.Intent.Cause.CauseOperationID {
				return fault(api.CodeIntegrity, "completed collection lost its retained independent evidence")
			}
			var raw []byte
			if err := s.db.QueryRowContext(ctx, "SELECT data FROM events WHERE seq=?", uint64(r.Commit.FirstSeq)).Scan(&raw); err != nil {
				return err
			}
			var event api.Event
			var body api.CleanEvent
			if decodeStored(raw, &event) != nil || api.DecodeObject(event.Payload, &body) != nil || event.Kind != "lane.cleaned" || event.OperationID != r.Intent.Cause.CauseOperationID || event.RequestID != r.Intent.Cause.CauseRequestID || body.ArchiveReceipt != r.Intent.Archive {
				return fault(api.CodeIntegrity, "completed collection lost its atomic cleaned event")
			}
		}
	}
	return nil
}
