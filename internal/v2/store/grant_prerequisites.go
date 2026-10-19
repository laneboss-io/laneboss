package store

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

// The lane helper measures its registered capture worker. A separate worker
// or external resource has a different native owner; do not credit that owner
// from the lane's zero-survivor observation or from a consumed input lease.
func (s *Service) grantCascadeCollectionPrerequisites(ctx context.Context, db readDatabase, affected map[api.ID]bool, lanes []api.Lane, sets []api.GrantSet) error {
	for _, set := range sets {
		if affected[set.ID] && len(set.Resources) != 0 {
			return fault(api.CodePrerequisite, "revocation awaits the external resource owner's measured collection")
		}
	}
	captures := map[api.ID]bool{}
	for _, lane := range lanes {
		if !affected[lane.GrantSetID] || lane.Cleaned {
			continue
		}
		binding, err := s.launchBinding(ctx, db, lane.LaunchID)
		if err != nil {
			return err
		}
		if binding.Recovery == nil {
			return fault(api.CodePrerequisite, "revocation needs the lane's original helper recovery binding")
		}
		if binding.Recovery.Capture.Status == "registered" {
			captures[binding.Recovery.Capture.ProducerID] = true
		}
	}
	plans, err := projectionValues[api.LaunchPlanRecord](ctx, db, "launch_plan")
	if err != nil {
		return err
	}
	for _, plan := range plans {
		if !affected[plan.Reservation.GrantSetID] || plan.Phase != "failed" {
			continue
		}
		if plan.Plan != nil && plan.Plan.Capture.ProducerID != "" {
			captures[plan.Plan.Capture.ProducerID] = true
		}
	}
	records, err := projectionValues[api.LaunchRecord](ctx, db, "launch")
	if err != nil {
		return err
	}
	for _, worker := range records {
		if worker.Kind != "worker" || !affected[worker.GrantSetID] || captures[worker.Actor.ID] {
			continue
		}
		if !worker.Revoked {
			return fault(api.CodePrerequisite, "revocation awaits the independent worker owner's causal collection")
		}
		rows, err := db.QueryContext(ctx, "SELECT data FROM events WHERE json_extract(data,'$.kind')='helper.released' AND json_extract(data,'$.payload.lease_id')=?", string(worker.UIDLeaseID))
		if err != nil {
			return err
		}
		measured := false
		for rows.Next() {
			var raw []byte
			var event api.Event
			var receipt api.ReleaseReceipt
			if err := rows.Scan(&raw); err != nil {
				rows.Close()
				return err
			}
			if err := decodeStored(raw, &event); err != nil {
				rows.Close()
				return err
			}
			if err := decodeStored(event.Payload, &receipt); err != nil {
				rows.Close()
				return err
			}
			measured = measured || event.Origin == "service" && event.Actor.Kind == "service" && api.ValidateReleaseReceipt(receipt) == nil && receipt.Quiescence.Handle.Target == worker.Target && receipt.ContainmentID == worker.ContainmentID && receipt.Quiescence.Handle.Generation == worker.ProcessGeneration
		}
		readErr, closeErr := rows.Err(), rows.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if !measured {
			return fault(api.CodePrerequisite, "revocation awaits the independent worker's measured helper release")
		}
		var revoked api.LaunchRevocation
		if err := storedProjection(ctx, db, "launch_revocation", worker.ID, &revoked); err != nil {
			return fault(api.CodePrerequisite, "revocation awaits the independent worker's causal identity decision")
		}
		closed := false
		for _, kind := range []string{"grant_worker_close", "grant_transport_close"} {
			receipts, err := projectionValues[grantTransportClose](ctx, db, kind)
			if err != nil {
				return err
			}
			for _, receipt := range receipts {
				closed = closed || receipt.LaunchID == worker.ID && receipt.EventID == revoked.EventID && api.ValidateTransportInvalidation(revoked, receipt.Receipt) == nil
			}
		}
		if !closed {
			return fault(api.CodePrerequisite, "revocation awaits the independent worker's measured transport collection")
		}
	}
	return nil
}
