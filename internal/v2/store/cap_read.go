package store

import (
	"context"
	"database/sql"
	"errors"

	"laneboss.io/laneboss/internal/v2/api"
)

// Capture objects keep their immutable producer ACL. Public readers are
// derived from the protected run and its root ticket, never from a blob ID,
// a human label, a supervisor level or the full ancestor chain.
func (s *Service) captureVisible(ctx context.Context, db queryer, scope api.Scope, metadata api.ObjectMetadata) (bool, error) {
	acl := metadata.ACL
	if acl.Config != scope.Config || acl.Owner.Kind != "worker" || acl.LifeID == "" ||
		acl.Audience != "owner" || acl.Generation != 1 || len(acl.Participants) != 0 {
		return false, nil
	}
	var raw []byte
	err := db.QueryRowContext(ctx, `SELECT data FROM projections WHERE kind='capture_state'
 AND json_extract(data,'$.binding.operation_id')=?
 AND json_extract(data,'$.binding.target.life_id')=?
 AND json_extract(data,'$.binding.producer_id')=?`,
		string(metadata.SourceOperationID), string(acl.LifeID), string(acl.Owner.ID)).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var state api.CaptureState
	if err := decodeStored(raw, &state); err != nil {
		return false, err
	}
	return s.captureReader(ctx, db, scope, state.Binding)
}

// readScope has already checked the caller's live authentication, session or
// launch. This check uses the same pinned database as the selected object.
func (s *Service) captureReader(ctx context.Context, db queryer, scope api.Scope, binding api.CaptureBinding) (bool, error) {
	if binding.Config != scope.Config || binding.Status != "registered" ||
		scope.Actor.Kind != "human" && scope.Actor.Kind != "lane" {
		return false, nil
	}
	if err := api.ValidateCaptureBinding(binding); err != nil {
		return false, err
	}
	var plan api.LaunchPlanRecord
	if err := storedProjection(ctx, db, "launch_plan", binding.ReservationID, &plan); err != nil {
		return false, err
	}
	r := plan.Reservation
	if plan.Plan == nil || !sameValue(plan.Plan.Capture, binding) || r.Config != scope.Config ||
		r.ID != binding.ReservationID || r.Target != binding.Target || r.LaunchID != binding.LaunchID ||
		r.OperationID != binding.OperationID || r.RequestID != binding.RequestID || r.RequestedBy != binding.RequestedBy {
		return false, fault(api.CodeIntegrity, "capture reader lacks its retained launch binding")
	}
	if scope.Actor.Kind == "lane" {
		return r.ParentLifeID != "" && scope.Actor.LifeID == r.ParentLifeID, nil
	}
	var raw []byte
	err := db.QueryRowContext(ctx, `SELECT data FROM projections WHERE kind='launch_plan'
 AND json_extract(data,'$.reservation.target.life_id')=?
 AND json_extract(data,'$.reservation.base_generation')=0
 AND json_extract(data,'$.reservation.mode') IN ('start','adopt')`, string(r.RootLifeID)).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var root api.LaunchPlanRecord
	if err := decodeStored(raw, &root); err != nil {
		return false, err
	}
	if root.Reservation.Target.LifeID != r.RootLifeID || root.Reservation.RootLifeID != r.RootLifeID ||
		root.Reservation.ParentLifeID != "" || root.Reservation.RequestedBy != scope.Actor {
		return false, nil
	}
	ticket, err := s.reservationTicket(ctx, db, root)
	if err != nil {
		return false, err
	}
	return ticket.PrincipalID == scope.Actor.ID && ticket.Config == scope.Config, nil
}
