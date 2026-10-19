package store

import (
	"context"
	"crypto/hmac"

	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Service) verifyDelegationState(ctx context.Context) error {
	leases, err := projectionValues[delegationLease](ctx, s.db, "delegation_lease")
	if err != nil {
		return err
	}
	for _, lease := range leases {
		seal, err := s.sealDelegation(lease)
		if err != nil || !hmac.Equal([]byte(seal), []byte(lease.SHA256)) || lease.Parent.LifeID == "" || lease.ChildGrants.ParentLifeID != lease.Parent.LifeID || lease.ChildSeq == 0 || lease.EndSeq <= lease.ChildSeq {
			return fault(api.CodeIntegrity, "delegation lease lost its private authority seal")
		}
		parent, err := s.launchBinding(ctx, s.db, lease.LaunchID)
		if err != nil {
			return err
		}
		if parent.Record.Target != lease.Parent || parent.Record.GrantSetID != lease.ParentGrants.ID {
			return fault(api.CodeIntegrity, "delegation lease lost its original parent binding")
		}
		var raw []byte
		if err := s.db.QueryRowContext(ctx, "SELECT data FROM events WHERE id=? AND seq=?", string(lease.ChildEvent), uint64(lease.ChildSeq)).Scan(&raw); err != nil {
			return err
		}
		var created api.Event
		if err := decodeStored(raw, &created); err != nil {
			return err
		}
		var child api.LaunchEvent
		if err := decodeStored(created.Payload, &child); err != nil {
			return err
		}
		if created.Origin != "service" || created.Actor.Kind != "service" || created.Kind != "lane.created" && created.Kind != "lane.adopted" || created.LifeID != lease.ChildGrants.LifeID || child.GrantSetID != lease.ChildGrants.ID || child.GrantsSHA256 != lease.ChildGrants.SHA256 {
			return fault(api.CodeIntegrity, "delegation lease changed its authentic child creation")
		}
		binding, err := s.launchBinding(ctx, s.db, child.LaunchID)
		if err != nil {
			return err
		}
		var authority launchAuthority
		if binding.Recovery == nil {
			return fault(api.CodeIntegrity, "delegation lease child lost its original reservation")
		}
		if err := storedProjection(ctx, s.db, "launch_authority", binding.Recovery.PlanID, &authority); err != nil {
			return err
		}
		if !sameValue(authority.Ceiling, lease.ParentGrants) {
			return fault(api.CodeIntegrity, "delegation lease changed its retained parent ceiling")
		}
		if err := s.db.QueryRowContext(ctx, "SELECT data FROM events WHERE id=? AND seq=?", string(lease.EndEvent), uint64(lease.EndSeq)).Scan(&raw); err != nil {
			return err
		}
		var event api.Event
		if err := decodeStored(raw, &event); err != nil {
			return err
		}
		var end api.RunEndEvent
		if err := decodeStored(event.Payload, &end); err != nil {
			return err
		}
		if event.Kind != "lane.ended" || event.Origin != "service" || event.Actor.Kind != "service" || event.LifeID != lease.Parent.LifeID || event.Run != lease.Parent.Run || end.LaunchID != lease.LaunchID || end.Reason != "exit" || end.Observation.State != "exited" || end.Observation.Survivors == nil || *end.Observation.Survivors != 0 || end.Observation.Handle.ContainmentID != parent.Record.ContainmentID || end.Observation.Handle.Generation != parent.Record.ProcessGeneration {
			return fault(api.CodeIntegrity, "delegation lease lost its actual measured parent end")
		}
	}
	return nil
}
