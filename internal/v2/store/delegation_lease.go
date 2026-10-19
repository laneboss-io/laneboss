package store

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

// A lease is private store state, sealed from the original launch reservation,
// issued sets, authentic child creation and measured parent end. It cannot be
// supplied through StateWrites or used to issue a new child after parent exit.
type delegationLease struct {
	Parent            api.LifeRef
	LaunchID          api.ID
	ParentGrants      api.GrantSet
	ChildGrants       api.GrantSet
	ChildEvent        api.ID
	ChildSeq          api.Sequence
	EndEvent          api.ID
	EndSeq            api.Sequence
	CancellationEpoch api.Generation
	SHA256            api.Digest
}

func (s *Service) sealDelegation(lease delegationLease) (api.Digest, error) {
	lease.SHA256 = ""
	raw, err := canonicalValue(lease)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte("laneboss.delegation.v1\x00"))
	mac.Write(raw)
	return api.Digest(hex.EncodeToString(mac.Sum(nil))), nil
}

func (s *Service) deriveDelegationLease(ctx context.Context, db queryer, parent api.Lane, child api.Lane, end api.Event) (delegationLease, error) {
	var result delegationLease
	refuse := func() (delegationLease, error) {
		return result, fault(api.CodeForbidden, "post-exit lease lacks its prior authentic delegation and measured end")
	}
	if child.ParentLifeID != parent.LifeID || child.Level >= parent.Level || end.Kind != "lane.ended" || end.Origin != "service" || end.Actor.Kind != "service" || end.Config != s.deps.Config || end.LifeID != parent.LifeID || end.Run != parent.Run {
		return refuse()
	}
	var ended api.RunEndEvent
	if err := wire.Decode(end.Payload, &ended); err != nil {
		return result, err
	}
	if ended.LaunchID != parent.LaunchID || ended.Reason != "exit" || ended.Observation.State != "exited" || ended.Observation.Survivors == nil || *ended.Observation.Survivors != 0 || ended.Observation.ExitCode == nil && ended.Observation.Signal == nil || ended.Observation.Handle.Target != (api.LifeRef{LifeID: parent.LifeID, Run: parent.Run}) {
		return refuse()
	}
	var record api.LaunchRecord
	if err := storedProjection(ctx, db, "launch", parent.LaunchID, &record); err != nil {
		return result, err
	}
	if record.Revoked || record.Target != ended.Observation.Handle.Target || record.ContainmentID != ended.Observation.Handle.ContainmentID || record.ProcessGeneration != ended.Observation.Handle.Generation {
		return refuse()
	}
	creation, err := starterEvent(ctx, db, child.LifeID)
	if err != nil {
		return result, err
	}
	var created api.LaunchEvent
	if err := wire.Decode(creation.Payload, &created); err != nil {
		return result, err
	}
	if creation.Seq >= end.Seq || created.Lane.ParentLifeID != parent.LifeID || created.GrantSetID != child.GrantSetID {
		return refuse()
	}
	if err := storedProjection(ctx, db, "grants", parent.GrantSetID, &result.ParentGrants); err != nil {
		return result, err
	}
	if err := storedProjection(ctx, db, "grants", child.GrantSetID, &result.ChildGrants); err != nil {
		return result, err
	}
	if result.ParentGrants.Revoked || result.ChildGrants.Revoked || result.ParentGrants.PolicyGeneration != parent.PolicyGeneration || result.ChildGrants.PolicyGeneration != parent.PolicyGeneration || created.GrantsSHA256 != result.ChildGrants.SHA256 {
		return refuse()
	}
	// A copied starter label cannot supply authority. Read the child's original
	// reservation and its independently retained exact parent ceiling.
	binding, err := s.launchBinding(ctx, db, created.LaunchID)
	if err != nil {
		return result, err
	}
	if binding.Recovery == nil {
		return refuse()
	}
	var plan api.LaunchPlanRecord
	if err := storedProjection(ctx, db, "launch_plan", binding.Recovery.PlanID, &plan); err != nil {
		return result, err
	}
	var ceiling launchAuthority
	if err := storedProjection(ctx, db, "launch_authority", plan.Reservation.ID, &ceiling); err != nil {
		return result, err
	}
	if plan.Reservation.ParentLifeID != parent.LifeID || plan.Reservation.Authority.Kind != "starter" || plan.Reservation.Authority.ID != parent.LaunchID || !sameValue(ceiling.Ceiling, result.ParentGrants) {
		return refuse()
	}
	result.Parent, result.LaunchID = record.Target, record.ID
	result.ChildEvent, result.ChildSeq, result.EndEvent, result.EndSeq = creation.ID, creation.Seq, end.ID, end.Seq
	result.CancellationEpoch = parent.CancellationEpoch
	result.SHA256, err = s.sealDelegation(result)
	return result, err
}

func (s *Service) stampDelegationLeases(ctx context.Context, tx *sql.Tx, input api.Transaction, operation api.ID) error {
	for _, submitted := range input.Events {
		if submitted.Kind != "lane.ended" {
			continue
		}
		var end api.Event
		var raw []byte
		if err := tx.QueryRowContext(ctx, "SELECT data FROM events WHERE id=? AND json_extract(data,'$.operation_id')=?", string(submitted.ID), string(operation)).Scan(&raw); err != nil {
			return err
		}
		if err := decodeStored(raw, &end); err != nil {
			return err
		}
		var parent api.Lane
		if err := storedProjection(ctx, tx, "lane", end.LifeID, &parent); err != nil {
			return err
		}
		var launch api.LaunchRecord
		if err := storedProjection(ctx, tx, "launch", parent.LaunchID, &launch); err != nil {
			return err
		}
		if launch.Revoked {
			continue
		} // Revocation never preserves delegable authority.
		lanes, err := projectionValues[api.Lane](ctx, tx, "lane")
		if err != nil {
			return err
		}
		for _, child := range lanes {
			if child.ParentLifeID != parent.LifeID || child.Cleaned {
				continue
			}
			var parentSet, childSet api.GrantSet
			if err := storedProjection(ctx, tx, "grants", parent.GrantSetID, &parentSet); err != nil {
				return err
			}
			if err := storedProjection(ctx, tx, "grants", child.GrantSetID, &childSet); err != nil {
				return err
			}
			if parentSet.Revoked || childSet.Revoked || parentSet.PolicyGeneration != parent.PolicyGeneration || childSet.PolicyGeneration != parent.PolicyGeneration {
				continue
			}
			creation, err := starterEvent(ctx, tx, child.LifeID)
			if err != nil {
				return err
			}
			var created api.LaunchEvent
			if err := decodeStored(creation.Payload, &created); err != nil {
				return err
			}
			binding, err := s.launchBinding(ctx, tx, created.LaunchID)
			if err != nil {
				return err
			}
			if binding.Recovery == nil {
				return fault(api.CodeIntegrity, "delegation candidate lost its original reservation")
			}
			var plan api.LaunchPlanRecord
			if err := storedProjection(ctx, tx, "launch_plan", binding.Recovery.PlanID, &plan); err != nil {
				return err
			}
			var ceiling launchAuthority
			if err := storedProjection(ctx, tx, "launch_authority", plan.Reservation.ID, &ceiling); err != nil {
				return err
			}
			// An ended run is still recorded when the child has no preservable
			// authority. It receives no new lease across a changed issuing run,
			// policy, parent ceiling or child grant generation.
			if plan.Reservation.Authority.ID != parent.LaunchID || !sameValue(ceiling.Ceiling, parentSet) || created.GrantsSHA256 != childSet.SHA256 {
				continue
			}
			lease, err := s.deriveDelegationLease(ctx, tx, parent, child, end)
			if err != nil {
				return err
			}
			if err := putGenerated(ctx, tx, "delegation_lease", child.GrantSetID, 1, lease); err != nil {
				return err
			}
		}
	}
	return nil
}

// Verification re-derives the seal from immutable journal facts and current
// revocation/policy/expiry fences. A projection checksum alone is insufficient.
func (s *Service) VerifyDelegationLease(ctx context.Context, scope api.Scope, parentID, childSetID api.ID) (api.Digest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return "", err
	}
	if !internalScope(scope) || scope.Actor.Kind != "service" {
		return "", fault(api.CodeForbidden, "delegation leases require the private grants reader")
	}
	if err := s.readScope(ctx, scope); err != nil {
		return "", err
	}
	db, err := s.reader(scope)
	if err != nil {
		return "", err
	}
	var lease delegationLease
	if err := storedProjection(ctx, db, "delegation_lease", childSetID, &lease); err != nil {
		return "", err
	}
	var parent, child api.Lane
	if err := storedProjection(ctx, db, "lane", parentID, &parent); err != nil {
		return "", err
	}
	if err := storedProjection(ctx, db, "lane", lease.ChildGrants.LifeID, &child); err != nil {
		return "", err
	}
	if parent.LifeID != lease.Parent.LifeID || parent.Run != lease.Parent.Run || parent.LaunchID != lease.LaunchID || parent.CancellationEpoch != lease.CancellationEpoch || child.GrantSetID != childSetID || child.Cleaned || parent.Cleaned {
		return "", fault(api.CodeConflict, "delegation lease life run or cancellation fence changed")
	}
	switch parent.State {
	case "verifying", "idle", "profile_wait", "accepted", "merged", "abandoned":
	default:
		return "", fault(api.CodeForbidden, "delegation lease requires a measured ended ancestor")
	}
	var policy api.EffectivePolicy
	if err := storedProjection(ctx, db, "policy", api.ID(s.deps.Config), &policy); err != nil {
		return "", err
	}
	if policy.Generation != lease.ParentGrants.PolicyGeneration || !future(lease.ParentGrants.ExpiresAt, s.deps.Clock.Now()) || !future(lease.ChildGrants.ExpiresAt, s.deps.Clock.Now()) {
		return "", fault(api.CodeConflict, "delegation lease expired or its policy changed")
	}
	for _, set := range []api.GrantSet{lease.ParentGrants, lease.ChildGrants} {
		for _, expiry := range manifest.Expiries(set) {
			if !future(expiry, s.deps.Clock.Now()) {
				return "", fault(api.CodeForbidden, "delegation lease member expired")
			}
		}
	}
	var raw []byte
	if err := db.QueryRowContext(ctx, "SELECT data FROM events WHERE id=? AND seq=?", string(lease.EndEvent), uint64(lease.EndSeq)).Scan(&raw); err != nil {
		return "", err
	}
	var end api.Event
	if err := json.Unmarshal(raw, &end); err != nil {
		return "", err
	}
	actual, err := s.deriveDelegationLease(ctx, db, parent, child, end)
	if err != nil {
		return "", err
	}
	if !sameValue(actual, lease) {
		return "", fault(api.CodeIntegrity, "sealed delegation differs from its retained immutable authority")
	}
	return lease.SHA256, nil
}
