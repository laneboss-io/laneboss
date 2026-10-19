package secrets

import (
	"context"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
	"reflect"
	"slices"
)

func (s *Service) projectionJournal(ctx context.Context, f *projectionFlight, id api.ID, fn func(bstate.Journal) error) error {
	backend, err := s.brokerBackend()
	if err != nil {
		return err
	}
	durable, ok := backend.(bstate.DurableBackend)
	if !ok {
		return wire.Error(api.CodePrerequisite, "credential projection requires its durable journal")
	}
	return durable.WithBrokerDurable(ctx, func(j bstate.Journal) error {
		err := fn(j)
		if err != nil {
			return s.fenceProjectionLocked(j, f, id, err)
		}
		return nil
	})
}
func (s *Service) fenceProjectionLocked(j bstate.Journal, f *projectionFlight, id api.ID, cause error) error {
	f.fence()
	var p bstate.Projection
	if err := j.Read("projection", id, &p); err != nil {
		if hasCode(err, api.CodeNotFound) {
			return cause
		}
		return err
	}
	p.Fenced = true
	if err := j.Write("projection", id, p); err != nil {
		return err
	}
	return cause
}

func readProjectionFence(j bstate.Journal, id api.ID, expected bstate.Projection) error {
	var read bstate.Projection
	if err := j.Read("projection", id, &read); err != nil {
		return err
	}
	if !read.Fenced || !reflect.DeepEqual(read, expected) {
		return wire.Error(api.CodeIntegrity, "credential private withdrawal fence was not durably read back")
	}
	return nil
}
func (s *Service) projectionClaim(ctx context.Context, r api.CredentialProjectionRequest) error {
	if err := wire.Context(ctx); err != nil {
		return err
	}
	if err := s.projectionPolicy(ctx, r); err != nil {
		return err
	}
	claim, err := s.deps.Store.Effect(ctx, s.deps.ServiceScope, r.Cause.EffectID)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(claim, r.Claim.Record) || !api.EffectLeaseClaimed(r.Claim) || !future(claim.ClaimExpiresAt, s.deps.Clock.Now()) {
		return wire.Error(api.CodeConflict, "credential projection lost its current prepare claim")
	}
	return nil
}

func bindProjectionSlot(slot *bstate.Slot, a api.CredentialProjectionAuthority) {
	slot.ProjectionID = a.ID
	if slot.Kind == "worker" {
		slot.Handoff = &a.Request.Handoff
		slot.LaunchID = a.Request.Handoff.Spec.LaunchID
		slot.HelperLeaseID = a.Request.Lease.ID
		slot.Backend = a.Request.Handoff.Spec.Backend
	}
}

// A normal release retires a lane copy without clearing canonical reuse gates.
func projectionHasRetirableCopy(j bstate.Journal, a api.CredentialProjectionAuthority, normal bool) (bool, error) {
	for _, id := range a.Request.Handoff.Spec.Injection.SlotIDs {
		var slot bstate.Slot
		if err := j.Read("slot", id, &slot); err != nil {
			return false, err
		}
		clear(slot.Material)
		clear(slot.Returned)
		if slot.Credential.Mode == "codex-file" || normal && slot.Credential.Mode == "claude-api-key" {
			return true, nil
		}
	}
	return false, nil
}

func (s *Service) quarantineProjection(j bstate.Journal, a api.CredentialProjectionAuthority) error {
	for _, id := range a.Request.Handoff.Spec.Injection.SlotIDs {
		var slot bstate.Slot
		if err := j.Read("slot", id, &slot); err != nil {
			return err
		}
		clear(slot.Material)
		clear(slot.Returned)
		if slot.Credential.Mode == "codex-file" {
			var owner bstate.Login
			if err := j.Read("login", slot.LoginID, &owner); err != nil {
				return err
			}
			owner.Quarantined = true
			err := j.Write("login", owner.ID, owner)
			clear(owner.Material)
			if err != nil {
				return err
			}
			var read bstate.Login
			if err := j.Read("login", owner.ID, &read); err != nil {
				clear(read.Material)
				return err
			}
			clear(read.Material)
			if !read.Quarantined || read.SlotID != owner.SlotID || read.ProjectionID != owner.ProjectionID {
				return wire.Error(api.CodeIntegrity, "credential quarantine was not durably read back")
			}
		}
	}
	return nil
}
func (s *Service) completeWithdrawal(ctx context.Context, record api.CredentialProjectionRecord, actual api.CredentialWithdrawalReceipt) (api.CredentialProjectionRecord, error) {
	completed, err := s.deps.Store.CompleteCredentialWithdrawal(ctx, s.deps.ServiceScope, actual)
	if err != nil {
		return record, err
	}
	read, err := s.projectionRecord(ctx, record.Authority)
	if err != nil {
		return record, err
	}
	if read.State != "withdrawn" || read.Generation != actual.Generation || read.Withdrawal == nil || !reflect.DeepEqual(*read.Withdrawal, actual) || !reflect.DeepEqual(read, completed) {
		return record, wire.Error(api.CodeIntegrity, "credential withdrawal completion was not durably read back")
	}
	return read, nil
}
func (s *Service) acknowledgeTransfer(ctx context.Context, j bstate.Journal, f *projectionFlight, receipt api.CredentialProjectionReceipt) (api.CredentialProjectionRecord, error) {
	if err := validateTransferReceiptID(f.transfer, receipt); err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	return s.acknowledgeLocked(ctx, j, f, receipt)
}

func validateTransferReceiptID(transfer api.CredentialTransfer, receipt api.CredentialProjectionReceipt) error {
	if receipt.ProjectionID != transfer.Authority.ID {
		return wire.Error(api.CodeForbidden, "credential acknowledgement names another transfer")
	}
	return nil
}
func (s *Service) deliveryPolicy(ctx context.Context, j bstate.Journal, slot bstate.Slot) error {
	policy, err := s.deps.Store.CurrentApprovedPolicy(ctx, s.deps.ServiceScope)
	if err != nil {
		return err
	}
	if slot.PolicyGeneration != policy.Generation || !wire.Digest(policy.SHA256) {
		return wire.Error(api.CodeConflict, "credential delivery policy changed")
	}
	if slot.ProfileID != "" && slices.Contains(policy.ProfileExclusions, slot.ProfileID) {
		return wire.Error(api.CodeForbidden, "credential delivery selects an excluded profile")
	}
	if slot.Kind == "profile" {
		if slices.Contains(policy.ProfileExclusions, slot.ProfileID) || !future(slot.Credential.ExpiresAt, s.deps.Clock.Now()) {
			return wire.Error(api.CodeForbidden, "credential delivery profile is excluded or expired")
		}
		var profile bstate.Profile
		if err := j.Read("profile", slot.ProfileID, &profile); err != nil {
			return err
		}
		if profile.Generation != slot.ProfileGeneration || !future(profile.ExpiresAt, s.deps.Clock.Now()) {
			return wire.Error(api.CodeForbidden, "credential delivery profile enrollment expired or changed")
		}
		if profile.Mode == "file_login" || profile.Mode == "codex-file" {
			var owner bstate.Login
			if err := j.Read("login", slot.LoginID, &owner); err != nil {
				return err
			}
			clear(owner.Material)
			if owner.Quarantined || owner.PendingRelease != "" || owner.SlotID != slot.ID {
				return wire.Error(api.CodeForbidden, "credential delivery canonical owner is quarantined or collecting")
			}
		}
	}
	return nil
}
