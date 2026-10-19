package store

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

type approvalConsumption struct {
	Approval    api.ChangeApproval
	OperationID api.ID
}

func (s *Service) validatePublishedPolicy(ctx context.Context, db queryer, input api.Transaction) error {
	p := input.Writes.Policy
	if p == nil || !p.AllowCaptureRefusal {
		return nil
	}
	if input.Internal == nil || input.Internal.Kind != api.InternalOrgPublish {
		return fault(api.CodeForbidden, "capture refusal policy requires actual D6 publication")
	}
	var used approvalConsumption
	if err := storedProjection(ctx, db, "approval_use", p.CaptureRefusalApprovalID, &used); err != nil {
		return err
	}
	operation := input.Internal.CauseOperationID
	if operation == "" {
		operation = input.Internal.ID
	}
	if used.OperationID != operation {
		return fault(api.CodeForbidden, "capture policy approval was consumed by another operation")
	}
	matched := false
	for _, application := range input.Writes.Applications {
		matched = matched || application.ApprovalID == used.Approval.ID && application.ChangeID == used.Approval.ChangeID && application.NewGeneration == p.Generation && application.ManifestSHA256 == used.Approval.ManifestSHA256
	}
	if !matched {
		return fault(api.CodeForbidden, "capture refusal policy lacks its same-transaction approved application")
	}
	return nil
}

func (s *Service) approvedCapturePolicy(ctx context.Context, db queryer, policy api.EffectivePolicy) error {
	var used approvalConsumption
	if err := storedProjection(ctx, db, "approval_use", policy.CaptureRefusalApprovalID, &used); err != nil {
		return err
	}
	var receipt api.ChangeReceipt
	if err := storedProjection(ctx, db, "application", used.Approval.ChangeID, &receipt); err != nil {
		return err
	}
	if !policy.AllowCaptureRefusal || receipt.ApprovalID != used.Approval.ID || receipt.ChangeID != used.Approval.ChangeID || receipt.ManifestSHA256 != used.Approval.ManifestSHA256 || receipt.NewGeneration != policy.Generation {
		return fault(api.CodeForbidden, "capture policy lacks its actual consumed D6 publication receipt")
	}
	return s.capturePublication(ctx, db, used, receipt)
}

func (s *Service) capturePublication(ctx context.Context, db queryer, used approvalConsumption, receipt api.ChangeReceipt) error {
	event, err := authorityEvent(ctx, db, used.OperationID, "org.change.applied", receipt.ID)
	if err != nil {
		return err
	}
	var publication api.ChangeEvent
	if err := wire.Decode(event.Payload, &publication); err != nil {
		return err
	}
	if event.Config != s.deps.Config || event.Actor.Kind != "service" || event.Origin != "service" || publication.Receipt == nil || !sameValue(*publication.Receipt, receipt) ||
		publication.Change.Config != s.deps.Config || publication.Change.ID != receipt.ChangeID || publication.Change.BaseGeneration != receipt.OldGeneration || publication.Change.ManifestSHA256 != receipt.ManifestSHA256 || publication.Change.Status != "applied" {
		return fault(api.CodeForbidden, "capture publication differs from its actual application event")
	}
	if publication.Approval != nil && !sameValue(*publication.Approval, used.Approval) {
		return fault(api.CodeForbidden, "capture publication changed its consumed approval")
	}
	if err := wire.ValidateEvent(event); err != nil {
		return err
	}
	return nil
}

func (s *Service) currentCapturePolicy(ctx context.Context, db queryer, binding api.CaptureBinding) error {
	if binding.Status != "refused" {
		return nil
	}
	var current api.EffectivePolicy
	if err := storedProjection(ctx, db, "policy", api.ID(s.deps.Config), &current); err != nil {
		return err
	}
	if err := api.ValidateCapturePolicy(binding, current); err != nil {
		return err
	}
	return s.approvedCapturePolicy(ctx, db, current)
}
