package store

import (
	"context"
	"database/sql"
	"reflect"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/approval"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// Validate under the writer lock before any projection/guard is changed. Only
// these exact joined public operations may acquire service event provenance.
func (s *Service) validateChangeTransaction(ctx context.Context, db queryer, input api.Transaction) error {
	method := input.Scope.Request.Method
	if input.Internal != nil || method != "org.change.propose" && method != "org.change.approve" {
		return nil
	}
	if input.Reply != nil && input.Reply.Error != nil {
		return nil // Shape validation permits only an empty preflight failure.
	}
	if len(input.Events) != 1 || input.Events[0].Kind != api.EventKind(string(method)+"d") {
		// propose -> proposed, approve -> approved.
		return fault(api.CodeForbidden, "org change requires its one exact transactional event")
	}
	event := input.Events[0]
	var value api.ChangeEvent
	if err := wire.Decode(event.Payload, &value); err != nil {
		return err
	}
	change := value.Change
	if err := approval.ValidateChange(change); err != nil {
		return err
	}
	if change.Config != s.deps.Config || change.OrgID != api.ID(s.deps.Config) || event.Origin != "service" ||
		event.Actor != input.Scope.Actor || event.RequestedBy != input.Scope.Actor || value.Receipt != nil {
		return fault(api.CodeForbidden, "org change event differs from its authenticated configuration or requester")
	}
	if !hasCompare(input, api.CompareOrg, change.OrgID, change.BaseGeneration) {
		return fault(api.CodeForbidden, "org change omitted its exact base generation comparison")
	}
	var snapshot api.OrgSnapshot
	if err := storedProjection(ctx, db, "org", change.OrgID, &snapshot); err != nil {
		return err
	}
	if snapshot.Config != change.Config || snapshot.Ref != change.SourceSnapshot || snapshot.Renderer != change.Renderer ||
		snapshot.OwnershipManifest != change.OwnershipManifest || snapshot.Sources == nil || snapshot.Derived == nil {
		return fault(api.CodeConflict, "org change source snapshot, ownership or renderer differs from the approved base")
	}
	if err := s.changeObjects(ctx, db, change); err != nil {
		return err
	}
	if method == "org.change.propose" {
		if input.Scope.Actor.Kind != "lane" || input.Scope.Actor.Level != 6 || input.Scope.Actor != change.Requester || change.Status != "proposed" ||
			len(input.Writes.Changes) != 1 || !sameValue(input.Writes.Changes[0], change) || value.Approval != nil ||
			!hasCompare(input, api.CompareChange, change.ID, 0) {
			return fault(api.CodeForbidden, "proposal lacks its current L6, absent change comparison or exact source write")
		}
		var launch api.LaunchRecord
		if err := storedProjection(ctx, db, "launch", input.Scope.LaunchID, &launch); err != nil {
			return err
		}
		if launch.Revoked || launch.Config != change.Config || launch.Actor != change.Requester || launch.ID != input.Scope.LaunchID ||
			launch.EndpointGeneration != input.Scope.EndpointGeneration || event.LifeID != launch.Target.LifeID || event.Run != launch.Target.Run ||
			event.ParentLifeID != launch.ParentLifeID || event.RootLifeID != launch.RootLifeID ||
			event.StarterEventSeq != launch.StarterEventSeq || !reflect.DeepEqual(event.StarterChain, launch.StarterChain) {
			return fault(api.CodeForbidden, "proposal event does not join its current authenticated L6 launch")
		}
		var request api.ChangeProposeRequest
		if err := wire.Decode(input.Scope.Request.Params, &request); err != nil {
			return err
		}
		if err := approval.ValidateProposeResult(request, change); err != nil {
			return err
		}
		return changeDeltas(snapshot, change)
	}
	if input.Scope.Actor.Kind != "human" || value.Approval == nil || len(input.Writes.Approvals) != 1 ||
		!sameValue(input.Writes.Approvals[0], *value.Approval) || !hasCompare(input, api.CompareApproval, value.Approval.ID, 0) ||
		event.LifeID != "" || event.Run != 0 {
		return fault(api.CodeForbidden, "approval event lacks its exact human receipt and absent approval comparison")
	}
	var retained api.ChangeRequest
	if err := storedProjection(ctx, db, "change", change.ID, &retained); err != nil {
		return err
	}
	if !sameValue(retained, change) {
		return fault(api.CodeConflict, "approval event changed the retained proposal")
	}
	if err := approval.ValidateApprovalBinding(s.deps.Clock.Now(), change, *value.Approval); err != nil {
		return err
	}
	var request api.ChangeApproveRequest
	if err := wire.Decode(input.Scope.Request.Params, &request); err != nil {
		return err
	}
	if err := approval.ValidateApproveResult(request, *value.Approval); err != nil {
		return err
	}
	if input.Scope.Request.Proof == nil || len(input.Guards) != 1 || input.Guards[0].Proof == nil {
		return fault(api.CodeForbidden, "approval requires the exact consumed human proof")
	}
	var facts api.VerifiedHumanProof
	if err := storedProjection(ctx, db, "proof", input.Scope.Request.Proof.ID, &facts); err != nil {
		return err
	}
	want := *value.Approval
	if want.ApproverKeyID != facts.CredentialID || want.NonceID != facts.NonceID || want.SimulatedPresence != facts.SimulatedPresence ||
		facts.Ref != *input.Scope.Request.Proof || facts.SimulatedPresence != facts.Ref.SimulatedPresence {
		return fault(api.CodeForbidden, "approval changed verified key, nonce or presence provenance")
	}
	return nil
}

func hasCompare(input api.Transaction, kind api.CompareKind, id api.ID, generation api.Generation) bool {
	for _, compare := range input.Compare {
		if compare.Kind == kind && compare.ID == id && compare.Generation == generation {
			return true
		}
	}
	return false
}

func (s *Service) changeObjects(ctx context.Context, db queryer, change api.ChangeRequest) error {
	refs := []api.BlobRef{change.Reason, change.Diff, change.OwnershipManifest}
	for _, group := range [][]api.ResourceDelta{change.Files, change.Derived} {
		for _, file := range group {
			if file.After != nil {
				refs = append(refs, *file.After)
			}
		}
	}
	for _, ref := range refs {
		metadata, _, err := objectRow(ctx, db, ref.ID)
		if err != nil {
			return err
		}
		if metadata.Ref != ref || metadata.ACL.Config != change.Config {
			return fault(api.CodeIntegrity, "org change object differs from its actual committed bytes or configuration")
		}
	}
	return nil
}

func changeDeltas(snapshot api.OrgSnapshot, change api.ChangeRequest) error {
	owned := [2]map[string]api.ResourceFile{{}, {}}
	final := map[string]bool{}
	for group, files := range [][]api.ResourceFile{snapshot.Sources, snapshot.Derived} {
		for _, file := range files {
			owned[group][file.Source.Path] = file
			final[file.Source.Path] = true
		}
	}
	for group, files := range [][]api.ResourceDelta{change.Files, change.Derived} {
		for _, file := range files {
			if _, foreign := owned[1-group][file.Path]; foreign {
				return fault(api.CodeForbidden, "org delta crosses source/generated ownership")
			}
			before, exists := owned[group][file.Path]
			if file.Action == "add" && exists || file.Action != "add" && (!exists || before.Content.SHA256 != file.BeforeSHA256 || file.Action == "delete" && file.Mode != before.Mode) {
				return fault(api.CodeConflict, "org delta differs from its approved preimage or deletion mode")
			}
			if file.Action == "delete" {
				delete(final, file.Path)
			} else {
				final[file.Path] = true
			}
		}
	}
	for path := range final {
		for parent := path; strings.Contains(parent, "/"); {
			parent = parent[:strings.LastIndexByte(parent, '/')]
			if final[parent] {
				return fault(api.CodeConflict, "org delta creates an overlapping file and directory")
			}
		}
	}
	return nil
}

// Projection runs after typed writes in the same SQLite transaction. It checks
// the event/write join instead of independently advancing another generation.
func (s *Service) projectChange(ctx context.Context, tx *sql.Tx, event api.Event) error {
	var value api.ChangeEvent
	if err := wire.Decode(event.Payload, &value); err != nil {
		return err
	}
	if event.Origin != "service" || event.Actor.Kind != "service" || value.Change.Config != s.deps.Config {
		return fault(api.CodeForbidden, "org event lacks service-owned transactional provenance")
	}
	var change api.ChangeRequest
	if err := storedProjection(ctx, tx, "change", value.Change.ID, &change); err != nil {
		return err
	}
	if !sameValue(change, value.Change) {
		return fault(api.CodeConflict, "org event differs from its exact retained change")
	}
	if event.Kind == "org.change.proposed" {
		if value.Approval != nil || value.Receipt != nil || change.Status != "proposed" {
			return fault(api.CodeForbidden, "proposal event contains uncommitted approval or publication")
		}
		return nil
	}
	if value.Approval == nil {
		return fault(api.CodeForbidden, "org event omitted its retained approval")
	}
	var approved api.ChangeApproval
	if err := storedProjection(ctx, tx, "approval", value.Approval.ID, &approved); err != nil {
		return err
	}
	if approved != *value.Approval || approved.ChangeID != change.ID || approved.ManifestSHA256 != change.ManifestSHA256 || approved.BaseGeneration != change.BaseGeneration {
		return fault(api.CodeConflict, "org event changed its retained approval binding")
	}
	if event.Kind == "org.change.approved" {
		if value.Receipt != nil {
			return fault(api.CodeForbidden, "approval event cannot claim publication")
		}
		return nil
	}
	bound, ok := ctx.Value(orgPublicationCommitKey{}).(orgPublicationCommit)
	if event.Kind != "org.change.applied" || !ok || bound.Store != s || value.Receipt == nil || *value.Receipt != bound.Marker.Receipt ||
		event.OperationID != bound.Job.Deferred.OperationID || event.RequestID != bound.Job.Effect.Context.CauseRequestID ||
		change.Status != "applied" || approved != bound.Job.Approval {
		return fault(api.CodeForbidden, "org publication requires its claimed durable filesystem completion")
	}
	var snapshot api.OrgSnapshot
	if err := storedProjection(ctx, tx, "org", change.OrgID, &snapshot); err != nil {
		return err
	}
	if !sameValue(snapshot, bound.Marker.Snapshot) {
		return fault(api.CodeIntegrity, "published org snapshot differs from the measured generation")
	}
	return nil
}
