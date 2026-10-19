package migration

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"laneboss.io/laneboss/internal/v2/api"
)

type ReadBackReport struct {
	Verified          bool `json:"verified"`
	EventsMatched     int  `json:"events_matched"`
	DecisionsMatched  int  `json:"decisions_matched"`
	VectorsMatched    int  `json:"vectors_matched"`
	EgressMatched     int  `json:"egress_matched"`
	MailDelivered     int  `json:"mail_delivered"`
	MailPending       int  `json:"mail_pending"`
	MailReturned      int  `json:"mail_returned"`
	ArchivesMatched   int  `json:"archives_matched"`
	OwnerQueueMatched int  `json:"owner_queue_matched"`
}

// VerifyMigratedState checks actual scoped records AND their retained bytes.
// Queries use exact IDs and bounded pages, including on a nonempty live store.
func (s *Service) VerifyMigratedState(ctx context.Context, scope api.Scope, planID api.ID) (result *ReadBackReport, resultErr error) {
	return s.verifyMigratedState(ctx, scope, planID, false)
}

func (s *Service) verifyMigratedState(ctx context.Context, scope api.Scope, planID api.ID, staging bool) (result *ReadBackReport, resultErr error) {
	if err := validateScopeForPlan(scope); err != nil {
		return nil, err
	}
	state, exists := s.lookupPlan(planID)
	if !exists || state.config != scope.Config || state.bundle == nil {
		return nil, &api.Error{Code: api.CodeNotFound, Message: "migration plan is not available in this configuration", Instead: "Open the retained migration plan first.", Owner: "lb-v2-migration"}
	}
	readScope := scope
	readScope.ReadView = nil
	view, err := s.deps.Store.BeginRead(ctx, readScope)
	if err != nil {
		return nil, err
	}
	if view == nil {
		return nil, integrityErr("migration read-back omitted its pinned store snapshot")
	}
	defer func() {
		if err := view.Close(); err != nil {
			result, resultErr = nil, errors.Join(resultErr, err)
		}
	}()
	if view.Snapshot().Config != scope.Config {
		return nil, integrityErr("migration read-back snapshot belongs to another configuration")
	}
	scope.ReadView = view
	bundle := state.bundle
	deployment, err := s.deps.Store.Deployment(ctx, scope, planID)
	if err != nil {
		return nil, err
	}
	if deployment.Config != scope.Config || deployment.MigrationPlanID != planID || deployment.OperationID == "" {
		return nil, integrityErr("migration read-back has no correlated deployment")
	}
	if deployment.Phase != "complete" && !(staging && deployment.Phase == "activating") {
		return nil, conflictErr("migration.phase is not complete")
	}
	verification, err := s.deps.Store.Verify(ctx, api.VerifyRequest{Scope: "migration", ObjectID: planID})
	if err != nil {
		return nil, err
	}
	if !verification.OK {
		return nil, integrityErr("post-migration store verification failed")
	}
	foundCompletion, cursor := false, ""
	seenCursors := map[string]bool{"": true}
	for {
		page, err := s.deps.Store.Events(ctx, scope, api.EventTailRequest{Cursor: cursor})
		if err != nil {
			return nil, err
		}
		for _, event := range page.Events {
			if event.OperationID != deployment.OperationID {
				continue
			}
			if event.Kind == "identity.bound" || event.Kind == "decision.changed" || event.Kind == "mail.queued" || event.Kind == "mail.delivered" || event.Kind == "archive.verified" || event.ParentLifeID != "" || len(event.StarterChain) != 0 {
				return nil, integrityErr("migration read-back found imported active authority or a label-derived parent")
			}
			if event.Kind == "migration.completed" {
				var completed api.MigrationEvent
				if err := api.DecodeObject(event.Payload, &completed); err != nil || event.Origin != "service" ||
					completed.Plan.ID != planID || completed.Manifest != state.plan.SourceManifest || completed.LegacyEventCount != uint64(len(bundle.Events)) {
					return nil, integrityErr("migration read-back completion belongs to another source or plan")
				}
				foundCompletion = true
			}
		}
		if page.Complete {
			break
		}
		if seenCursors[page.Cursor] {
			return nil, integrityErr("migration read-back event page did not reach a complete advancing cursor")
		}
		seenCursors[page.Cursor] = true
		cursor = page.Cursor
	}
	if deployment.Phase == "activating" && foundCompletion {
		return nil, integrityErr("migration.completed was published before read-back")
	}
	if deployment.Phase == "complete" && !foundCompletion {
		return nil, integrityErr("migration read-back missing migration.completed event")
	}
	lookup := func(id api.ID) (api.Record, bool, error) {
		page, err := s.deps.Store.Records(ctx, scope, api.RecordQuery{RecordID: id, SearchMode: "keyword", Limit: 1})
		if err != nil {
			return api.Record{}, false, err
		}
		if len(page.Records) != 1 || page.Records[0].ID != id || page.Cursor != "" {
			return api.Record{}, false, nil
		}
		return page.Records[0], true, nil
	}
	checkBytes := func(record api.Record, data []byte) error {
		metadata, err := s.deps.Store.ObjectMetadata(ctx, scope, record.Content.ID)
		if err != nil {
			return err
		}
		if metadata.Ref != record.Content || metadata.Origin != "legacy_import" || metadata.ACL.Config != scope.Config || metadata.SourceOperationID != deployment.OperationID {
			return integrityErr("migration read-back object metadata or provenance mismatch")
		}
		actual, err := readBlobFull(ctx, s.deps.Store, scope, record.Content)
		if err != nil {
			return err
		}
		if !bytes.Equal(actual, data) {
			return integrityErr("migration read-back retained bytes differ from the source")
		}
		return nil
	}
	checkRecord := func(id api.ID, collection, action string, data []byte) error {
		record, exists, err := lookup(id)
		if err != nil {
			return err
		}
		if !exists || record.Origin != "legacy_import" || record.Collection != collection || record.Action != action || record.Content.SHA256 != DigestBytes(data) || record.Content.Bytes != int64(len(data)) {
			return integrityErr(fmt.Sprintf("migration read-back record mismatch for %s", id))
		}
		return checkBytes(record, data)
	}
	report := &ReadBackReport{}
	for _, event := range bundle.Events {
		rec, exists, err := lookup(sanitizeRecordID("mig-ev-", event.ID))
		if err != nil {
			return nil, err
		}
		lev := event
		if !exists || rec.Content.SHA256 != api.Digest(lev.SHA256) || rec.Origin != "legacy_import" {
			return nil, integrityErr(fmt.Sprintf("migration read-back mismatch for legacy event seq %d id %s", event.Seq, event.ID))
		}
		if rec.Collection != mapLegacyEventCollection(event) {
			return nil, integrityErr("migration read-back legacy event collection mismatch")
		}
		if err := checkBytes(rec, event.RawCanonical); err != nil {
			return nil, err
		}
		report.EventsMatched++
	}
	for _, decision := range bundle.Decisions {
		id := sanitizeRecordID("mig-dec-", decision.ID)
		if err := checkRecord(id, "decisions", "", decision.RecordJSON); err != nil {
			return nil, err
		}
		// TurnStore.Decision includes superseded history. Legacy claims cannot
		// insert or overwrite any current canonical decision or its history.
		_, err := s.deps.Store.Decision(ctx, scope, id)
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeNotFound {
			if err != nil {
				return nil, err
			}
			return nil, integrityErr("migration read-back found a canonical decision created from legacy authority")
		}
		report.DecisionsMatched++
	}
	for _, vector := range bundle.Vectors {
		if err := checkRecord(DeterministicID("mig-vec-", vector.RecordID, vector.WhichText, vector.Model), "embeddings", "", vector.RawJSON); err != nil {
			return nil, err
		}
		report.VectorsMatched++
	}
	for _, egress := range bundle.Egress {
		if err := checkRecord(DeterministicID("mig-eg-", fmt.Sprint(egress.ID), egress.EntrySHA256), "judge_egress", "", egress.RawJSON); err != nil {
			return nil, err
		}
		report.EgressMatched++
	}
	for _, archive := range bundle.Archives {
		if err := checkRecord(DeterministicID("mig-arc-", archive.Stem), "archives", "", archive.ReceiptBytes); err != nil {
			return nil, err
		}
		report.ArchivesMatched++
	}
	for _, mail := range bundle.Mail {
		if err := checkRecord(DeterministicID("mail-mig-", mail.Lane, fmt.Sprint(mail.Sequence)), "observations", legacyMailStatus(mail), mail.Content); err != nil {
			return nil, err
		}
		if mail.Delivered {
			report.MailDelivered++
		} else if mail.Returned {
			report.MailReturned++
		} else {
			report.MailPending++
		}
	}
	for index, queue := range bundle.OwnerQueue {
		if err := checkRecord(DeterministicID("mig-oq-", fmt.Sprint(index+1)), "reports", "", queue); err != nil {
			return nil, err
		}
		report.OwnerQueueMatched++
	}
	for index, ledger := range bundle.BoxLedger {
		if err := checkRecord(DeterministicID("mig-bl-", fmt.Sprint(index+1)), "ledger", "", ledger); err != nil {
			return nil, err
		}
	}
	inventory, ok := s.deps.Store.(migrationEffectsReader)
	if !ok {
		return nil, api.NotImplemented("lb-v2-service", "migration.effects inventory")
	}
	effects, err := inventory.MigrationEffects(ctx, scope, deployment.OperationID)
	if err != nil {
		return nil, err
	}
	foundMigrationEffect := false
	for _, record := range effects {
		effect := record.Effect
		if effect.OperationID == deployment.OperationID && effect.Deliver != nil {
			return nil, integrityErr("migration read-back found a duplicate mail delivery effect")
		}
		if effect.OperationID == deployment.OperationID && effect.Migration != nil && effect.Migration.PlanID == planID && effect.Context != nil && effect.Context.Config == scope.Config {
			foundMigrationEffect = true
		}
	}
	if !foundMigrationEffect {
		return nil, integrityErr("migration.effects inventory omitted its causal migration")
	}
	report.Verified = deployment.Phase == "complete"
	return report, nil
}
