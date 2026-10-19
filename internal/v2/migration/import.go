package migration

import (
	"encoding/json"
	"fmt"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// All historical content is inert. In particular, a legacy human label is not
// decision authority, a delivered message is not a new delivery, and an archive
// receipt is not a fresh archive. Exact original files remain in SourceManifest.
func buildImportTransaction(scope api.Scope, plan api.MigrationPlan, bundle *VerifiedBundle, intent api.InternalIntent, deployment api.DeploymentPlan) (api.Transaction, error) {
	now := api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))
	scope.Request = api.Request{}
	scope.ReadView = nil
	tx := api.Transaction{Scope: scope, Internal: &intent,
		Compare: []api.Compare{{Kind: api.CompareUpgrade, ID: deployment.ID, Generation: deployment.Generation}}}
	appendEvent := func(kind api.EventKind, origin string, payload any) error {
		raw, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		tx.Events = append(tx.Events, api.Event{Schema: api.SchemaVersion,
			ID:     DeterministicID("ev-mig-", scope.Config, string(plan.ID), fmt.Sprint(len(tx.Events)), string(kind)),
			Config: scope.Config, Kind: kind, Actor: intent.Actor, RequestedBy: intent.RequestedBy,
			RequestID: intent.CauseRequestID, OperationID: intent.CauseOperationID,
			StarterChain: []api.ID{}, RecordedAt: now, RequestedAt: now, ObservedAt: now, Origin: origin, Payload: raw})
		return nil
	}
	appendRecord := func(id api.ID, collection, action string, data []byte, recordedAt api.Timestamp) error {
		objectID := DeterministicID("blob-mig-", scope.Config, string(plan.ID), string(id))
		write := api.ObjectWrite{ObjectKey: objectID, Class: "record", Bytes: append([]byte(nil), data...), SHA256: DigestBytes(data),
			ACL:    api.ObjectACL{Config: scope.Config, Owner: intent.RequestedBy, Audience: "owner", Participants: []api.ID{}, Generation: 1},
			Origin: "legacy_import", InputRefs: []api.BlobRef{plan.SourceManifest}}
		tx.Writes.Objects = append(tx.Writes.Objects, write)
		tx.Compare = append(tx.Compare, api.Compare{Kind: api.CompareRecord, ID: id, Generation: 0})
		record := api.Record{ID: id, Collection: collection, Action: action,
			Content: api.BlobRef{ID: objectID, SHA256: write.SHA256, Bytes: int64(len(data)), Class: write.Class},
			Actor:   intent.Actor, Origin: "legacy_import", RecordedAt: recordedAt, Generation: 1}
		return appendEvent("record.appended", "legacy_import", record)
	}
	for _, event := range bundle.Events {
		if err := appendRecord(sanitizeRecordID("mig-ev-", event.ID), mapLegacyEventCollection(event), "", event.RawCanonical, now); err != nil {
			return api.Transaction{}, err
		}
		// These mutations deliberately violate the real authority boundary. The
		// focused controls inspect the constructed transaction as well as the
		// store's independent closed-catalog validation.
		if allowLabelParent() {
			if starter, _ := event.Payload["starter"].(string); starter != "" {
				tx.Events[len(tx.Events)-1].ParentLifeID = DeterministicID("label-parent-", starter)
				tx.Events[len(tx.Events)-1].StarterChain = []api.ID{tx.Events[len(tx.Events)-1].ParentLifeID}
			}
		}
		if (event.Kind == "lane.started" || event.Kind == "lane.adopted") && importActiveAuthority() {
			launch := api.LaunchRecord{ID: DeterministicID("forged-launch-", event.Lane), Config: scope.Config,
				Target:     api.LifeRef{LifeID: DeterministicID("forged-life-", event.Lane), Run: 1},
				RootLifeID: DeterministicID("forged-life-", event.Lane), StarterChain: []api.ID{}, Actor: intent.RequestedBy,
				UIDLeaseID: "lease-legacy", HostUID: 1000, ProcessGeneration: "legacy-gen", ContainmentID: "legacy-cgroup",
				GrantSetID: "gset-legacy", GrantsSHA256: plan.SourceManifest.SHA256, EndpointGeneration: 1}
			if err := appendEvent("identity.bound", "service", launch); err != nil {
				return api.Transaction{}, err
			}
		}
	}
	for _, decision := range bundle.Decisions {
		// Authoritative in the legacy format describes history only. A new
		// human/D6 decision commit is required to create a DecisionProjection.
		if err := appendRecord(sanitizeRecordID("mig-dec-", decision.ID), "decisions", "", decision.RecordJSON, now); err != nil {
			return api.Transaction{}, err
		}
	}
	for _, vector := range bundle.Vectors {
		id := DeterministicID("mig-vec-", vector.RecordID, vector.WhichText, vector.Model)
		if err := appendRecord(id, "embeddings", "", vector.RawJSON, now); err != nil {
			return api.Transaction{}, err
		}
	}
	for _, egress := range bundle.Egress {
		id := DeterministicID("mig-eg-", fmt.Sprint(egress.ID), egress.EntrySHA256)
		if err := appendRecord(id, "judge_egress", "", egress.RawJSON, now); err != nil {
			return api.Transaction{}, err
		}
	}
	for _, archive := range bundle.Archives {
		if err := appendRecord(DeterministicID("mig-arc-", archive.Stem), "archives", "", archive.ReceiptBytes, now); err != nil {
			return api.Transaction{}, err
		}
	}
	for _, mail := range bundle.Mail {
		id := DeterministicID("mail-mig-", mail.Lane, fmt.Sprint(mail.Sequence))
		if err := appendRecord(id, "observations", legacyMailStatus(mail), mail.Content, now); err != nil {
			return api.Transaction{}, err
		}
		if mail.Delivered && resendDeliveredMail() {
			copy := api.Mail{ID: id, Generation: 1, Artifacts: []api.BlobRef{}, Status: "delivered",
				Content: api.BlobRef{ID: tx.Writes.Objects[len(tx.Writes.Objects)-1].ObjectKey, SHA256: api.Digest(mail.SHA256), Bytes: mail.Bytes, Class: "record"}}
			effectID := DeterministicID("eff-dup-mail-", string(id))
			cause := intent
			cause.Kind, cause.EffectID = api.InternalMailDeliver, effectID
			tx.Effects = append(tx.Effects, api.Effect{ID: effectID, OperationID: intent.CauseOperationID, Context: &cause, Deliver: &copy})
		}
	}
	for index, queue := range bundle.OwnerQueue {
		if err := appendRecord(DeterministicID("mig-oq-", fmt.Sprint(index+1)), "reports", "", queue, now); err != nil {
			return api.Transaction{}, err
		}
	}
	for index, ledger := range bundle.BoxLedger {
		if err := appendRecord(DeterministicID("mig-bl-", fmt.Sprint(index+1)), "ledger", "", ledger, now); err != nil {
			return api.Transaction{}, err
		}
	}
	deployment.Generation++
	deployment.Phase = "activating"
	tx.Writes.Deployments = []api.DeploymentPlan{deployment}
	return tx, nil
}

func legacyMailStatus(mail LegacyMailItem) string {
	if mail.Delivered {
		return "delivered"
	}
	if mail.Returned {
		return "returned"
	}
	return "queued"
}
