package lifecycle

import "laneboss.io/laneboss/internal/v2/api"

// A terminal record retains the claim that produced its outcome. These rules
// apply equally to service reads and the fixture writer's real transitions.
func effectRecord(record api.EffectRecord) error {
	if !validID(record.Effect.ID) || !validGeneration(record.Generation) {
		return integrity("effect has no valid identity or revision")
	}
	switch record.State {
	case api.EffectPending:
		if record.ClaimID == "" && record.ClaimantID == "" && record.ClaimExpiresAt == "" && record.Outcome == nil {
			return nil
		}
	case api.EffectClaimed:
		if record.Generation >= 2 && validID(record.ClaimID) && validID(record.ClaimantID) && validTime(record.ClaimExpiresAt) && record.Outcome == nil {
			return nil
		}
	case api.EffectCompleted, api.EffectFailed:
		outcome := record.Outcome
		if validID(record.ClaimID) && validID(record.ClaimantID) && validTime(record.ClaimExpiresAt) && outcome != nil &&
			outcome.EffectID == record.Effect.ID && outcome.ClaimID == record.ClaimID &&
			validGeneration(outcome.ExpectedGeneration) && outcome.ExpectedGeneration >= 2 && record.Generation > outcome.ExpectedGeneration &&
			(record.State == api.EffectCompleted && outcome.Status == "succeeded" && outcome.Error == nil ||
				record.State == api.EffectFailed && outcome.Status == "failed" && outcome.Error != nil) {
			return nil
		}
	}
	return integrity("effect state has no valid claim and outcome provenance")
}

func effectCompletion(record api.EffectRecord, lease api.EffectLease) error {
	if effectRecord(lease.Record) != nil || !api.EffectLeaseClaimed(lease) || !validID(lease.ClaimID) ||
		lease.Record.ClaimID != lease.ClaimID || lease.Record.ClaimExpiresAt != lease.ExpiresAt ||
		effectRecord(record) != nil || record.Outcome == nil || record.ClaimID != lease.ClaimID ||
		record.ClaimantID != lease.Record.ClaimantID || record.ClaimExpiresAt != lease.ExpiresAt ||
		record.Outcome.ExpectedGeneration != lease.Record.Generation {
		return integrity("effect completion lost its original claimed lease")
	}
	return nil
}
