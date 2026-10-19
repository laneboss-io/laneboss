package store

import (
	"encoding/json"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// Outcome status describes the measured action; state describes its outbox
// lifecycle. A successful outcome completes the effect, never a new state name.
func terminalEffectState(outcome api.EffectOutcome) api.EffectState {
	switch outcome.Status {
	case "succeeded":
		return api.EffectCompleted
	case "failed":
		return api.EffectFailed
	default:
		return ""
	}
}

func encodeEffectState(record api.EffectRecord) ([]byte, error) {
	if err := validateEffectState(record); err != nil {
		return nil, err
	}
	return json.Marshal(record)
}

func validateEffectState(record api.EffectRecord) error {
	if !api.ValidEffectState(record.State) || record.Generation == 0 {
		return fault(api.CodeIntegrity, "effect has an unknown persisted state")
	}
	if record.Outcome != nil {
		if record.Outcome.ExpectedGeneration < 2 || record.State != terminalEffectState(*record.Outcome) || record.Outcome.EffectID != record.Effect.ID ||
			record.Outcome.ClaimID != record.ClaimID || record.Generation != record.Outcome.ExpectedGeneration+1 || record.LastSeq == 0 {
			return fault(api.CodeIntegrity, "terminal effect differs from its measured outcome")
		}
	} else if record.State == api.EffectPending {
		if record.Generation != 1 || record.ClaimID != "" || record.ClaimantID != "" || record.ClaimExpiresAt != "" {
			return fault(api.CodeIntegrity, "unclaimed effect has claim metadata")
		}
		return nil
	} else if record.State != api.EffectClaimed || record.Generation < 2 {
		return fault(api.CodeIntegrity, "unfinished effect is not pending or claimed")
	}
	if !wire.ValidID(string(record.ClaimID)) || !wire.ValidID(string(record.ClaimantID)) {
		return fault(api.CodeIntegrity, "effect has no authentic claim identity")
	}
	if _, err := time.Parse(time.RFC3339Nano, string(record.ClaimExpiresAt)); err != nil {
		return fault(api.CodeIntegrity, "effect has no claim deadline")
	}
	return nil
}
