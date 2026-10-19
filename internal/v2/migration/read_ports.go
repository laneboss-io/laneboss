package migration

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

// These optional, service-owned reads add no RPC or authority from a label.
// Implementations must read the bound installation, not caller measurements.
// Missing support refuses; PendingEffects is not an all-state inventory.
type migrationEffectsReader interface {
	MigrationEffects(context.Context, api.Scope, api.ID) ([]api.EffectRecord, error)
}

type rollbackQuiescenceReader interface {
	MigrationQuiescence(context.Context, api.Scope) (api.QuiescenceReceipt, error)
}

func migrationPlanProblems(bundle *VerifiedBundle, store api.StateStore) []string {
	problems := []string{}
	if bundle == nil || !bundle.Verification.OK {
		problems = append(problems, "source.verification is not verified")
	}
	if _, ok := store.(migrationEffectsReader); !ok {
		problems = append(problems, "migration.effects inventory port is unavailable")
	}
	return problems
}
