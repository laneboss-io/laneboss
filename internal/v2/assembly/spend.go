package assembly

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

func checkRunnerSpend(ctx context.Context, store api.StateStore, slot api.CredentialSlot) error {
	if slot.Mode != "claude-api-key" {
		return nil
	}
	guard, ok := store.(api.CredentialSpendGuard)
	if !ok {
		return runError(api.CodePrerequisite, "API credential requires its service-owned spend guard and operator tool reading")
	}
	_, err := guard.CheckCredentialSpend(ctx, slot)
	return err
}
