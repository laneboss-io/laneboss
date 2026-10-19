package cli

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

// runUpgradePlan maps file/flag inputs to api.UpgradePlanRequest, then calls upgrade.plan.
func runUpgradePlan(ctx context.Context, call Invocation) error {
	// TODO(lb-v2-packaging): parse inputs, transfer bounded bytes and use call.Client.
	// The only successful response shape is api.UpgradePlan; never call a legacy handler.
	return api.NotImplemented("lb-v2-packaging", "upgrade.plan")
}

// runUpgradeApply maps file/flag inputs to api.UpgradeApplyRequest, then calls upgrade.apply.
func runUpgradeApply(ctx context.Context, call Invocation) error {
	// TODO(lb-v2-packaging): parse inputs, transfer bounded bytes and use call.Client.
	// The only successful response shape is api.Operation; never call a legacy handler.
	return api.NotImplemented("lb-v2-packaging", "upgrade.apply")
}
