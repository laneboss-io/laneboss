package service

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

func retainedMaterialization(ctx context.Context, state api.StateStore, scope api.Scope, effect api.Effect) (bool, error) {
	if effect.Worker == nil || effect.Worker.Kind != "materialize" {
		return false, nil
	}
	owner, ok := state.(interface {
		MaterializationOwnsEffect(context.Context, api.Scope, api.Effect) (bool, error)
	})
	if !ok {
		return false, nil
	}
	return owner.MaterializationOwnsEffect(ctx, scope, effect)
}

// This refusal is produced by supportsEffect before any worker execution.
// It is a known unsupported request, so retain its typed failure per effect.
// Joined errors and execution/storage uncertainty keep their fatal semantics.
func unsupportedWorker(effect api.Effect, err error) *api.Error {
	if effect.Worker == nil || effect.Worker.Kind == "archive" {
		return nil
	}
	typed, ok := err.(*api.Error)
	if !ok || typed == nil || typed.Code != api.CodeNotImplemented || typed.Owner != "lb-v2-service" || typed.Retryable {
		return nil
	}
	return typed
}
