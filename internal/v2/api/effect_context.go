package api

import "context"

type effectLeaseContextKey struct{}

// planningLeaseContextKey carries the parent PlanLaunch attempt while a
// lifecycle owner drives a separately claimed HelperPrepare child.  The
// helper stage still authenticates its own EffectLeaseFromContext; the parent
// lease is retained only for registration/runtime resolution, which must read
// the original planning reservation rather than a child effect.
type planningLeaseContextKey struct{}
type prepareLeaseContextKey struct{}

// WithEffectLease carries this in-process attempt separately from immutable
// effect inputs. Receivers must compare it with the live durable store record;
// a context value alone grants no execution authority.
func WithEffectLease(ctx context.Context, lease EffectLease) context.Context {
	return context.WithValue(ctx, effectLeaseContextKey{}, lease)
}

func EffectLeaseFromContext(ctx context.Context) (EffectLease, bool) {
	lease, ok := ctx.Value(effectLeaseContextKey{}).(EffectLease)
	return lease, ok
}

func WithPlanningLease(ctx context.Context, lease EffectLease) context.Context {
	return context.WithValue(ctx, planningLeaseContextKey{}, lease)
}

func PlanningLeaseFromContext(ctx context.Context) (EffectLease, bool) {
	lease, ok := ctx.Value(planningLeaseContextKey{}).(EffectLease)
	return lease, ok
}

func WithPrepareLease(ctx context.Context, lease EffectLease) context.Context {
	return context.WithValue(ctx, prepareLeaseContextKey{}, lease)
}

func PrepareLeaseFromContext(ctx context.Context) (EffectLease, bool) {
	lease, ok := ctx.Value(prepareLeaseContextKey{}).(EffectLease)
	return lease, ok
}
