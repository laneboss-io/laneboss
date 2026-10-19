//go:build linux

package admin

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestRuntimeRegisteredSources(t *testing.T) {
	service, store, _, _ := seedLaunchFiles(t)
	ctx := context.Background()
	expected, err := service.ResolveLaunchSources(ctx, api.LaunchSourceRequest{ReservationID: store.plan.Reservation.ID, GrantSetID: store.grants.ID, Claim: fixtureLaunchClaim(store)})
	if err != nil {
		t.Fatal("planning source control did not reach the retained bytes", err)
	}
	store.plan.Phase, store.plan.Generation = "sourced", 2
	store.plan.Inputs = &api.LaunchInputs{Grants: store.grants, Sources: expected}
	cause := *store.claim.Effect.Context
	cause.Kind = api.InternalHelperRegister
	attempt := api.EffectLease{Record: store.claim, ClaimID: store.claim.ClaimID, ExpiresAt: store.claim.ClaimExpiresAt}
	ctx = api.WithEffectLease(ctx, attempt)
	handoff := api.PreparedSpecHandoff{Cause: cause, Config: service.deps.Config,
		Spec:     api.LaunchSpec{Kind: "agent", PlanID: store.plan.Reservation.ID, Grants: store.grants, Runner: &api.RunnerPlan{}},
		Original: api.BlobRef{ID: "runtime-spec-input", Bytes: 1}}
	for _, row := range []struct {
		name, message string
		call          func(context.Context, api.PreparedSpecHandoff) error
	}{
		{"runtime", "runtime resolution has no exact retained plan and handoff", func(ctx context.Context, handoff api.PreparedSpecHandoff) error {
			_, err := service.ResolveRuntime(ctx, handoff)
			return err
		}},
		{"registration", "agent spec differs from retained plan and handoff", func(ctx context.Context, handoff api.PreparedSpecHandoff) error {
			_, err := service.RegisterSpec(ctx, handoff)
			return err
		}},
	} {
		t.Run(row.name, func(t *testing.T) {
			var typed *api.Error
			if err := row.call(ctx, handoff); !errors.As(err, &typed) || typed.Code != api.CodeIntegrity || typed.Message != row.message {
				t.Fatal("registration did not thread its actual planning attempt to the retained handoff gate", err)
			}
			if err := row.call(context.Background(), handoff); err == nil {
				t.Fatal("registration adopted a live planning claim without an explicit attempt")
			}
			stale := attempt
			stale.ClaimID = "runtime-stale-attempt"
			if err := row.call(api.WithEffectLease(context.Background(), stale), handoff); err == nil {
				t.Fatal("registration adopted the live claim for a stale caller attempt")
			}
		})
	}
	authority, err := service.launchAuthority(ctx, store.plan.Reservation.ID, store.grants.ID, &cause, fixtureLaunchClaim(store))
	if err != nil {
		t.Fatal("runtime registration did not validate its actual current cause", err)
	}
	actual, err := service.runtimeLaunchSources(ctx, authority)
	if err != nil || !reflect.DeepEqual(actual, expected) {
		t.Fatal("registered runtime was incorrectly required to invent a new planning selector", err)
	}
	// This component cannot impersonate the installed service UID. A valid
	// registration must reach that real IPC identity gate, with no new planner.
	service.deps.ServiceUID = service.binding.Service.UID
	check := ""
	ctx = api.WithHelperReasonObserver(ctx, func(_ error, reason string) { check = reason })
	_, err = service.runtimeLaunchStorage(ctx, authority, "runtime-helper-lease")
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeForbidden || check != "call_identity" {
		t.Fatal("registered storage did not reach its original installed service identity gate", err)
	}
	store.cancelled = true
	if _, err := service.runtimeLaunchSources(ctx, authority); err == nil {
		t.Fatal("runtime source reuse lost its current cancellation fence")
	}
	store.cancelled = false
	ref := *service.deps.LaunchEnrollment
	changed := append([]byte{}, store.objects[ref.ID]...)
	changed[0] ^= 1
	store.objects[ref.ID] = changed
	if _, err := service.runtimeLaunchSources(ctx, authority); err == nil {
		t.Fatal("runtime source reuse ignored its retained enrollment bytes")
	}
}
