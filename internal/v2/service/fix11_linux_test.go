//go:build linux

package service

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

type refusingPlanRead struct{ *store.Service }

func (r refusingPlanRead) LaunchPlan(context.Context, api.Scope, api.ID) (api.LaunchPlanRecord, error) {
	return api.LaunchPlanRecord{}, api.NotImplemented("lb-v2-service", "component retained plan read refusal")
}

type foreignPlanRead struct {
	*store.Service
	record api.LaunchPlanRecord
}

func (r foreignPlanRead) LaunchPlan(context.Context, api.Scope, api.ID) (api.LaunchPlanRecord, error) {
	return r.record, nil
}

type staleDispatchPlanRead struct {
	*store.Service
	snapshot api.EffectRecord
}

func (r staleDispatchPlanRead) DispatchEffects(context.Context) ([]api.EffectRecord, error) {
	return []api.EffectRecord{r.snapshot}, nil
}

func TestPrivatePlanRead(t *testing.T) {
	f := fx.New(t)
	f.Reserve(t)
	f.Source(t)
	f.BuildPlan(t, true)
	f.Spec(t)
	s := launchServer(t, f)
	ctx := context.Background()
	t.Run("exact_record", func(t *testing.T) {
		actual, err := s.Plan(ctx, f.Reservation.ID)
		if err != nil || !reflect.DeepEqual(actual, f.Record) {
			t.Fatal("private plan source did not load the retained record", err)
		}
	})
	t.Run("store_refusal", func(t *testing.T) {
		s.deps.Store = refusingPlanRead{f.State}
		defer func() { s.deps.Store = f.State }()
		_, err := s.Plan(ctx, f.Reservation.ID)
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Message != "component retained plan read refusal is not implemented" {
			t.Fatal("private plan source hid the actual store failure", err)
		}
	})
	t.Run("foreign_result", func(t *testing.T) {
		other := fx.New(t)
		other.Reserve(t)
		other.Source(t)
		other.BuildPlan(t, true)
		other.Spec(t)
		s.deps.Store = foreignPlanRead{f.State, other.Record}
		defer func() { s.deps.Store = f.State }()
		if _, err := s.Plan(ctx, f.Reservation.ID); err == nil {
			t.Fatal("private plan source accepted a different retained reservation")
		}
	})
	t.Run("foreign_selector", func(t *testing.T) {
		if _, err := s.Plan(ctx, fx.ID(t)); err == nil {
			t.Fatal("private plan read accepted a foreign reservation selector")
		}
	})
	t.Run("expired_claim", func(t *testing.T) {
		f.ExpireClaim(t)
		s.deps.Store = staleDispatchPlanRead{f.State, f.Claim.Record}
		if _, err := s.Plan(ctx, f.Reservation.ID); err == nil {
			t.Fatal("private plan read accepted an expired durable claim")
		}
	})
}

func TestAdministratorEntryRefusesPublic(t *testing.T) {
	s := fixtureServer(t)
	for _, action := range []string{"begin", "complete"} {
		t.Run(action, func(t *testing.T) {
			var err error
			if action == "begin" {
				_, err = s.BeginHumanEnrollment(context.Background(), api.EnrollmentCeremonyRequest{Config: s.options.Config, CeremonyID: fixtureID(t), PrincipalID: fixtureID(t)})
			} else {
				_, err = s.CompleteHumanEnrollment(context.Background(), api.EnrollmentValidationRequest{})
			}
			if err == nil {
				t.Fatal("administrator entry accepted public " + action)
			}
			codeIs(t, err, api.CodeForbidden)
		})
	}
}
