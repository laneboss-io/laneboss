package codex

import (
	"context"
	"errors"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestPlanningAuthor(t *testing.T) {
	for _, name := range []string{"retained", "kind", "id", "changed", "claimant"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			lease := fixtureCopy(f.service.deps.Planning.Lease)
			current := fixtureCopy(lease.Record)
			f.service.deps.ReadScope.Actor.ID = "fresh_attempt"
			current.ClaimantID = f.service.deps.ReadScope.Actor.ID
			code := api.CodeIntegrity
			switch name {
			case "kind":
				current.Effect.Context.Actor.Kind = "human"
			case "id":
				current.Effect.Context.Actor.ID = ""
			case "claimant":
				current.ClaimantID = "foreign_attempt"
				code = api.CodeConflict
			}
			lease.Record = fixtureCopy(current)
			if name == "changed" {
				current.Effect.Context.Actor.ID = "changed_author"
				code = api.CodeConflict
			}
			f.store.effects[current.Effect.ID] = current
			f.service.deps.Planning.Lease = lease
			plan, err := f.service.Start(context.Background(), f.request)
			if name == "retained" {
				if err != nil || plan.Driver != api.DriverCodex || current.Effect.Context.Actor == f.service.deps.ReadScope.Actor {
					t.Fatal("acceptance: fresh planning claimant lost the retained service author", err)
				}
				return
			}
			if name == "kind" || name == "id" {
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != api.CodeIntegrity || typed.Message != "Codex planning effect is not the reserved launch operation" {
					t.Fatal("acceptance: invalid planning author escaped its deciding guard", err)
				}
				return
			}
			wantCode(t, err, code)
		})
	}
}
