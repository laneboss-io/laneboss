package policy

import (
	"context"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestOrgSnapshotSelectors(t *testing.T) {
	for _, test := range []struct {
		name       string
		generation api.Generation
	}{
		{"initial", 1},
		{"published", 7},
		{"advanced", 19},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t, sourceRule("ordinary"))
			f.store.org.Ref.Generation = test.generation
			f.store.policy.Generation, f.scope.PolicyGeneration = 31, 31
			for i := range f.store.policy.Sources {
				f.store.policy.Sources[i].Generation = test.generation
			}
			f.store.policy.GuidanceSource.Generation = test.generation
			for i := range f.store.policy.Rules {
				f.store.policy.Rules[i].Source.Generation = test.generation
			}
			f.seal(t)
			snapshot, err := f.service.approvedSources(context.Background(), f.scope, f.store.policy)
			want := api.OrgSnapshotRequest{OrgID: api.ID(f.scope.Config), Generation: f.store.org.Ref.Generation}
			if err != nil || snapshot.OrgSnapshotRef != f.store.org.Ref || len(f.store.orgRequests) != 1 || f.store.orgRequests[0] != want {
				t.Fatal("approved sources omitted or changed the current publication selectors", err)
			}
			if f.store.policy.Generation != 31 || len(f.judge.requests) != 0 || len(f.store.events) != 0 {
				t.Fatal("org source selection changed policy state or performed inference")
			}
		})
	}
}

func TestOrgSnapshotSelectorRefusals(t *testing.T) {
	for _, rule := range []string{"missing", "mixed", "stale"} {
		t.Run(rule, func(t *testing.T) {
			f := newFixture(t, sourceRule("ordinary"))
			switch rule {
			case "missing":
				f.store.policy.Sources = nil
			case "mixed":
				other := f.store.policy.Sources[0]
				other.ID = "other-source"
				other.Generation++
				f.store.policy.Sources = append(f.store.policy.Sources, other)
			case "stale":
				f.store.org.Ref.Generation++
			}
			result, err := f.service.approvedSources(context.Background(), f.scope, f.store.policy)
			if err == nil || !reflect.DeepEqual(result, sourceSnapshot{}) {
				t.Fatal("org source selection accepted " + rule)
			}
			if rule == "stale" {
				wantCode(t, err, api.CodeConflict)
			} else if len(f.store.orgRequests) != 0 {
				t.Fatal("invalid source pins reached org snapshot lookup")
			}
		})
	}
}
