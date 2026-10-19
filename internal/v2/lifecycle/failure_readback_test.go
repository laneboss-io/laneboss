package lifecycle

import (
	"context"
	"errors"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// Model the real writer's JSON boundary rather than retaining private error
// fields through shared pointers in the component store. All public bytes come
// from the actual failed-plan transaction and cleanup batch.
type persistedFailureStore struct {
	*launchFixtureStore
	t        *testing.T
	mutation string
}

func (s *persistedFailureStore) FailPlan(ctx context.Context, tx api.Transaction, jobs []api.PlanCleanup) (api.Commit, error) {
	commit, err := s.launchFixtureStore.FailPlan(ctx, tx, jobs)
	if err != nil {
		return commit, err
	}
	id := tx.Writes.LaunchPlans[0].Reservation.ID
	plan := launchClone(s.t, s.plans[id])
	if s.mutation == "error" {
		plan.Error.Message += " changed after persistence"
	}
	s.plans[id] = plan
	for i, job := range jobs {
		retained := launchClone(s.t, s.cleanups[job.ID])
		if s.mutation == "cleanup" && i == 0 {
			retained.Issues = append(retained.Issues, &api.Error{Code: api.CodeIntegrity, Message: "changed cleanup issue"})
		}
		s.cleanups[job.ID] = retained
	}
	return commit, nil
}

func TestFailureDiagnosticReadback(t *testing.T) {
	for _, mutation := range []string{"", "error", "cleanup"} {
		t.Run("case-"+mutation, func(t *testing.T) {
			f := newLaunchFixture(t)
			_, record := f.reserve(t)
			scope, request := f.claim(t, record)
			if _, err := f.service.PlanLaunch(context.Background(), scope, request); err != nil {
				t.Fatal(err)
			}
			record = f.store.plans[record.Reservation.ID]
			f.service.deps.Store = &persistedFailureStore{launchFixtureStore: f.store, t: t, mutation: mutation}
			execution := &planExecution{service: f.service, scope: scope, lease: request.Lease, record: record}
			original := api.WithErrorComponent(problem(api.CodeNotFound, "retained input disappeared", "Preserve its original records."), "store_object")
			err := execution.failPlan(context.Background(), original)
			if mutation == "" {
				if err != original || api.ErrorComponent(err) != "store_object" || len(f.store.failedWrites) != 1 {
					t.Fatal("private diagnostic changed durable failure readback or the live refusal", err)
				}
				return
			}
			if err == original || !errors.Is(err, original) {
				t.Fatal("changed durable failure fields escaped readback verification", err)
			}
		})
	}
}
