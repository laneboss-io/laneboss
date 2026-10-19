package approval

import (
	"context"
	"errors"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestApplyPublicationEpoch(t *testing.T) {
	f := readyFixture(t)
	f.store.currentLane = &api.Lane{LifeID: f.scope.Actor.LifeID, Run: f.store.launch.Target.Run, LaunchID: f.store.launch.ID, CancellationEpoch: 7}
	request := api.ChangeApplyRequest{ChangeID: f.store.change.ID, ApprovalID: f.store.approval.ID, ExpectedGeneration: 7}
	scope := f.bound("org.change.apply", request, false)
	stopped := errors.New("component transaction stopped after epoch inspection")
	observed := false
	f.store.transact = func(tx api.Transaction) (api.Commit, error) {
		observed = true
		if len(tx.Effects) != 1 || tx.Effects[0].Context.CancellationEpoch != 7 {
			t.Fatal("publication effect dropped the current L6 life cancellation epoch")
		}
		return api.Commit{}, stopped
	}
	if _, err := f.service.OrgChangeApply(context.Background(), scope, request); err != stopped || !observed {
		t.Fatal("publication epoch check did not reach its actual guarded transaction", err)
	}
}
