//go:build linux && laneboss_root_canary

package admin

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestSavedWait(t *testing.T) {
	for _, slot := range []string{"retirement", "worker"} {
		for _, state := range []string{"running", "running-status", "missing", "both", "exit", "signal"} {
			t.Run(slot+"-"+state, func(t *testing.T) {
				m, e, q, group, live, hold := retirementFixture(t, "live")
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				p, err := m.find(e.LeaseID)
				if err != nil {
					t.Fatal(err)
				}
				p.Archive.Retirement = &archiveRetirementJournal{Job: q.Job, Claim: q.Claim, AuthorizedAt: gateTimestamp(), Opened: true}
				if state == "exit" {
					if err := hold.Close(); err != nil {
						t.Fatal(err)
					}
					select {
					case <-live.done:
					case <-ctx.Done():
						t.Fatal("original wait did not finish")
					}
				} else if state == "signal" {
					if err := m.killContainment(ctx, archiveChild(p, *p.Archive.Worker)); err != nil {
						t.Fatal(err)
					}
					if _, err := live.Stop(ctx, q.Process); err != nil {
						t.Fatal(err)
					}
				}
				saved, err := live.Observe(ctx, q.Process)
				if err != nil {
					t.Fatal(err)
				}
				switch state {
				case "running-status":
					code := 0
					saved.ExitCode = &code
				case "missing":
					saved.State, saved.ExitCode, saved.Signal = "exited", nil, nil
				case "both":
					code, signal := 0, 9
					saved.State, saved.ExitCode, saved.Signal = "exited", &code, &signal
				}
				if slot == "retirement" {
					p.Archive.Retirement.Observation = &saved
				} else {
					p.Archive.Worker.Observation = &saved
				}
				// Deliberately retain malformed semantic evidence through the raw
				// file store. Read it back after discarding the live owner, then
				// call the recovery wait guard directly: records()'s independent
				// validator must not mask this regression or kill its control.
				if err := m.store.Save(p); err != nil {
					t.Fatal(err)
				}
				restarted := newLeaseManager(m.binding, m.bootID, m.store, m.resources)
				records, err := restarted.store.Records()
				if err != nil || len(records) != 1 || !reflect.DeepEqual(records[0], p) || restarted.gates[q.Allocation.ID] != nil {
					t.Fatal("saved wait fixture did not survive a fresh native owner")
				}
				actual, err := restarted.retirementWait(ctx, &records[0])
				if state == "exit" || state == "signal" {
					if err != nil || !reflect.DeepEqual(actual, saved) {
						t.Fatal("acceptance: restarted retirement changed its original terminal wait")
					}
					return
				}
				var typed *api.Error
				_, groupErr := os.Stat(group)
				still, observeErr := live.Observe(ctx, q.Process)
				if !errors.As(err, &typed) || typed.Code != api.CodeContainmentUnknown || typed.Message != "archive retirement did not observe a terminal native wait" || groupErr != nil || observeErr != nil || still.State != "running" || records[0].Archive.Worker.Collected {
					t.Fatal("acceptance: restarted retirement reused a nonterminal saved wait")
				}
			})
		}
	}
}
