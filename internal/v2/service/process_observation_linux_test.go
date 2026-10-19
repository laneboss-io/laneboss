//go:build linux

package service

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/dataworker"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// These are real SQLite reservation/launch/completion and service-control
// components. Native execution remains the installed lifecycle harness's job.
func TestCompletedLaunchObservation(t *testing.T) {
	for _, state := range []string{"running", "exited"} {
		t.Run(state, func(t *testing.T) {
			f := fx.Ready(t, true)
			f.Opened(t)
			if state == "exited" {
				f.Ended(t)
			}
			s, ctx := launchServer(t, f), context.Background()
			stage, err := f.State.Effect(ctx, f.Execution, f.Claim.Record.Effect.ID)
			if err != nil || stage.Outcome == nil || stage.Outcome.Status != "succeeded" || stage.Outcome.Process == nil || *stage.Outcome.Process != f.Process {
				t.Fatal("regression did not complete its real original launch", err)
			}
			if _, err := s.processClaim(ctx, f.Reservation.Target, f.Process); err == nil {
				t.Fatal("completed observation fixture still has stage authority")
			} else {
				codeIs(t, err, api.CodeConflict)
			}
			request, err := s.Observe(ctx, f.Process)
			if err != nil || request.Handle != f.Process || request.LeaseID != f.Plan.Lease.ID {
				t.Fatal("completed launch lost read-only observation authority", err)
			}
			// Standing monitoring authority cannot mutate the gate or release a UID.
			if _, err := s.Stop(ctx, f.Process, "unclaimed stop control"); err == nil {
				t.Fatal("completed observation authority opened an unclaimed stop")
			}
			if _, err := s.Release(ctx, f.Plan.Lease.ID, f.Observation(t, "exited").Observation); err == nil {
				t.Fatal("completed observation authority opened an unclaimed release")
			}
		})
	}
}

func TestProcessObservationRunOwnership(t *testing.T) {
	for _, mode := range []string{"handle", "foreign_life", "containment", "generation", "stale_run", "foreign_launch", "cleaned", "launch_owner"} {
		t.Run(mode, func(t *testing.T) {
			f := fx.Ready(t, true)
			f.Opened(t)
			handle := f.Process
			switch mode {
			case "handle":
				handle.ID = fx.ID(t)
			case "foreign_life":
				handle.Target.LifeID = fx.ID(t)
			case "containment":
				handle.ContainmentID = fx.ID(t)
			case "generation":
				handle.Generation += "-foreign"
			case "stale_run", "foreign_launch", "cleaned":
				lane := f.Lane
				lane.Generation++
				if mode == "stale_run" {
					lane.Run++
				} else if mode == "foreign_launch" {
					lane.LaunchID = fx.ID(t)
				} else {
					lane.Cleaned = true
				}
				// Explicit protected-state fault after the real completed launch.
				f.Replace(t, "lane", lane.LifeID, lane.Generation, lane)
			case "launch_owner":
				record := f.Binding.Record
				record.HostUID++
				// Corrupt this current projection after open. Reopening would
				// correctly fail journal verification before the target check.
				db, err := sql.Open("sqlite", filepath.Join(f.Deps.Directory, "state.sqlite"))
				if err != nil {
					t.Fatal(err)
				}
				result, writeErr := db.Exec("UPDATE projections SET data=? WHERE kind='launch' AND id=?", fx.JSON(t, record), string(record.ID))
				if writeErr != nil {
					db.Close()
					t.Fatal(writeErr)
				}
				count, countErr := result.RowsAffected()
				closeErr := db.Close()
				if countErr != nil || closeErr != nil || count != 1 {
					t.Fatal("current launch corruption did not change one real projection", countErr, closeErr)
				}
			}
			s := launchServer(t, f)
			if request, err := s.Observe(context.Background(), handle); err == nil || request != (api.HelperObserveRequest{}) {
				t.Fatal("process observation accepted a foreign or stale run", err)
			}
		})
	}
}

func TestUncompletedObservationStillClaims(t *testing.T) {
	f := fx.Ready(t, true)
	ctx := context.Background()
	if err := f.State.RecordLaunchObservation(ctx, f.Reservation.LaunchID, f.Observation(t, "running")); err != nil {
		t.Fatal(err)
	}
	s := launchServer(t, f)
	if _, err := s.Observe(ctx, f.Process); err == nil {
		t.Fatal("uncompleted launch bypassed its stage claim")
	} else {
		codeIs(t, err, api.CodeConflict)
	}
	cause := f.Intent(t, api.InternalLifecycleEffect)
	cause.ID, cause.EffectID, cause.CauseOperationID, cause.CauseRequestID = fx.ID(t), fx.ID(t), fx.ID(t), fx.ID(t)
	cause.RequestedBy = f.Execution.Actor
	claimControl(t, f, api.Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID, Context: &cause, Stop: &f.Process})
	if request, err := s.Observe(ctx, f.Process); err != nil || request.Handle != f.Process || request.LeaseID != f.Plan.Lease.ID {
		t.Fatal("current stop claim lost its original observation route", err)
	}
}

func TestCleanWithoutNativePort(t *testing.T) {
	f := fx.New(t)
	if f.State.CleanupNativeReady() {
		t.Fatal("store without cleanup native port advertised readiness")
	}
	// Both are concrete production components. The missing native capability
	// must stop dispatch before any unconfigured worker method can execute.
	runtime := api.RuntimeServices{Store: f.State, Worker: &dataworker.Service{}}
	err := supportsEffect(runtime, api.Effect{Clean: &api.CleanRequest{}})
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeNotImplemented || typed.Owner != "lb-v2-admin" || typed.Message != "installed protected cleanup native ports is not implemented" {
		t.Fatal("clean without native port escaped its installed refusal", err)
	}
}
