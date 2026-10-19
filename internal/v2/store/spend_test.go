//go:build linux

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type spendWriter interface {
	reconcileSpend(context.Context, *sql.Tx, api.SpendReading) (api.SpendBalance, error)
	accountSpendChunk(context.Context, *sql.Tx, api.LaunchPlanRecord, api.CaptureRecord, []byte, bool) error
	spendRelease(context.Context, *sql.Tx, api.LaunchPlanRecord, api.Timestamp) error
	checkSpendPlan(context.Context, queryer, api.LaunchPlanRecord) error
}

func spendTx(t *testing.T, s *Service, call func(spendWriter, *sql.Tx) error) error {
	t.Helper()
	w, ok := any(s).(spendWriter)
	if !ok {
		t.Fatal("persistent vendor spend accounting is missing")
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	err = call(w, tx)
	if err != nil {
		if e := tx.Rollback(); e != nil {
			t.Fatal(e)
		}
		return err
	}
	return tx.Commit()
}

func spendReading(t *testing.T, amount string) api.SpendReading {
	t.Helper()
	return api.SpendReading{ID: testID(t), CredentialID: "pool-one", ProfileIDs: []api.ID{"profile-one", "profile-alias"}, FloorMicros: 5000000, Selector: "TOTAL",
		Output: []byte("profile-one  " + amount + " USD\nTOTAL  " + amount + " USD\n"), ObservedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}
}

func spendPlan(life, session string) api.LaunchPlanRecord {
	b := api.CaptureBinding{ID: api.ID("capture-" + life), Config: "store-fixture", Target: api.LifeRef{LifeID: api.ID(life), Run: 1}, LaunchID: api.ID("launch-" + life), OperationID: api.ID("operation-" + life), RequestID: api.ID("request-" + life), RequestedBy: api.Actor{Kind: "service", ID: "operator"}, Status: "registered"}
	p := api.LaunchPlan{Runner: api.RunnerPlan{Driver: api.DriverClaudock, Slot: api.CredentialSlot{ProfileID: "profile-one", Mode: "claude-api-key"}, Session: api.Session{VendorID: session}}, Capture: b}
	return api.LaunchPlanRecord{Reservation: api.LaunchReservation{Config: b.Config, Target: b.Target, LaunchID: b.LaunchID, OperationID: b.OperationID, RequestID: b.RequestID, RequestedBy: b.RequestedBy}, Plan: &p}
}

func spendChunk(t *testing.T, p api.LaunchPlanRecord, cost string) (api.CaptureRecord, []byte) {
	t.Helper()
	raw := []byte(`{"type":"result","uuid":"result-one","session_id":"` + p.Plan.Runner.Session.VendorID + `","is_error":false,"total_cost_usd":` + cost + `,"cost_usd":99,"usage":{"input_tokens":10,"output_tokens":2}}` + "\n")
	r := api.CaptureRecord{ID: testID(t), BindingID: p.Plan.Capture.ID, Target: p.Reservation.Target, Stream: "stdout", Data: api.BlobRef{ID: testID(t), Class: "capture", Bytes: int64(len(raw)), SHA256: testDigest(raw)}, Primary: true, Coverage: "partial"}
	return r, raw
}

func TestSpendLedger(t *testing.T) {
	for _, name := range []string{"two_lanes", "lower_reading", "latest_reading", "at_floor", "missing_reading", "crossing_stop", "fake_key", "split", "restart", "replay", "release", "capture_required", "unknown_cost"} {
		t.Run(name, func(t *testing.T) {
			s, deps := testStore(t)
			guard, ok := any(s).(api.CredentialSpendGuard)
			if !ok {
				t.Fatal("credential launch spend guard is missing")
			}
			slot := api.CredentialSlot{ProfileID: "profile-one", Mode: "claude-api-key"}
			if name == "missing_reading" {
				if _, err := guard.CheckCredentialSpend(context.Background(), slot); err == nil {
					t.Fatal("missing reading admitted a launch")
				}
				return
			}
			seed := "10.00"
			if name == "at_floor" {
				seed = "5.00"
			}
			var balance api.SpendBalance
			err := spendTx(t, s, func(w spendWriter, tx *sql.Tx) error {
				var e error
				balance, e = w.reconcileSpend(context.Background(), tx, spendReading(t, seed))
				return e
			})
			if err != nil {
				t.Fatal(err)
			}
			if name == "at_floor" {
				if _, err := guard.CheckCredentialSpend(context.Background(), slot); err == nil {
					t.Fatal("launch at floor was admitted")
				}
				return
			}
			p := spendPlan("lane-one", "session-one")
			if name == "capture_required" {
				p.Plan.Capture.Status = "refused"
				err := spendTx(t, s, func(w spendWriter, tx *sql.Tx) error { return w.checkSpendPlan(context.Background(), tx, p) })
				if err == nil {
					t.Fatal("API key launch accepted refused spend capture")
				}
				return
			}
			cost := "1.25"
			if name == "crossing_stop" {
				cost = "5.01"
			}
			if name == "fake_key" {
				cost = "0"
			}
			if name == "crossing_stop" {
				lane := api.Lane{LifeID: p.Reservation.Target.LifeID, Run: 1, Generation: 1, State: "running", LaunchID: p.Reservation.LaunchID, RootLifeID: p.Reservation.Target.LifeID, StarterChain: []api.ID{}}
				fixtureProjection(t, s, "lane", lane.LifeID, 1, lane)
				fixtureProjection(t, s, "launch_plan", "plan-one", 1, p)
				fixtureProjection(t, s, "launch", lane.LaunchID, 1, api.LaunchRecord{ID: lane.LaunchID, Config: deps.Config, Target: p.Reservation.Target, ContainmentID: "containment-one", ProcessGeneration: "process-one"})
				fixtureProjection(t, s, "launch_observation", lane.LaunchID, 1, struct {
					Observation api.ProcessObservation
					Generation  api.Generation
				}{Observation: api.ProcessObservation{Handle: api.ProcessHandle{ID: "native-process-handle", Target: p.Reservation.Target, ContainmentID: "containment-one", Generation: "process-one"}}, Generation: 1})
			}
			r, raw := spendChunk(t, p, cost)
			if name == "fake_key" {
				r, raw = spendFakeKeyCapture(t, &p)
			}
			if name == "unknown_cost" {
				raw = []byte(`{"type":"result","uuid":"result-one","session_id":"session-one","is_error":true}` + "\n")
				r.Data.Bytes = int64(len(raw))
				r.Data.SHA256 = testDigest(raw)
			}
			err = spendTx(t, s, func(w spendWriter, tx *sql.Tx) error {
				if name == "split" {
					first := r
					first.Data.Bytes = 19
					first.Data.SHA256 = testDigest(raw[:19])
					if e := w.accountSpendChunk(context.Background(), tx, p, first, raw[:19], false); e != nil {
						return e
					}
					r.Offset = 19
					r.Data.Bytes = int64(len(raw) - 19)
					r.Data.SHA256 = testDigest(raw[19:])
					raw = raw[19:]
				}
				return w.accountSpendChunk(context.Background(), tx, p, r, raw, false)
			})
			if err != nil {
				t.Fatal(err)
			}
			if name == "replay" {
				if err := spendTx(t, s, func(w spendWriter, tx *sql.Tx) error {
					return w.accountSpendChunk(context.Background(), tx, p, r, raw, false)
				}); err != nil {
					t.Fatal(err)
				}
			}
			if name == "release" {
				if err := spendTx(t, s, func(w spendWriter, tx *sql.Tx) error {
					return w.spendRelease(context.Background(), tx, p, api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano)))
				}); err != nil {
					t.Fatal(err)
				}
				if _, err := guard.CheckCredentialSpend(context.Background(), slot); err == nil {
					t.Fatal("release admitted another launch without a tool reading")
				}
				if err := spendTx(t, s, func(w spendWriter, tx *sql.Tx) error {
					_, err := w.reconcileSpend(context.Background(), tx, spendReading(t, "8.50"))
					return err
				}); err != nil {
					t.Fatal(err)
				}
			}
			if name == "two_lanes" {
				p = spendPlan("lane-two", "session-two")
				p.Plan.Runner.Slot.ProfileID = "profile-alias"
				r, raw = spendChunk(t, p, "0.75")
				if err := spendTx(t, s, func(w spendWriter, tx *sql.Tx) error {
					return w.accountSpendChunk(context.Background(), tx, p, r, raw, false)
				}); err != nil {
					t.Fatal(err)
				}
			}
			if name == "lower_reading" || name == "latest_reading" {
				if err := spendTx(t, s, func(w spendWriter, tx *sql.Tx) error {
					var e error
					balance, e = w.reconcileSpend(context.Background(), tx, spendReading(t, "6.00"))
					return e
				}); err != nil {
					t.Fatal(err)
				}
			}
			if name == "latest_reading" {
				if err := spendTx(t, s, func(w spendWriter, tx *sql.Tx) error {
					_, err := w.reconcileSpend(context.Background(), tx, spendReading(t, "8.00"))
					return err
				}); err != nil {
					t.Fatal(err)
				}
			}
			if name == "restart" {
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
				var e error
				s, e = New(deps)
				if e != nil {
					t.Fatal(e)
				}
				t.Cleanup(func() {
					if e := s.Close(); e != nil {
						t.Error(e)
					}
				})
				guard, ok = any(s).(api.CredentialSpendGuard)
				if !ok {
					t.Fatal("reopened ledger lost its spend guard")
				}
			}
			balance, err = guard.CheckCredentialSpend(context.Background(), slot)
			want := int64(8750000)
			switch name {
			case "two_lanes":
				want = 8000000
			case "lower_reading":
				want = 6000000
			case "latest_reading":
				want = 8000000
			case "crossing_stop":
				want = 4990000
			case "fake_key":
				want = 10000000
			case "release":
				want = 8500000
			case "unknown_cost":
				want = 10000000
			}
			if balance.RemainingMicros != want {
				t.Fatal("wrong shared remaining balance", balance.RemainingMicros)
			}
			if name == "fake_key" {
				var count int
				if e := s.db.QueryRow("SELECT count(*) FROM projections WHERE kind='spend_result'").Scan(&count); e != nil || count != 1 || balance.SpentMicros != 0 || balance.AccountingError != nil {
					t.Fatal("fake-key refusal did not retain its vendor zero-cost result", e)
				}
			}
			if name == "crossing_stop" {
				if err == nil {
					t.Fatal("crossed floor still admits launch")
				}
				var lane api.Lane
				if e := storedProjection(context.Background(), s.db, "lane", "lane-one", &lane); e != nil || lane.State != "stopping" {
					t.Fatal("crossed floor did not fence lane", e)
				}
				effects, e := s.PendingEffects(context.Background(), api.CursorRequest{Limit: 200})
				if e != nil || len(effects) != 1 || effects[0].Stop == nil || effects[0].Stop.ID != "native-process-handle" {
					t.Fatal("crossed floor did not queue contained stop", e)
				}
				var count int
				if e := s.db.QueryRow("SELECT count(*) FROM events WHERE json_extract(data,'$.kind')='spend.stopped'").Scan(&count); e != nil || count != 1 {
					t.Fatal("floor stop was not journaled", e)
				}
			} else if name == "unknown_cost" {
				if err == nil || balance.AccountingError == nil || !balance.NeedsReading {
					t.Fatal("unpriced vendor result was counted as zero-cost success")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			var rawBalance []byte
			if e := s.db.QueryRow("SELECT data FROM projections WHERE kind='spend_pool'").Scan(&rawBalance); e != nil || !json.Valid(rawBalance) {
				t.Fatal("balance not persisted", e)
			}
		})
	}
}
