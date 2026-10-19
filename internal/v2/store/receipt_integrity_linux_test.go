//go:build linux

package store_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

func TestLaunchReceiptIntegrity(t *testing.T) {
	f := fx.New(t)
	f.Reserve(t)
	if _, err := f.State.LaunchPlan(context.Background(), f.Execution, f.Reservation.ID); err != nil {
		t.Fatal("receipt integrity positive control failed", err)
	}
	compact, err := json.Marshal(f.Human.Request)
	if err != nil || bytes.Equal(compact, f.Raw) {
		t.Fatal("receipt corruption did not change representation", err)
	}
	// Change only this disposable fixture's receipt bytes. The original launch
	// object and digest stay untouched, so the actual lookup must detect it.
	db, err := sql.Open("sqlite", filepath.Join(f.Deps.Directory, "state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	if _, err := db.Exec("DROP TRIGGER receipts_no_update"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE receipts SET request=? WHERE json_extract(operation,'$.id')=?", compact, string(f.Reservation.OperationID)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TRIGGER receipts_no_update BEFORE UPDATE ON receipts BEGIN SELECT RAISE(ABORT, 'immutable receipts'); END"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.State.LaunchPlan(context.Background(), f.Execution, f.Reservation.ID); err == nil {
		t.Fatal("launch plan accepted changed receipt bytes")
	} else {
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeIntegrity || typed.Message != "launch request is not the exact original receipt bytes" {
			t.Fatal("receipt integrity control reached an unrelated refusal", err)
		}
	}
}
