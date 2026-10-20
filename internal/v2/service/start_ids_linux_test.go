//go:build linux

package service

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

type startIDsStore struct{ api.StateStore }

func (startIDsStore) Effect(context.Context, api.Scope, api.ID) (api.EffectRecord, error) {
	return api.EffectRecord{}, serviceError(api.CodeNotFound, "fixture lookup refusal")
}

func TestEffectStartIDs(t *testing.T) {
	effect := api.Effect{ID: fixtureID(t), OperationID: fixtureID(t),
		Context:    &api.InternalIntent{Target: api.LifeRef{LifeID: fixtureID(t), Run: 2}},
		PlanLaunch: &api.LaunchPlanEffect{ReservationID: fixtureID(t)}}
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	old := os.Stderr
	os.Stderr = write
	defer func() { os.Stderr = old; write.Close() }()
	host := &Server{deps: Dependencies{Store: startIDsStore{}}}
	if got := host.reconcileEffect(context.Background(), effect, effectRetries{}); got != attemptStop {
		t.Fatal("lookup refusal did not stop the actual launch attempt")
	}
	os.Stderr = old
	if err := write.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(read)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	for _, outcome := range []string{"started", "fault"} {
		var row struct {
			Outcome     string        `json:"outcome"`
			Effect      api.ID        `json:"effect_id"`
			Operation   api.ID        `json:"operation_id"`
			Life        api.ID        `json:"life_id"`
			Run         api.RunNumber `json:"run"`
			Reservation api.ID        `json:"reservation_id"`
		}
		if err := decoder.Decode(&row); err != nil {
			t.Fatal(err)
		}
		if row.Outcome != outcome || row.Effect != effect.ID || row.Operation != effect.OperationID ||
			row.Life != effect.Context.Target.LifeID || row.Run != effect.Context.Target.Run || row.Reservation != effect.PlanLaunch.ReservationID {
			t.Fatal("launch attempt cannot join its life and durable effect", row)
		}
	}
}
