package lifecycle

import (
	"context"
	"encoding/json"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestFixtureStarterFence(t *testing.T) {
	f := newLaunchFixture(t)
	var seed api.LaunchEvent
	if err := api.DecodeObject(f.store.events[0].Payload, &seed); err != nil {
		t.Fatal(err)
	}
	if seed.TaskSecretNames == nil || seed.TaskSecretFileNames == nil || seed.SecretGrantIDs == nil || seed.SecretSourceVersions == nil || seed.Trigger.MailIDs == nil || seed.Trigger.CausingSeqs == nil {
		t.Fatal("starter fixture retained null required arrays")
	}
	_, record := f.reserve(t)
	epoch, present := f.store.fences[record.Reservation.Target.LifeID]
	if !present || epoch != record.Reservation.CancellationEpoch || record.Reservation.StarterEventSeq != f.store.events[0].Seq {
		t.Fatal("reservation lost its recorded starter and cancellation fences")
	}
	// The schema-invalid original seed cannot establish an authentic starter.
	seed.TaskSecretNames = nil
	raw, err := json.Marshal(seed)
	if err != nil {
		t.Fatal(err)
	}
	if api.DecodeObject(raw, &seed) == nil {
		t.Fatal("null launch metadata became a valid starter event")
	}
}

func TestFixtureEpochRefuses(t *testing.T) {
	for _, mode := range []string{"absent", "changed"} {
		t.Run(mode, func(t *testing.T) {
			f := newLaunchFixture(t)
			_, record := f.reserve(t)
			scope, request := f.claim(t, record)
			if mode == "absent" {
				delete(f.store.fences, record.Reservation.Target.LifeID)
			} else {
				f.store.fences[record.Reservation.Target.LifeID]++
			}
			_, err := f.service.PlanLaunch(context.Background(), scope, request)
			if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeConflict || f.ports.calls["allocate"] != 0 || f.ports.calls["acquire"] != 0 {
				t.Fatalf("missing or changed fixture epoch passed the actual launch path: %v", err)
			}
		})
	}
}

func TestFixturePreparedFences(t *testing.T) {
	f := newLaunchFixture(t)
	_, record := f.reserve(t)
	scope, request := f.claim(t, record)
	plan, err := f.service.PlanLaunch(context.Background(), scope, request)
	if err != nil {
		t.Fatal(err)
	}
	lane := f.bindPrepared(t, scope, request, plan)
	if f.store.fences[lane.LifeID] != lane.CancellationEpoch || lane.Generation != plan.Reservation.Generation ||
		lane.Generation == lane.CancellationEpoch || f.store.plans[record.Reservation.ID].Generation <= record.Generation {
		t.Fatal("prepared fixture confused life generation, plan revision and cancellation epoch")
	}
}
