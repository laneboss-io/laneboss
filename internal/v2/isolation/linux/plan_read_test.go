package linux

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// This implements the actual shared port with retained metadata and failing
// reads. It proves no durable store claim or successful installed launch.
type retainedControls struct {
	fixtureControls
	record  api.LaunchPlanRecord
	planErr error
	foreign bool
	reads   []api.ID
}

func (s *retainedControls) Plan(ctx context.Context, id api.ID) (api.LaunchPlanRecord, error) {
	s.reads = append(s.reads, id)
	if err := ctx.Err(); err != nil {
		return api.LaunchPlanRecord{}, err
	}
	if s.planErr != nil {
		// Even a source that returns partial data with its error cannot turn
		// that data into a fallback plan in the consumer.
		return s.record, s.planErr
	}
	if !s.foreign && id != s.record.Reservation.ID {
		return api.LaunchPlanRecord{}, failure(api.CodeNotFound, "retained selector is absent")
	}
	return s.record, nil
}

func retainedMeta(t *testing.T) *retainedControls {
	t.Helper()
	r, raw := planMeta(t)
	return &retainedControls{record: r, fixtureControls: fixtureControls{handoff: *r.Handoff, original: raw}}
}

func foreignMeta(t *testing.T) api.LaunchPlanRecord {
	t.Helper()
	r, _ := planMeta(t)
	reservation := r.Reservation
	reservation.ID = "foreign-reservation"
	r = api.LaunchPlanRecord{Reservation: reservation, Generation: 1, Phase: "reserved"}
	if err := api.ValidateLaunchPlanRecord(r); err != nil {
		t.Fatal("foreign record must be structurally valid:", err)
	}
	return r
}

func TestPlanSourceRead(t *testing.T) {
	source := retainedMeta(t)
	id := source.record.Reservation.ID
	record, err := readAgentPlan(context.Background(), source, id)
	if err != nil || len(source.reads) != 1 || source.reads[0] != id || !reflect.DeepEqual(record, source.record) {
		t.Fatal("shared plan port was not consumed with the retained selector")
	}
	if record.DataStageID != source.record.DataStageID {
		t.Fatal("retained child stage was changed by the plan read")
	}
}

func TestPlanSourceError(t *testing.T) {
	for _, expected := range []error{errors.New("durable claim expired"), api.NotImplemented("lb-v2-service", "service.Plan")} {
		source := retainedMeta(t)
		source.planErr = expected
		record, err := readAgentPlan(context.Background(), source, source.record.Reservation.ID)
		if err != expected || len(source.reads) != 1 {
			t.Fatal("source plan error was replaced or the source was not called")
		}
		if record.Plan != nil || record.Handoff != nil {
			t.Fatal("source plan error leaked fallback data")
		}
	}
}

func TestPlanSourceForeign(t *testing.T) {
	source := retainedMeta(t)
	id := source.record.Reservation.ID
	source.record, source.foreign = foreignMeta(t), true
	_, err := readAgentPlan(context.Background(), source, id)
	if err == nil || len(source.reads) != 1 || source.reads[0] != id {
		t.Fatal("foreign retained plan escaped the shared reader")
	}
	requireCode(t, err, api.CodeInvalid)
}

func TestPlanSourceRecord(t *testing.T) {
	source := retainedMeta(t)
	source.record.Generation = 0
	_, err := readAgentPlan(context.Background(), source, source.record.Reservation.ID)
	if err == nil || len(source.reads) != 1 {
		t.Fatal("malformed retained plan escaped the shared reader")
	}
	requireCode(t, err, api.CodeInvalid)
}
