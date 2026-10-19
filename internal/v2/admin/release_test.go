package admin

import (
	"context"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestReleaseMeasuredFacts(t *testing.T) {
	ctx := context.Background()
	m, store, resources := testManager()
	lease, err := m.allocate(ctx, testAllocation())
	if err != nil {
		t.Fatal(err)
	}
	claim := testRelease(lease, testObservation(lease))
	measured := testObservation(lease)
	claimTime, err := time.Parse(time.RFC3339Nano, string(claim.Observation.ObservedAt))
	if err != nil {
		t.Fatal(err)
	}
	measured.ObservedAt = api.Timestamp(claimTime.Add(time.Nanosecond).Format(time.RFC3339Nano))
	zero := uint64(0)
	resources.facts = &releaseFacts{Observation: measured, LiveConnections: &zero, QueuedJobs: &zero, WritableExports: &zero}
	for _, field := range []string{"connections", "jobs", "exports", "survivors", "exit"} {
		bad := *resources.facts
		one, exit := uint64(1), 7
		switch field {
		case "connections":
			bad.LiveConnections = &one
		case "jobs":
			bad.QueuedJobs = nil
		case "exports":
			bad.WritableExports = &one
		case "survivors":
			bad.Observation.Survivors = &one
		case "exit":
			bad.Observation.ExitCode = &exit
		}
		resources.facts = &bad
		receipt, err := m.release(ctx, claim)
		if err == nil || receipt.ID != "" || store.records[0].Phase != "active" || len(resources.removed) != 0 {
			t.Fatal("acceptance: unmeasured release")
		}
		requireCode(t, err, api.CodeContainmentUnknown)
		resources.facts = &releaseFacts{Observation: measured, LiveConnections: &zero, QueuedJobs: &zero, WritableExports: &zero}
	}
	receipt, err := m.release(ctx, claim)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ID == "" || !reflect.DeepEqual(receipt.Quiescence, measured) || receipt.Quiescence.ObservedAt == claim.Observation.ObservedAt ||
		receipt.LeaseID != lease.ID || receipt.EffectID != claim.Cause.EffectID || store.records[0].Receipt == nil {
		t.Fatal("receipt did not retain independent measurement")
	}
	replayed, err := m.release(ctx, claim)
	if err != nil || !reflect.DeepEqual(replayed, receipt) {
		t.Fatal("release replay changed the measured receipt")
	}
}
