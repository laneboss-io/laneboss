//go:build linux

package service

import (
	"testing"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/reviewjob"
	"laneboss.io/laneboss/internal/v2/store"
)

func TestReviewInstalledProducers(t *testing.T) {
	state, err := store.New(store.Dependencies{Config: "service-fixture", Directory: privateHostDirectory(t), Clock: fixtureClock{}})
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	if _, ok := any(state).(reviewjob.Source); !ok {
		t.Error("authoritative writer lacks ReviewSnapshot, ReserveReviewWorker and AwaitReviewResult")
	}
	if _, ok := any(new(admin.Service)).(reviewjob.Requirements); !ok {
		t.Error("installed administrator lacks protected RequiredReviewChecks")
	}
}
