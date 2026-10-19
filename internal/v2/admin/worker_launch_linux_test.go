//go:build linux

package admin

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/identity"
)

func TestWorkerLaunchUnbound(t *testing.T) {
	source, ok := any(&Service{}).(identity.WorkerLaunchSource)
	if !ok {
		t.Fatal("worker launch source is absent from the administrator client")
	}
	guard, err := source.AcquireWorkerLaunch(context.Background(), "foreign", "stale-prepared")
	if err == nil || guard != nil {
		t.Fatal("unbound administrator supplied a worker launch guard")
	}
}
