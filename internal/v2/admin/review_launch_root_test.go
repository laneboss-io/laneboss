//go:build linux && laneboss_root_canary

package admin

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

func TestReviewLaunchNative(t *testing.T) {
	if _, ok := any(new(Service)).(interface {
		FreezeReview(context.Context, archivejob.Intent, api.Lane) (archivejob.Snapshot, error)
	}); !ok {
		t.Fatal("installed native review freeze and verifier execution are absent")
	}
	TestWorkerLaunchNative(t)
}
