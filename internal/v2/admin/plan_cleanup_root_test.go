//go:build linux && laneboss_root_canary

package admin

import (
	"context"
	"os"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestPlanCleanupNativeJournal(t *testing.T) {
	m, record, base := collectionLeaseFixture(t, true)
	cause := record.Request.Cause
	cause.Kind, cause.ID, cause.EffectID = api.InternalHelperAbort, "cleanup-native-cause", "cleanup-native-effect"
	request := api.HelperAbortRequest{Cause: cause, LeaseID: record.Lease.ID, OperationID: cause.CauseOperationID, EffectID: cause.EffectID}
	ctx := context.Background()
	actual, err := m.abort(ctx, request)
	if err != nil {
		t.Fatal("failed-start cleanup did not collect its actual unopened native allocation", err)
	}
	entries, err := os.ReadDir(base)
	if err != nil || len(entries) != 0 {
		t.Fatal("native abort retained private storage beneath its protected parent", err)
	}
	effect := api.Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID, Context: &cause, HelperAbort: &request}
	raw, err := canonicalValue(effect)
	if err != nil {
		t.Fatal(err)
	}
	value, err := m.dispatch(ctx, "plan_cleanup_native_read", raw)
	if err != nil {
		t.Fatal("native cleanup has no independent terminal journal port", err)
	}
	read, ok := value.(api.EffectOutcome)
	if !ok || read.Abort == nil || !reflect.DeepEqual(*read.Abort, actual) || read.Release != nil || read.EffectID != effect.ID {
		t.Fatal("native read replaced its real original abort measurement")
	}
	retry, err := m.abort(ctx, request)
	if err != nil || !reflect.DeepEqual(retry, actual) {
		t.Fatal("native cleanup retry changed its retained receipt", err)
	}
	foreign := effect
	foreign.ID = "foreign-cleanup-native-effect"
	raw, err = canonicalValue(foreign)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.dispatch(ctx, "plan_cleanup_native_read", raw); err == nil {
		t.Fatal("native journal rebound a receipt to a foreign cleanup effect")
	}
}
