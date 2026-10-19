package assembly

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

func TestArchiveNativeInstalledForwarder(t *testing.T) {
	port := &helperCleanupNative{}
	native, ok := any(port).(archivejob.Native)
	if !ok {
		t.Fatal("installed native forwarding capability omits archive freeze and read-back")
	}
	intent := archivejob.Intent{Request: api.ArchiveRequest{Target: api.LifeRef{LifeID: "archive-forward-life", Run: 2}}, OperationID: "archive-forward-operation"}
	lane := api.Lane{LifeID: intent.Request.Target.LifeID, Run: intent.Request.Target.Run}
	frozen := archivejob.Freeze{}
	_, freezeErr := native.FreezeArchive(context.Background(), intent, lane)
	checkErr := native.CheckArchiveFreeze(context.Background(), intent, frozen)
	for _, err := range []error{freezeErr, checkErr} {
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeNotImplemented || typed.Owner != "lb-v2-admin" {
			t.Fatal("unbound archive native port invented a freeze or read-back", err)
		}
	}
	if err := port.bind(nil); err == nil {
		t.Fatal("archive native port accepted a missing administrator")
	}
	helper := &admin.Service{}
	if err := port.bind(helper); err != nil {
		t.Fatal(err)
	}
	if err := port.bind(helper); err == nil {
		t.Fatal("archive native port replaced its bound administrator")
	}
	// The actual admin client must preserve cancellation before opening any
	// native transport. A forwarding no-op or successful empty snapshot fails.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	want, wantErr := helper.FreezeArchive(ctx, intent, lane)
	got, gotErr := native.FreezeArchive(ctx, intent, lane)
	if wantErr == nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(gotErr, wantErr) {
		t.Fatal("archive freeze did not forward the real administrator refusal", gotErr)
	}
	wantErr = helper.CheckArchiveFreeze(ctx, intent, frozen)
	gotErr = native.CheckArchiveFreeze(ctx, intent, frozen)
	if wantErr == nil || !reflect.DeepEqual(gotErr, wantErr) {
		t.Fatal("archive freeze read-back did not forward the real administrator refusal", gotErr)
	}
}
