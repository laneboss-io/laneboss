package assembly

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/store"
)

func TestRestoreRootForwarder(t *testing.T) {
	port := &helperCleanupNative{}
	source, ok := any(port).(store.RestoreRootSource)
	if !ok {
		t.Fatal("installed restore root capability is missing")
	}
	_, err := source.RestoreRoots(context.Background(), api.Scope{})
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeNotImplemented {
		t.Fatal("unbound restore roots invented authority", err)
	}
	helper := &admin.Service{}
	if err := port.bind(helper); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	want, wantErr := helper.RestoreRoots(ctx, api.Scope{})
	got, gotErr := source.RestoreRoots(ctx, api.Scope{})
	if wantErr == nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(gotErr, wantErr) {
		t.Fatal("restore root forwarding lost the actual administrator refusal", gotErr)
	}
}
