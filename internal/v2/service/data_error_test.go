package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestMaterializeErrors(t *testing.T) {
	for _, mode := range []string{"cancelled", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			want := api.CodeCancelled
			cancel()
			if mode == "deadline" {
				ctx, cancel = context.WithDeadline(context.Background(), time.Unix(0, 0))
				want = api.CodeDeadline
			}
			defer cancel()
			driver := errors.New("component driver interruption without a wrapped context")
			err := materializationError(ctx, driver)
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != want {
				t.Fatal("materialization lost the interrupted context", err)
			}
			if materializationError(ctx, nil) != nil {
				t.Fatal("materialization changed a successful read")
			}
			integrity := serviceError(api.CodeIntegrity, "component exact byte mismatch")
			if materializationError(ctx, integrity) != integrity {
				t.Fatal("materialization masked an integrity refusal")
			}
			if materializationError(context.Background(), driver) != driver {
				t.Fatal("materialization hid an unrelated read failure")
			}
		})
	}
}
