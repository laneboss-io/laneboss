package lifecycle

import (
	"context"
	"errors"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestPlanInvalidOwnCheck(t *testing.T) {
	f := newLaunchFixture(t)
	_, record := f.reserve(t)
	scope, request := f.claim(t, record)
	request.Lease.Record.Effect.PlanLaunch.ReservationID = ""
	observed := ""
	ctx := api.WithHelperReasonObserver(context.Background(), func(cause error, check string) {
		var typed *api.Error
		if errors.As(cause, &typed) && typed.Code == api.CodeInvalid {
			observed = check
		}
	})
	_, err := f.service.PlanLaunch(ctx, scope, request)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeInvalid || observed != "plan_entry" {
		t.Fatal("invalid planning input lost its own fixed check", observed, err)
	}
}
