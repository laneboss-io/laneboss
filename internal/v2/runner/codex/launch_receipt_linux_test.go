//go:build linux

package codex

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	storeport "laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// Exercise the actual runner's original-input reader against real admission,
// protected reservation, receipt and object bytes. No store method is stubbed.
func TestOriginalLaunchReservationReceipt(t *testing.T) {
	f := fx.New(t)
	f.Reserve(t)
	ctx := context.Background()
	view, err := f.State.BeginRead(ctx, f.Execution)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := view.Close(); err != nil {
			t.Error(err)
		}
	}()
	scope := f.Execution
	scope.ReadView = view
	runner := &Service{deps: Dependencies{Store: f.State, ReadScope: scope}}
	original, err := runner.originalLaunch(ctx, f.Reservation)
	if err != nil || scope.Actor.Kind != "service" || scope.Actor == f.Reservation.RequestedBy {
		t.Fatal("real runner could not read its protected original launch receipt", err)
	}
	originalJSON, err := api.CanonicalJSON(fx.JSON(t, original))
	if err != nil {
		t.Fatal(err)
	}
	admittedJSON, err := api.CanonicalJSON(fx.JSON(t, f.Human.Request))
	if err != nil || !bytes.Equal(originalJSON, admittedJSON) {
		t.Fatal("real runner changed the admitted original request", err)
	}
	receipt, err := f.State.LaunchReceipt(ctx, scope, api.LaunchReceiptRequest{ReservationID: f.Reservation.ID})
	if err != nil || receipt.Actor != f.Human.Actor || receipt.Operation.ID != f.Reservation.OperationID || !bytes.Equal(receipt.RawRequest, f.Raw) {
		t.Fatal("private receipt read lost the exact admitted owner and bytes", err)
	}
	key := api.RequestKey{Method: original.Method, IdempotencyKey: original.IdempotencyKey, RequestSHA256: original.RequestSHA256}
	_, err = f.State.LookupReceipt(ctx, f.Execution, key)
	wantCode(t, err, api.CodeNotFound)
	public, err := f.State.LookupReceipt(ctx, f.Human, key)
	if err != nil || !reflect.DeepEqual(public, receipt) {
		t.Fatal("public receipt owner read changed its retained result", err)
	}
	foreign := scope
	foreign.Actor.ID = fx.ID(t)
	_, err = f.State.LaunchReceipt(ctx, foreign, api.LaunchReceiptRequest{ReservationID: f.Reservation.ID})
	wantCode(t, err, api.CodeUnauthenticated)
}

func TestLaunchReceiptRetainedOwner(t *testing.T) {
	for _, mutation := range []string{"another_human", "other_reservation", "other_operation"} {
		t.Run(mutation, func(t *testing.T) {
			f := fx.New(t)
			request := f.ReservationRequest(t)
			f.Reserve(t)
			owner := struct {
				Request       api.LaunchReservationRequest
				ReservationID api.ID
				Actor         api.Actor
			}{Request: request, ReservationID: f.Reservation.ID, Actor: f.Human.Actor}
			switch mutation {
			case "another_human":
				owner.Actor.ID = fx.ID(t)
			case "other_reservation":
				owner.ReservationID = fx.ID(t)
			case "other_operation":
				owner.Request.OperationID = fx.ID(t)
			}
			// The real writer verifies immutable reservation ownership at open.
			// A substituted protected row cannot become a usable receipt reader.
			healthy, verifyErr := f.State.Verify(context.Background(), api.VerifyRequest{Scope: "all"})
			if verifyErr != nil || !healthy.OK {
				t.Fatal("receipt owner control did not start from verified real state", verifyErr)
			}
			f.Corrupt(t, "launch_operation", f.Reservation.OperationID, 1, owner)
			reopened, openErr := storeport.New(f.Deps)
			if reopened != nil {
				t.Cleanup(func() {
					if err := reopened.Close(); err != nil {
						t.Error(err)
					}
				})
				t.Fatal("real writer reopened a substituted retained receipt owner")
			}
			wantCode(t, openErr, api.CodeIntegrity)
			runner := &Service{deps: Dependencies{Store: f.State, ReadScope: f.Execution}}
			original, err := runner.originalLaunch(context.Background(), f.Reservation)
			wantCode(t, err, api.CodeUnavailable)
			if !reflect.DeepEqual(original, api.Request{}) {
				t.Fatal("real runner accepted a substituted retained receipt owner")
			}
		})
	}
}
