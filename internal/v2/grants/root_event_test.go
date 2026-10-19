package grants

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func TestRootGrantIssuedEvent(t *testing.T) {
	f, backend, request, _ := rootProfileCase(t)
	scope := humanScope(t, f, "grants.root", request)
	rootProfileCommit(t, f, backend, scope)
	commit := f.store.onTransaction
	var emitted api.Event
	f.store.onTransaction = func(tx api.Transaction) (api.Commit, error) {
		if len(tx.Events) != 1 || tx.Events[0].Kind != "grants.issued" || !wire.ValidID(string(tx.Events[0].ID)) {
			t.Fatal("root grant producer omitted its valid issuance event ID")
		}
		emitted = tx.Events[0]
		if emitted.Actor != scope.Actor || emitted.RequestedBy != scope.Actor || emitted.RequestID != scope.Request.RequestID || emitted.LifeID != tx.Writes.Grants[0].LifeID {
			t.Fatal("root grant event changed its authenticated issuance context")
		}
		// The store owns these assignments. Keep every producer field,
		// particularly ID, and pass the resulting event through its actual
		// strict decoder instead of relying on the component writer's shape.
		settled := emitted
		settled.Seq = 1
		settled.OperationID = "root-operation"
		settled.RecordedAt = api.Timestamp(f.clock.Now().UTC().Format(time.RFC3339Nano))
		settled.RequestedAt, settled.ObservedAt = settled.RecordedAt, settled.RecordedAt
		settled.StarterChain = []api.ID{}
		if err := wire.ValidateEvent(settled); err != nil {
			t.Fatal("root grant event failed the production wire validator", err)
		}
		var payload api.GrantEvent
		if err := api.DecodeObject(settled.Payload, &payload); err != nil || !reflect.DeepEqual(payload.GrantSet, tx.Writes.Grants[0]) {
			t.Fatal("root grant event lost the exact issued grant set", err)
		}
		// The same strict validator must still reject the original omission.
		settled.ID = ""
		var typed *api.Error
		if err := wire.ValidateEvent(settled); !errors.As(err, &typed) || typed.Code != api.CodeInvalid || typed.Message != "invalid object ID" {
			t.Fatal("empty issuance event ID was accepted by the strict validator", err)
		}
		return commit(tx)
	}
	result, err := f.service.GrantsRoot(context.Background(), scope, request)
	if err != nil || result.ID == "" || emitted.ID == "" || f.store.transactions != 1 {
		t.Fatal("root grant issuance did not preserve its emitted identity", err)
	}
}
