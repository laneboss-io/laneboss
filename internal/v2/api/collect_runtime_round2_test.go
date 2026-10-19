package api

import (
	"context"
	"encoding/json"
	"testing"
)

func TestCollectRuntimeReviewAccounting(t *testing.T) {
	for _, state := range []string{"present", "absent"} {
		t.Run(state, func(t *testing.T) {
			job, inventory, receipt, model := collectionFixture(t)
			object := &inventory.Objects[7]
			object.Role, object.OwnerLifeID, object.OwnershipGeneration = "runtime", "", 0
			result := &receipt.Objects[7]
			if state == "absent" {
				delete(model.objects, object.Ref.ID)
				for _, read := range []*ObjectReadback{&result.Before, &result.After} {
					read.State, read.Identity, read.SHA256, read.Bytes = "absent", "", "", 0
				}
			}
			model.blobs[inventory.Manifest.ID] = collectionInventory(t, &inventory)
			model.blobs[receipt.Manifest.ID] = collectionReceipt(t, &receipt)
			model.inventory, model.receipt = inventory, cloneCleanupReceipt(receipt)
			model.journals[result.ObjectID] = *result
			verified, err := VerifyCleanup(context.Background(), model, job, inventory, receipt, model.clock)
			if err != nil {
				t.Fatal("retain-only runtime readback was refused", state, err)
			}
			lane, event, outcome := collectionCompletion(t, job, receipt)
			var payload CleanEvent
			if err := json.Unmarshal(event.Payload, &payload); err != nil {
				t.Fatal(err)
			}
			payload.UnownedRetained = UnownedRetained{}
			event.Payload = initialRuntimeJSON(t, payload)
			if err := ValidateCleanupCompletion(job, inventory, verified, lane, event, outcome, model.clock.Now()); err != nil {
				t.Fatal("vendor runtime bytes inflated the unowned-data report", err)
			}
			changed := cloneCleanupReceipt(receipt)
			changed.Objects[7].Action = "remove"
			collectionReceipt(t, &changed)
			if err := ValidateCleanupReceipt(job, inventory, changed, model.clock.Now()); err == nil {
				t.Fatal("historical runtime acquired deletion authority")
			}
		})
	}
}

func initialRuntimeJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
