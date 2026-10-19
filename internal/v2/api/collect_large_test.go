package api

import (
	"context"
	"fmt"
	"testing"
)

func TestCollectLargeProof(t *testing.T) {
	job, inventory, receipt, reads := collectionFixture(t)
	for n := 0; n < 4097; n++ {
		id := ID(fmt.Sprintf("large-owned-%d", n))
		object := inventory.Objects[0]
		object.Ref = collectionBlob(id, "artifact", []byte(id))
		object.Identity = "identity-" + string(id)
		result := receipt.Objects[0]
		result.ObjectID = id
		result.Before.ID, result.Before.ObjectID = ID("before-"+string(id)), id
		result.Before.Identity, result.Before.SHA256, result.Before.Bytes = object.Identity, object.Ref.SHA256, object.Ref.Bytes
		result.After.ID, result.After.ObjectID = ID("after-"+string(id)), id
		inventory.Objects = append(inventory.Objects, object)
		receipt.Objects = append(receipt.Objects, result)
		reads.journals[id] = result
	}
	input := collectionInventory(t, &inventory)
	output := collectionReceipt(t, &receipt)
	if len(input) <= MaxFrameBytes || len(output) <= MaxFrameBytes {
		t.Fatal("large cleanup fixture did not cross the RPC frame boundary")
	}
	reads.inventory, reads.receipt = inventory, cloneCleanupReceipt(receipt)
	reads.blobs[inventory.Manifest.ID], reads.blobs[receipt.Manifest.ID] = input, output
	verified, err := VerifyCleanup(context.Background(), reads, job, inventory, receipt, reads.clock)
	if err != nil {
		t.Fatal("large retained cleanup proof still used the RPC frame bound", err)
	}
	lane, event, outcome := collectionCompletion(t, job, receipt)
	if err := ValidateCleanupCompletion(job, inventory, verified, lane, event, outcome, reads.clock.Now()); err != nil {
		t.Fatal("large cleanup completion lost its complete proof", err)
	}
	delete(reads.journals, inventory.Objects[len(inventory.Objects)-1].Ref.ID)
	_, err = VerifyCleanup(context.Background(), reads, job, inventory, receipt, reads.clock)
	contractCode(t, err, CodeIntegrity, "large cleanup accepted a missing object journal")
}
