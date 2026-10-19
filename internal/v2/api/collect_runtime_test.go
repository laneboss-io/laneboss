package api

import "testing"

func TestCollectRuntimeInventory(t *testing.T) {
	job, inventory, _, model := collectionFixture(t)
	object := inventory.Objects[len(inventory.Objects)-1]
	object.Ref.ID, object.Ref.Class, object.Ref.Bytes = "installed-vendor", "artifact", MaxObjectBytes+1
	object.Role, object.OwnerLifeID, object.OwnershipGeneration = "runtime", "", 0
	inventory.Objects = append(inventory.Objects, object)
	collectionInventory(t, &inventory)
	if err := ValidateCleanupInventory(job, inventory, model.clock.Now()); err != nil {
		t.Fatal("measured installation file was limited as a SQL blob", err)
	}
	for _, fault := range []string{"owned", "generation", "class", "oversize", "empty", "sql-blob"} {
		changed := inventory
		changed.Objects = append([]CleanupObject{}, inventory.Objects...)
		o := &changed.Objects[len(changed.Objects)-1]
		switch fault {
		case "owned":
			o.OwnerLifeID, o.OwnershipGeneration = job.Intent.Cause.Target.LifeID, 1
		case "generation":
			o.OwnershipGeneration = 1
		case "class":
			o.Ref.Class = "manifest"
		case "oversize":
			o.Ref.Bytes = MaxVendorBytes + 1
		case "empty":
			o.Ref.Bytes = 0
		case "sql-blob":
			o.Role = "history"
		}
		collectionInventory(t, &changed)
		if err := ValidateCleanupInventory(job, changed, model.clock.Now()); err == nil {
			t.Fatal("runtime file widened collection authority", fault)
		}
	}
}
