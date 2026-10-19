package claudock

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestBrokerUsageOwner(t *testing.T) {
	f, capture := usageReady(t)
	e, _ := f.retainedUsage(t)
	selected, _ := f.launchRecord(t)
	endpoint, peer, err := f.launch.usageWorker(context.Background(), selected.Scope, e.WorkerLeaseID)
	if err != nil {
		t.Fatal(err)
	}
	producer, err := f.launch.WorkerBinding(context.Background(), endpoint, peer)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []api.ID{e.ID, e.Raw.ID} {
		var metadata api.ObjectMetadata
		if err := f.launch.read("meta-"+string(id), &metadata); err != nil {
			t.Fatal(err)
		}
		metadata.ACL.Owner = producer.Record.Actor
		f.launch.write("meta-"+string(id), metadata)
	}
	signal, err := f.service.LimitFromCapture(context.Background(), capture, f.observation)
	if err != nil || signal == nil {
		t.Fatal("runner rejected the broker's actual private worker-owned evidence", err)
	}
	for _, id := range []api.ID{e.ID, e.Raw.ID} {
		var metadata api.ObjectMetadata
		if err := f.launch.read("meta-"+string(id), &metadata); err != nil {
			t.Fatal(err)
		}
		original := metadata
		metadata.ACL.Owner.ID = "foreign-usage-producer"
		f.launch.write("meta-"+string(id), metadata)
		if signal, err := f.service.LimitFromCapture(context.Background(), capture, f.observation); err == nil || signal != nil {
			t.Fatal("runner accepted another worker's evidence")
		}
		f.launch.write("meta-"+string(id), original)
	}
}
