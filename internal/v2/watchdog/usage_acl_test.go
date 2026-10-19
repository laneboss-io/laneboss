package watchdog

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestBrokerUsageAudience(t *testing.T) {
	r := newRig(t)
	for _, id := range []api.ID{r.signal.UsageEvidence.ID} {
		meta := r.store.metadata[id]
		meta.ACL.Audience = "service"
		r.store.metadata[id] = meta
	}
	var envelope api.UsageWindowEvidence
	if err := decodePayload(r.store.blobs[r.signal.UsageEvidence.ID], &envelope); err != nil {
		t.Fatal(err)
	}
	meta := r.store.metadata[envelope.Raw.ID]
	meta.ACL.Audience = "service"
	r.store.metadata[envelope.Raw.ID] = meta
	if _, err := r.s.assess(context.Background(), r.signal); err != nil {
		t.Fatal("watchdog rejected broker-produced private service evidence", err)
	}
	for _, fault := range []string{"owner", "life", "participants", "audience"} {
		t.Run(fault, func(t *testing.T) {
			original := r.store.metadata[envelope.Raw.ID]
			changed := original
			switch fault {
			case "owner":
				changed.ACL.Owner.ID = "foreign-worker"
			case "life":
				changed.ACL.LifeID = "foreign-life"
			case "participants":
				changed.ACL.Participants = []api.ID{"lane-one"}
			case "audience":
				changed.ACL.Audience = "life"
			}
			r.store.metadata[envelope.Raw.ID] = changed
			_, err := r.s.assess(context.Background(), r.signal)
			requireCode(t, err, api.CodeIntegrity)
			r.store.metadata[envelope.Raw.ID] = original
		})
	}
}
