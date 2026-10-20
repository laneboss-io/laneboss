//go:build linux

package store_test

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/store"
)

func TestInviteCaptureIsolation(t *testing.T) {
	f := capInviteFixture(t)
	owner := capHuman(t, f, f.Human.Actor)
	want := capAppend(t, f)
	capRead(t, f, owner, want, "")
	enrollment, pending := store.InviteForTest(t, f.State, owner)
	reader := capAdmissionReader(t, f, enrollment)
	for id := range want {
		chunk, err := f.State.Blob(context.Background(), reader, api.BlobReadRequest{ObjectID: id, Limit: api.MaxChunkBytes})
		if err == nil || len(chunk.Data) != 0 {
			t.Fatal("pending human read a real capture", err)
		}
	}
	approved := store.DecideForTest(t, f.State, owner, pending, "approve")
	if approved.State != "active" {
		t.Fatal("approval did not activate registration")
	}
	if _, err := f.State.Enrollment(context.Background(), reader); err != nil {
		t.Fatal("approved human enrollment control failed", err)
	}
	// These calls reach Blob, ObjectMetadata and lane.attach for the same actual
	// captured stdout/stderr as the owner's successful control above.
	capRead(t, f, reader, want, api.CodeNotFound)
	capRead(t, f, owner, want, "")
}

func TestInviteWorkerAdmin(t *testing.T) {
	f := capInviteFixture(t)
	ctx := context.Background()
	// The producer is a valid current worker with a real retained lease and
	// capture binding; this control does not relabel a human connection.
	state, err := f.State.CaptureState(ctx, f.Worker, f.Plan.Capture.ID)
	if err != nil || state.Binding.ProducerID != f.Worker.Actor.ID {
		t.Fatal("current worker positive control failed", err)
	}
	port, ok := any(f.State).(api.HumanAdmissionStore)
	if !ok {
		t.Fatal("later human invite/redeem/approve port is absent")
	}
	owner := capHuman(t, f, f.Human.Actor)
	_, pending := store.InviteForTest(t, f.State, owner)
	for _, request := range []api.HumanAccessRequest{
		{Action: "invite", Role: "human"},
		{Action: "approve", InviteID: pending.ID, Fingerprint: pending.Fingerprint, ExpectedGeneration: pending.Generation},
	} {
		worker := capAdminRequest(t, f.Worker, request)
		if _, err := port.PrepareHumanChange(ctx, worker, request); err == nil {
			t.Fatal("current worker reached human " + request.Action)
		}
	}
}
