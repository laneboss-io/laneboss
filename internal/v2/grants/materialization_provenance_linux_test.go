//go:build linux

package grants_test

import (
	"bytes"
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	datafx "laneboss.io/laneboss/internal/v2/store/matfx"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// The worker identity/projection are explicit component facts, but every
// reservation, claim, input, acknowledgement and metadata read uses SQLite's
// real store API. No protected row is patched or manufactured for this test.
func TestMaterializationWriterProvenance(t *testing.T) {
	d := datafx.NewData(t)
	d.Open(t)
	ctx := context.Background()
	_, raw := d.Result(t)
	ack, err := d.F.State.WorkerResult(ctx, d.Worker, d.Submission(raw))
	if err != nil {
		t.Fatal("real materialization writer rejected its original worker", err)
	}
	view, err := d.F.State.BeginRead(ctx, d.F.Execution)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := view.Close(); err != nil {
			t.Error(err)
		}
	}()
	scope := d.F.Execution
	scope.ReadView = view
	metadata, err := d.F.State.ObjectMetadata(ctx, scope, ack.Result.ID)
	if err != nil || metadata.Ref != ack.Result || metadata.Origin != "service" ||
		metadata.SourceOperationID != d.Stage.Reservation.OperationID || metadata.ACL.Config != scope.Config ||
		metadata.ACL.Audience != "private" || metadata.ACL.LifeID != d.Stage.Reservation.Target.LifeID ||
		metadata.ACL.Owner.Kind != "service" || metadata.ACL.Owner.ID == "" || metadata.ACL.Generation != 1 || len(metadata.ACL.Participants) != 0 {
		t.Fatal("real worker result lost its private operation provenance", err)
	}
	chunk, err := d.F.State.Blob(ctx, scope, api.BlobReadRequest{ObjectID: ack.Result.ID, Limit: api.MaxChunkBytes})
	if err != nil || !bytes.Equal(chunk.Data, raw) || chunk.SHA256 != fx.Digest(raw) || ack.Result.SHA256 != fx.Digest(raw) || ack.Result.Bytes != int64(len(raw)) {
		t.Fatal("real worker acknowledgement changed its committed result bytes", err)
	}
}
