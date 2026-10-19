package grants

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

func TestBlobDigest(t *testing.T) {
	f := newFixture(t)
	// Keep committed metadata and the requested reference equal. Only the
	// physical bytes are corrupted, with a valid hash on each returned chunk.
	ref := api.BlobRef{ID: "input-bytes", Bytes: 5, SHA256: manifest.Hash([]byte("input")), Class: "artifact"}
	f.store.blobs[ref.ID] = []byte("other")
	_, err := f.service.readRef(context.Background(), f.scope, ref)
	expectCode(t, err, api.CodeIntegrity)
}
