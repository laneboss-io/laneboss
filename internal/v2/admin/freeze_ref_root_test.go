//go:build linux && laneboss_root_canary

package admin

import (
	"encoding/json"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

// freezeRef is the job freeze object the store retains for this freeze: canonical JSON of the whole
// Freeze as a "manifest" object (store/archive.go), never the tree snapshot inside it.
func freezeRef(t *testing.T, f archivejob.Freeze) api.BlobRef {
	t.Helper()
	encoded, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := api.CanonicalJSON(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return api.BlobRef{ID: "archive-freeze-object", Class: "manifest", Bytes: int64(len(canonical)), SHA256: digestBytes(canonical)}
}
