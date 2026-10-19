//go:build linux

package admin

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestCollectRuntimeReviewMetadata(t *testing.T) {
	s, state, _, _ := seedLaunchFiles(t)
	var runtime api.RuntimeManifest
	if err := api.DecodeObject(state.objects[s.deps.RuntimeManifest.ID], &runtime); err != nil {
		t.Fatal(err)
	}
	raw := []byte("unexecuted vendor file with stable content")
	ref := api.BlobRef{ID: "claudock", Class: "artifact", Bytes: int64(len(raw)), SHA256: digestBytes(raw)}
	path := filepath.Join(s.files.base, "objects", "claudock")
	if err := os.WriteFile(path, raw, 0555); err != nil {
		t.Fatal(err)
	}
	runtime.Objects = append(runtime.Objects, api.RuntimeObject{ID: "claudock", Role: "claudock", RootID: "objects", RelativePath: "claudock", Content: ref, Mode: 0555})
	encoded := initialEncode(t, runtime)
	s.deps.RuntimeManifest.Bytes, s.deps.RuntimeManifest.SHA256 = int64(len(encoded)), digestBytes(encoded)
	manifestPath := filepath.Join(s.files.base, "manifest.json")
	if err := os.Chmod(manifestPath, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, encoded, 0444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(manifestPath, 0444); err != nil {
		t.Fatal(err)
	}
	pin, current, err := s.ReadCleanupRuntimeManifest(context.Background())
	if err != nil || pin != s.deps.RuntimeManifest || len(current.Objects) != len(runtime.Objects) || current.Objects[len(current.Objects)-1].Content != ref {
		t.Fatal("current runtime observation lost its exact protected namespace", err)
	}
	before, err := s.ReadCleanupRuntime(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().Add(time.Hour)
	if err := os.Chtimes(path, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	after, err := s.ReadCleanupRuntime(context.Background(), ref)
	if err != nil || before != after {
		t.Fatal("timestamp-only reinstall changed the retained runtime identity", err)
	}
}
