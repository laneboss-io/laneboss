package dataworker

import (
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

func TestReviewDiffIdentity(t *testing.T) {
	data := []byte(t.Name())
	left := api.BlobRef{ID: "base-object", Class: "artifact", Bytes: int64(len(data)), SHA256: manifest.Hash(data)}
	right := left
	right.ID = "native-freeze-object"
	base := api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{{Path: "file", Kind: "file", Mode: 0600, Content: &left}}}
	current := api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{{Path: "work/file", Kind: "file", Mode: 0600, Content: &right}}}
	diff := reviewTreeDiff(base, current, manifest.Hash([]byte("base")), manifest.Hash([]byte("current")))
	if len(diff.Changes) != 0 {
		t.Fatal("object identity alone became a workspace diff")
	}
	current.Entries[0].Mode = 0700
	diff = reviewTreeDiff(base, current, diff.Base, diff.Current)
	if len(diff.Changes) != 1 || diff.Changes[0].Before.Mode == diff.Changes[0].After.Mode {
		t.Fatal("actual mode change was omitted")
	}
	current.Entries[0].Mode = 0600
	current.Entries[0].Content = nil
	current.Entries[0].Assembly = &api.ObjectAssembly{SHA256: left.SHA256, Bytes: left.Bytes, Parts: []api.BlobRef{right}}
	diff = reviewTreeDiff(base, current, diff.Base, diff.Current)
	if len(diff.Changes) != 0 {
		t.Fatal("content partitioning alone became a workspace diff")
	}
}
