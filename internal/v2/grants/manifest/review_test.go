package manifest

import (
	"strconv"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestIntermediateLinkEscape(t *testing.T) {
	for _, target := range []string{"../child/input", "../private/../child/input"} {
		object := tree()
		object.Entries = append(object.Entries, api.ObjectEntry{Path: "child/leak", Kind: "symlink", LinkTarget: target})
		if err := Object(object); err != nil {
			t.Fatal("whole-object link control failed", err)
		}
		_, err := Select(object, "child")
		bad(t, err)
	}
}

func TestDirectoryLinkCycles(t *testing.T) {
	for _, item := range []struct{ name, target string }{{"self", "."}, {"parent", ".."}, {"sibling", ""}} {
		t.Run(item.name, func(t *testing.T) {
			object := tree()
			if item.name == "sibling" {
				object.Entries = append(object.Entries,
					api.ObjectEntry{Path: "child/to-private", Kind: "symlink", LinkTarget: "../private"},
					api.ObjectEntry{Path: "private/to-child", Kind: "symlink", LinkTarget: "../child"})
			} else {
				object.Entries = append(object.Entries, api.ObjectEntry{Path: "child/sub/loop", Kind: "symlink", LinkTarget: item.target})
			}
			bad(t, Object(object))
		})
	}
}
func TestFilesystemAliases(t *testing.T) {
	t.Run("case", func(t *testing.T) {
		object := tree()
		duplicate := object.Entries[0]
		duplicate.Path = "CHILD/INPUT"
		object.Entries = append(object.Entries, duplicate)
		if err := Object(object); err == nil {
			t.Fatal("filesystem case alias was accepted")
		} else {
			bad(t, err)
		}
	})
	t.Run("root", func(t *testing.T) {
		object := tree()
		object.Entries[0].Path = "."
		object.Entries = object.Entries[:1]
		if err := Object(object); err == nil {
			t.Fatal("filesystem root file was accepted")
		} else {
			bad(t, err)
		}
	})
}
func TestImplicitDirectoryBound(t *testing.T) {
	ref := api.BlobRef{ID: "bytes", Class: "artifact", Bytes: 1, SHA256: Hash([]byte("x"))}
	object := api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{}}
	for i := 0; i < MaxEntries/2+1; i++ {
		object.Entries = append(object.Entries, api.ObjectEntry{Path: "dir-" + strconv.Itoa(i) + "/file", Kind: "file", Content: &ref})
	}
	bad(t, Object(object))
}
