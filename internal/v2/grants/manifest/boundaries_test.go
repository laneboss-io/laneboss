package manifest

import (
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestGitAdministration(t *testing.T) {
	ref := api.BlobRef{ID: "file", SHA256: Hash([]byte("bytes")), Bytes: 5, Class: "artifact"}
	for _, item := range []struct{ name, path string }{
		{"pointer", ".git"}, {"common", ".git/commondir"},
		{"alternates", ".git/objects/info/alternates"}, {"refs", ".git/refs/heads/private"},
		{"config", "repo/.git/config"}, {"hook", "repo/.git/hooks/pre-commit"},
	} {
		t.Run(item.name, func(t *testing.T) {
			object := api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{
				{Path: item.path, Kind: "file", Mode: 0644, Content: &ref},
			}}
			bad(t, Object(object))
		})
	}
	ordinary := api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{
		{Path: "repo/source.c", Kind: "file", Mode: 0644, Content: &ref},
	}}
	if err := Object(ordinary); err != nil {
		t.Fatal("ordinary repository data was rejected", err)
	}
}

func TestSpecialObjectKinds(t *testing.T) {
	for _, kind := range []string{"hardlink", "mount", "socket", "fifo", "device"} {
		t.Run(kind, func(t *testing.T) {
			object := api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{{Path: "alias", Kind: kind, Mode: 0644}}}
			bad(t, Object(object))
		})
	}
}

func TestSubtreeSelection(t *testing.T) {
	object := tree()
	selected, err := Select(object, "child")
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 2 {
		t.Fatal("selected view contains extra or missing entries")
	}
	for _, entry := range selected {
		if !Beneath("child", entry.Path) {
			t.Fatal("selected view exposed an ungranted path")
		}
	}
	file, err := Select(object, "child/input")
	if err != nil || len(file) != 1 || file[0].Path != "child/input" {
		t.Fatal("file selection changed its scope", err)
	}
}
