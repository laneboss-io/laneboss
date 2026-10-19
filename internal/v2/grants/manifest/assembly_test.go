package manifest

import (
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func assemblyFixture() api.ObjectAssembly {
	return api.ObjectAssembly{SHA256: Hash([]byte("assembled")), Bytes: api.MaxObjectBytes + 1,
		Parts: []api.BlobRef{
			{ID: "part-one", Class: "artifact", Bytes: api.MaxObjectBytes, SHA256: Hash([]byte("one"))},
			{ID: "part-two", Class: "artifact", Bytes: 1, SHA256: Hash([]byte("two"))},
		}}
}

func TestAssemblyShape(t *testing.T) {
	// This validates manifest structure only; these refs do not claim real bytes.
	for _, item := range []struct {
		name   string
		mutate func(*api.ObjectAssembly)
	}{
		{"digest", func(a *api.ObjectAssembly) { a.SHA256 = "invalid" }},
		{"small", func(a *api.ObjectAssembly) { a.Bytes = 2 }},
		{"single", func(a *api.ObjectAssembly) { a.Parts = a.Parts[:1] }},
		{"part-class", func(a *api.ObjectAssembly) { a.Parts[1].Class = "policy" }},
		{"part-empty", func(a *api.ObjectAssembly) { a.Parts[1].Bytes = 0 }},
		{"part-large", func(a *api.ObjectAssembly) { a.Parts[0].Bytes++ }},
		{"total", func(a *api.ObjectAssembly) { a.Bytes++ }},
	} {
		t.Run(item.name, func(t *testing.T) {
			value := assemblyFixture()
			if err := Assembly(value); err != nil {
				t.Fatal("valid assembly shape was rejected", err)
			}
			item.mutate(&value)
			bad(t, Assembly(value))
		})
	}
}

func TestAssemblyEntry(t *testing.T) {
	assembly := assemblyFixture()
	file := api.ObjectEntry{Path: "large.bin", Kind: "file", Mode: 0644, Assembly: &assembly}
	object := api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{file}}
	if err := Object(object); err != nil {
		t.Fatal("valid assembly entry was rejected", err)
	}
	for _, kind := range []string{"file", "directory", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			entry := file
			entry.Kind = kind
			ref := assembly.Parts[0]
			if kind == "file" {
				entry.Content = &ref
			}
			if kind == "symlink" {
				entry.LinkTarget = "target.bin"
			}
			target := api.ObjectEntry{Path: "target.bin", Kind: "file", Mode: 0644, Content: &ref}
			bad(t, Object(api.ObjectManifest{Schema: object.Schema, Entries: []api.ObjectEntry{entry, target}}))
		})
	}
}
