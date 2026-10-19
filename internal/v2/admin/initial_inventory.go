package admin

import (
	"crypto/sha256"
	"encoding/hex"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

func initialTree(raw []byte, refs map[api.ID]api.BlobRef, objects map[api.ID][]byte) (api.ObjectManifest, error) {
	var tree api.ObjectManifest
	if err := manifest.Decode(raw, &tree); err != nil {
		return tree, err
	}
	if err := manifest.Object(tree); err != nil {
		return tree, err
	}
	if _, err := dataManifest(raw, 64<<20); err != nil {
		return tree, err
	}
	for _, entry := range tree.Entries {
		complete := sha256.New()
		var size int64
		for _, ref := range dataRefs(entry) {
			if refs[ref.ID] != ref {
				return tree, failure(api.CodeIntegrity, "initial tree content is not retained")
			}
			if _, err := complete.Write(objects[ref.ID]); err != nil {
				return tree, err
			}
			size += ref.Bytes
		}
		if entry.Assembly != nil && (entry.Assembly.Bytes != size || entry.Assembly.SHA256 != api.Digest(hex.EncodeToString(complete.Sum(nil)))) {
			return tree, failure(api.CodeIntegrity, "initial tree assembly bytes differ")
		}
	}
	return tree, nil
}

func initialSourceManifest(b initialBundle, refs map[api.ID]api.BlobRef) error {
	ref := b.manifest.SourceManifest
	if b.sources.Ref.ManifestSHA256 != ref.SHA256 {
		return failure(api.CodeIntegrity, "initial source generation lacks its exact manifest digest")
	}
	tree, err := initialTree(b.objects[ref.ID], refs, b.objects)
	if err != nil {
		return err
	}
	if len(tree.Entries) != len(b.sources.Sources) {
		return failure(api.CodeInvalid, "initial source manifest differs from its inventory")
	}
	files := map[string]api.ResourceFile{}
	for _, f := range b.sources.Sources {
		files[f.Source.Path] = f
	}
	for _, selected := range []struct {
		kind string
		file api.TemplateSource
	}{{"prompt", b.manifest.L5Sources.Prompt}, {"drivers", b.manifest.L5Sources.Drivers}} {
		f, found := files[selected.file.Source.Path]
		if !found || f.Kind != selected.kind || f.Source != selected.file.Source || f.Content != selected.file.Content {
			return failure(api.CodeIntegrity, "initial L5 template selection differs from its retained source inventory")
		}
	}
	for _, e := range tree.Entries {
		f, found := files[e.Path]
		if !found || e.Kind != "file" || e.Mode != f.Mode || e.Content == nil || *e.Content != f.Content {
			return failure(api.CodeIntegrity, "initial source manifest changed a source pin")
		}
	}
	ownership := b.sources.OwnershipManifest
	if refs[ownership.ID] != ownership || ownership.Class != "manifest" {
		return failure(api.CodeIntegrity, "initial ownership manifest is not retained")
	}
	_, err = initialTree(b.objects[ownership.ID], refs, b.objects)
	return err
}

func initialRuntime(runtime api.RuntimeManifest, refs map[api.ID]api.BlobRef) error {
	if runtime.Schema != "laneboss.runtime.v2" || runtime.Generation != 1 || runtime.Bindings == nil || len(runtime.Bindings) != 0 || len(runtime.Objects) == 0 || len(runtime.Objects) > 128 {
		return failure(api.CodeInvalid, "initial runtime is not a fresh explicit generation")
	}
	seen := map[api.ID]bool{}
	paths := map[string]bool{}
	for _, object := range runtime.Objects {
		key := string(object.RootID) + "/" + object.RelativePath
		if !validID(object.ID) || !validID(object.RootID) || !dataRelative(object.RelativePath) || object.RelativePath == "." || seen[object.ID] || paths[key] ||
			(object.Mode != 0444 && object.Mode != 0555) || !runtimeRef(object) {
			return failure(api.CodeIntegrity, "initial runtime lacks its unique retained immutable object")
		}
		if vendorRuntime(object) {
			for _, ref := range refs {
				if ref.ID == object.Content.ID || ref.SHA256 == object.Content.SHA256 {
					return failure(api.CodeIntegrity, "vendor executable must remain an installation file")
				}
			}
		} else if refs[object.Content.ID] != object.Content {
			return failure(api.CodeIntegrity, "initial runtime lacks its unique retained immutable object")
		}
		seen[object.ID], paths[key] = true, true
	}
	for _, executable := range []api.Executable{runtime.Artifact, runtime.Bootstrap} {
		if err := initialExecutable(runtime, executable); err != nil {
			return err
		}
	}
	return nil
}

func vendorRuntime(object api.RuntimeObject) bool {
	return object.Role == "claudock" || object.Role == "claude"
}

func runtimeLimit(object api.RuntimeObject) int64 {
	if vendorRuntime(object) {
		return api.MaxVendorBytes
	}
	return api.MaxObjectBytes
}

func runtimeRef(object api.RuntimeObject) bool {
	ref := object.Content
	return validID(ref.ID) && validDigest(ref.SHA256) && ref.Class == "artifact" && ref.Bytes > 0 && ref.Bytes <= runtimeLimit(object) &&
		(!vendorRuntime(object) || object.ID == api.ID(object.Role) && object.RelativePath == object.Role && object.Mode == 0555)
}

// Only the reachable immutable bundle may be imported. An unrelated manifest
// cannot hide as an opaque object beside the validated document selections.
func initialClosure(b initialBundle, runtime api.RuntimeManifest, launch api.LaunchEnrollment, refs map[api.ID]api.BlobRef) error {
	m := b.manifest
	used := map[api.ID]bool{}
	for _, r := range []api.BlobRef{m.Runtime, m.Launch, m.Policy, m.Sources, m.SourceManifest, m.Profiles, m.Task, b.sources.OwnershipManifest} {
		used[r.ID] = true
	}
	for _, r := range runtime.Objects {
		if !vendorRuntime(r) {
			used[r.Content.ID] = true
		}
	}
	for _, r := range b.sources.Sources {
		used[r.Content.ID] = true
	}
	trees := []api.BlobRef{m.SourceManifest, b.sources.OwnershipManifest}
	for _, p := range launch.Projects {
		trees = append(trees, p.Object)
	}
	for _, g := range b.profiles.Data {
		trees = append(trees, refs[g.SourceObjectID])
	}
	for _, r := range trees {
		used[r.ID] = true
		tree, err := initialTree(b.objects[r.ID], refs, b.objects)
		if err != nil {
			return err
		}
		for _, e := range tree.Entries {
			for _, part := range dataRefs(e) {
				used[part.ID] = true
			}
		}
	}
	if len(used) != len(refs) {
		return failure(api.CodeInvalid, "initial publication contains an unselected object")
	}
	return nil
}
