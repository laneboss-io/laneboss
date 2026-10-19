package admin

import (
	"bytes"
	"encoding/json"
	"path"
	"reflect"
	"sort"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
)

const dataEntryLimit = 65536

func canonicalValue(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return api.CanonicalJSON(raw)
}

func dataRelative(name string) bool {
	if name == "" || len(name) > 4096 || strings.Count(name, "/") > 64 || strings.ContainsAny(name, "\\\x00") || path.IsAbs(name) || path.Clean(name) != name || name == ".." || strings.HasPrefix(name, "../") {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if strings.EqualFold(part, ".git") {
			return false
		}
	}
	return true
}

func dataRefs(e api.ObjectEntry) []api.BlobRef {
	if e.Content != nil {
		return []api.BlobRef{*e.Content}
	}
	if e.Assembly != nil {
		return e.Assembly.Parts
	}
	return nil
}

func dataSize(e api.ObjectEntry) int64 {
	if e.Content != nil {
		return e.Content.Bytes
	}
	if e.Assembly != nil {
		return e.Assembly.Bytes
	}
	return 0
}

func dataManifest(raw []byte, ceiling uint64) (api.ObjectManifest, error) {
	var manifest api.ObjectManifest
	if len(raw) == 0 || len(raw) > api.MaxFrameBytes {
		return manifest, failure(api.CodeInvalid, "data manifest exceeds its bound")
	}
	if err := api.DecodeObject(raw, &manifest); err != nil {
		return manifest, err
	}
	if manifest.Schema != "laneboss.objects.v2" || len(manifest.Entries) > dataEntryLimit {
		return manifest, failure(api.CodeInvalid, "invalid data tree schema or entry bound")
	}
	entries := map[string]api.ObjectEntry{}
	var total uint64
	for _, e := range manifest.Entries {
		if !dataRelative(e.Path) {
			return manifest, failure(api.CodeInvalid, "data tree has a noncanonical or administrative path")
		}
		if _, found := entries[e.Path]; found {
			return manifest, failure(api.CodeInvalid, "data tree aliases a path")
		}
		entries[e.Path] = e
		switch e.Kind {
		case "directory":
			if e.Mode&^0777 != 0 || e.Mode&0022 != 0 || e.Mode&0500 != 0500 || e.Content != nil || e.Assembly != nil || e.LinkTarget != "" || e.Path == "." && e.Mode != 0700 {
				return manifest, failure(api.CodeInvalid, "data directory lacks supported private permissions")
			}
		case "symlink":
			if e.Path == "." || e.Mode != 0777 || e.Content != nil || e.Assembly != nil || e.LinkTarget == "" || strings.ContainsAny(e.LinkTarget, "\\\x00") || path.IsAbs(e.LinkTarget) || !dataRelative(path.Join(path.Dir(e.Path), e.LinkTarget)) {
				return manifest, failure(api.CodeInvalid, "data symlink escapes its granted tree")
			}
		case "file":
			if e.Path == "." || e.Mode&^0777 != 0 || e.Mode&0022 != 0 || e.Mode&0400 == 0 || (e.Content == nil) == (e.Assembly == nil) || e.LinkTarget != "" {
				return manifest, failure(api.CodeInvalid, "invalid data file permissions or content")
			}
			size := dataSize(e)
			if size < 0 || uint64(size) > ceiling-total {
				return manifest, failure(api.CodeBudget, "data tree exceeds its disk ceiling")
			}
			total += uint64(size)
			var parts int64
			refs := dataRefs(e)
			if len(refs) == 0 || len(refs) > dataEntryLimit {
				return manifest, failure(api.CodeInvalid, "data file lacks bounded content")
			}
			for _, ref := range refs {
				if !validID(ref.ID) || !validDigest(ref.SHA256) || ref.Bytes < 0 || ref.Bytes > size-parts {
					return manifest, failure(api.CodeInvalid, "data content reference differs from its length")
				}
				parts += ref.Bytes
			}
			if parts != size || e.Assembly != nil && !validDigest(e.Assembly.SHA256) {
				return manifest, failure(api.CodeInvalid, "data assembly differs from its parts")
			}
		default:
			return manifest, failure(api.CodeInvalid, "data tree contains an unsupported inode kind")
		}
	}
	for _, e := range manifest.Entries {
		for parent := path.Dir(e.Path); parent != "."; parent = path.Dir(parent) {
			if entry, found := entries[parent]; found && entry.Kind != "directory" {
				return manifest, failure(api.CodeInvalid, "data tree has a symlink or file parent")
			}
		}
	}
	return manifest, nil
}

func sameDataTree(a, b api.ObjectManifest) bool {
	shape := func(value api.ObjectManifest) []api.ObjectEntry {
		result := append([]api.ObjectEntry{}, value.Entries...)
		for i := range result {
			if result[i].Content != nil {
				ref := *result[i].Content
				ref.ID = ""
				result[i].Content = &ref
			}
			if result[i].Assembly != nil {
				assembly := *result[i].Assembly
				assembly.Parts = append([]api.BlobRef{}, assembly.Parts...)
				for j := range assembly.Parts {
					assembly.Parts[j].ID = ""
				}
				result[i].Assembly = &assembly
			}
		}
		sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
		return result
	}
	return reflect.DeepEqual(shape(a), shape(b))
}

func dataCanonical(raw []byte) error {
	canonical, err := api.CanonicalJSON(raw)
	if err != nil {
		return err
	}
	if !bytes.Equal(canonical, raw) {
		return failure(api.CodeIntegrity, "worker result is not the exact acknowledged JCS bytes")
	}
	return nil
}

func dataTerminal(observation api.ProcessObservation, handle api.ProcessHandle) error {
	if observation.Handle != handle || observation.State != "exited" || observation.ExitCode == nil || *observation.ExitCode != 0 || observation.Signal != nil || observation.Survivors == nil || *observation.Survivors != 0 {
		return failure(api.CodeContainmentUnknown, "data result needs measured terminal zero")
	}
	return nil
}
