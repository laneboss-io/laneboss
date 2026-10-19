package store

import (
	"encoding/json"
	"regexp"
	"sort"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/policy"
	"laneboss.io/laneboss/internal/v2/templates"
)

type orgPublicationMarker struct {
	Schema      string
	Config      string
	OperationID api.ID
	EffectID    api.ID
	Renderer    api.Executable
	Receipt     api.ChangeReceipt
	Snapshot    api.OrgSnapshot
}

var changedRolePath = regexp.MustCompile(`^\.laneboss/L([3-6])/roles/([^/]+)\.(md|toml)$`)

// Match the templates package's private templateSourceKind classification so
// new source paths retain the semantic kinds its approved reader requires.
func changeSourceKind(name string) string {
	switch name {
	case templates.OrgTemplatePath:
		return "prompt"
	case templates.OrgDriversPath:
		return "drivers"
	case templates.WorkflowPath:
		return "policy"
	}
	if match := changedRolePath.FindStringSubmatch(name); match != nil {
		if match[3] == "md" {
			return "prompt"
		}
		return "drivers"
	}
	return ""
}

func nextOrgSnapshot(job orgApply, receipt api.ChangeReceipt) (api.OrgSnapshot, error) {
	next := job.Snapshot
	next.Ref.Generation = job.Change.BaseGeneration + 1
	next.PublishedBy, next.PublishedAt = job.Deferred.OperationID, receipt.AppliedAt
	groups := [2][]api.ResourceFile{}
	for group, base := range [][]api.ResourceFile{job.Snapshot.Sources, job.Snapshot.Derived} {
		files := map[string]api.ResourceFile{}
		for _, file := range base {
			file.Source.Generation = next.Ref.Generation
			files[file.Source.Path] = file
		}
		deltas := job.Change.Files
		if group == 1 {
			deltas = job.Change.Derived
		}
		for _, delta := range deltas {
			if delta.Action == "delete" {
				delete(files, delta.Path)
				continue
			}
			if delta.After == nil {
				return api.OrgSnapshot{}, fault(api.CodeIntegrity, "publication delta omitted its approved after bytes")
			}
			file, exists := files[delta.Path]
			if !exists {
				kind := "source"
				if group == 1 {
					kind = "file"
				} else if semantic := changeSourceKind(delta.Path); semantic != "" {
					kind = semantic
				} else if policy.CanonicalSourcePath(delta.Path) {
					kind = "policy"
				}
				file = api.ResourceFile{Source: api.SourceRef{ID: api.ID("source-" + hash([]byte(string(job.Change.OrgID) + "\x00" + delta.Path))[:32]), Path: delta.Path}, Kind: kind}
			}
			file.Content, file.Mode, file.RevisionGeneration = *delta.After, delta.Mode, next.Ref.Generation
			file.Source.SHA256, file.Source.Generation = delta.After.SHA256, next.Ref.Generation
			files[delta.Path] = file
		}
		groups[group] = make([]api.ResourceFile, 0, len(files))
		for _, file := range files {
			groups[group] = append(groups[group], file)
		}
		sort.Slice(groups[group], func(i, j int) bool { return groups[group][i].Source.Path < groups[group][j].Source.Path })
	}
	next.Sources, next.Derived = groups[0], groups[1]
	raw, err := json.Marshal(struct {
		Sources, Derived []api.ResourceFile
		Renderer         api.Executable
		Ownership        api.BlobRef
	}{next.Sources, next.Derived, next.Renderer, next.OwnershipManifest})
	if err != nil {
		return api.OrgSnapshot{}, err
	}
	raw, err = api.CanonicalJSON(raw)
	if err != nil {
		return api.OrgSnapshot{}, err
	}
	next.Ref.ManifestSHA256 = api.Digest(hash(raw))
	return next, nil
}

func publicationMarker(job orgApply, receipt api.ChangeReceipt) (orgPublicationMarker, error) {
	snapshot, err := nextOrgSnapshot(job, receipt)
	if err != nil {
		return orgPublicationMarker{}, err
	}
	return orgPublicationMarker{Schema: "laneboss.org-publication.v2", Config: job.Change.Config, OperationID: job.Deferred.OperationID, EffectID: job.Deferred.EffectID, Renderer: job.Change.Renderer, Receipt: receipt, Snapshot: snapshot}, nil
}
