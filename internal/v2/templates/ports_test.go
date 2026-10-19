package templates_test

import (
	"context"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/templates"
)

func TestExactSnapshots(t *testing.T) {
	service, store, _, scope, request := component(t)
	briefing, err := service.BriefRender(context.Background(), scope, request)
	want := api.OrgSnapshotRequest{OrgID: store.snapshot.Ref.OrgID, Generation: store.snapshot.Ref.Generation}
	if err != nil || briefing.Markdown.ID == "" || len(store.snapshotRequests) != 1 || store.snapshotRequests[0] != want {
		t.Fatalf("render omitted its exact source snapshot selector: %v", err)
	}
	store.snapshotRequests = nil
	validation, err := service.OrgValidate(context.Background(), scope, api.OrgValidateRequest{Generation: want.Generation})
	if err != nil || !validation.Valid || validation.Problems == nil || len(validation.Problems) != 0 ||
		len(store.snapshotRequests) != 1 || store.snapshotRequests[0] != want {
		t.Fatalf("org validation omitted its exact source snapshot selector: %v", err)
	}
}

func TestInventorySelect(t *testing.T) {
	_, store, _, scope, request := component(t)
	selected, err := templates.SelectSources(scope, store.snapshot, request.Context)
	if err != nil || !reflect.DeepEqual(selected, store.selection) {
		t.Fatalf("inventory selection changed the exact committed source pair: %v", err)
	}
	files := []api.ResourceFile{}
	for _, file := range store.snapshot.Sources {
		if file.Source != selected.Local.Prompt.Source && file.Source != selected.Local.Drivers.Source {
			files = append(files, file)
		}
	}
	store.snapshot.Sources = files
	fallback, err := templates.SelectSources(scope, store.snapshot, request.Context)
	if err != nil || fallback.LocalStatus != "absent" || fallback.Local != nil || fallback.Org != selected.Org || fallback.Snapshot != selected.Snapshot {
		t.Fatalf("inventory selection did not preserve explicit org fallback: %v", err)
	}
	store.snapshot.Sources = append(files, api.ResourceFile{Source: selected.Local.Prompt.Source, Content: selected.Local.Prompt.Content, Kind: "prompt", Mode: 0644, RevisionGeneration: 2})
	if _, err := templates.SelectSources(scope, store.snapshot, request.Context); err == nil {
		t.Fatal("inventory selection treated a partial local pair as absent")
	}
}

func TestInventorySource(t *testing.T) {
	_, store, _, scope, _ := component(t)
	file := store.snapshot.Sources[0]
	retained, err := templates.SelectSource(scope, store.snapshot, file.Source)
	if err != nil || retained.Source != file.Source || retained.Content != file.Content {
		t.Fatalf("source lookup changed the exact committed content identity: %v", err)
	}
	for _, field := range []string{"id", "path", "hash", "generation"} {
		t.Run(field, func(t *testing.T) {
			ref := file.Source
			switch field {
			case "id":
				ref.ID = "foreign-source"
			case "path":
				ref.Path = ".laneboss/shared/foreign.md"
			case "hash":
				ref.SHA256 = digest([]byte("foreign source bytes"))
			case "generation":
				ref.Generation++
			}
			retained, err := templates.SelectSource(scope, store.snapshot, ref)
			if err == nil || retained.Source.ID != "" || retained.Content.ID != "" {
				t.Fatal("source lookup accepted a nonmatching retained source reference")
			}
		})
	}
}

func TestSourceCallback(t *testing.T) {
	service, store, policy, scope, _ := component(t)
	policy.failure = &api.Error{Code: api.CodeUnavailable, Owner: "fixture", Message: "policy callback must not recurse", Instead: "Call only the full source gate."}
	validation, err := service.ValidateSources(context.Background(), scope, api.OrgValidateRequest{Generation: store.snapshot.Ref.Generation})
	if err != nil || !validation.Valid || validation.Problems == nil || len(validation.Problems) != 0 || store.sourceCalls != len(store.snapshot.Sources) || store.writes != 0 {
		t.Fatalf("complete source callback recursed or skipped retained content: %v", err)
	}
}

func TestInventoryKinds(t *testing.T) {
	for _, name := range []string{"source-file", "derived-kind", "no-derived", "content"} {
		t.Run(name, func(t *testing.T) {
			service, store, _, scope, _ := component(t)
			switch name {
			case "source-file":
				file := store.snapshot.Sources[0]
				file.Source.ID, file.Source.Path, file.Kind = "notes-source", ".laneboss/shared/notes.md", "file"
				store.snapshot.Sources = append(store.snapshot.Sources, file)
			case "derived-kind":
				store.snapshot.Derived[0].Kind = "prompt"
			case "no-derived":
				store.snapshot.Derived = nil
			case "content":
				ref := store.snapshot.Sources[0].Content
				store.blobs[ref.ID][0] ^= 1
			}
			validation, err := service.ValidateSources(context.Background(), scope, api.OrgValidateRequest{Generation: store.snapshot.Ref.Generation})
			if err == nil || validation.Valid || store.writes != 0 {
				t.Fatal("full source gate accepted invalid kinds or retained content")
			}
			errorCode(t, err, api.CodeIntegrity)
		})
	}
}
