package templates_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/templates"
)

func TestOrgKinds(t *testing.T) {
	for _, gate := range []string{"org", "callback"} {
		for _, name := range []string{"prompt-source", "prompt-policy", "drivers", "local", "local-drivers", "workflow", "unselected"} {
			t.Run(gate+"/"+name, func(t *testing.T) {
				service, store, _, scope, _ := component(t)
				validate := service.OrgValidate
				if gate == "callback" {
					validate = service.ValidateSources
				}
				request := api.OrgValidateRequest{Generation: store.snapshot.Ref.Generation}
				if result, err := validate(context.Background(), scope, request); err != nil || !result.Valid {
					t.Fatalf("valid semantic catalog refused: %v", err)
				}
				if name == "unselected" {
					for _, file := range append([]api.ResourceFile(nil), store.snapshot.Sources...) {
						if strings.HasPrefix(file.Source.Path, ".laneboss/L3/roles/") {
							file.Source.ID += "-unselected"
							file.Source.Path = strings.Replace(file.Source.Path, "L3/roles/executor", "L4/roles/supervisor", 1)
							if strings.HasSuffix(file.Source.Path, ".md") {
								file.Kind = "source"
							}
							store.snapshot.Sources = append(store.snapshot.Sources, file)
						}
					}
				} else {
					for i := range store.snapshot.Sources {
						file := &store.snapshot.Sources[i]
						switch {
						case name == "prompt-source" && file.Source.Path == templates.OrgTemplatePath:
							file.Kind = "source"
						case name == "prompt-policy" && file.Source.Path == templates.OrgTemplatePath:
							file.Kind = "policy"
						case name == "drivers" && file.Source.Path == templates.OrgDriversPath:
							file.Kind = "prompt"
						case name == "local" && strings.HasSuffix(file.Source.Path, "executor.md"):
							file.Kind = "source"
						case name == "local-drivers" && strings.HasSuffix(file.Source.Path, "executor.toml"):
							file.Kind = "prompt"
						case name == "workflow" && file.Source.Path == templates.WorkflowPath:
							file.Kind = "task"
						}
					}
				}
				result, err := validate(context.Background(), scope, request)
				var failure *api.Error
				if result.Valid || !errors.As(err, &failure) || failure.Code != api.CodeInvalid || store.writes != 0 {
					t.Fatalf("org validation accepted a template kind that disagrees with its path: %v", err)
				}
			})
		}
	}
}

func TestOrgBoundary(t *testing.T) {
	t.Run("selection", func(t *testing.T) {
		_, store, _, scope, request := component(t)
		store.snapshot.Ref.OrgID = "foreign"
		_, pairsErr := templates.SelectSources(scope, store.snapshot, request.Context)
		_, sourceErr := templates.SelectSource(scope, store.snapshot, store.snapshot.Sources[0].Source)
		for _, err := range []error{pairsErr, sourceErr} {
			var failure *api.Error
			if !errors.As(err, &failure) || failure.Code != api.CodeIntegrity {
				t.Fatalf("inventory accepted an org outside its configuration: %v", err)
			}
		}
	})
	t.Run("org", func(t *testing.T) {
		service, store, policy, scope, _ := component(t)
		store.changeSnapshot = func(snapshot *api.OrgSnapshot) { snapshot.Ref.OrgID = "foreign" }
		policy.failure = errors.New("foreign snapshot reached policy validation")
		result, err := service.OrgValidate(context.Background(), scope, api.OrgValidateRequest{Generation: 7})
		var failure *api.Error
		if result.Valid || !errors.As(err, &failure) || failure.Code != api.CodeIntegrity || store.metadataCalls != 0 {
			t.Fatalf("foreign org snapshot reached policy or content validation: %v", err)
		}
	})
	t.Run("render", func(t *testing.T) {
		service, store, _, scope, request := component(t)
		store.selection.Snapshot.OrgID = "foreign"
		result, err := service.BriefRender(context.Background(), scope, request)
		var failure *api.Error
		if result.Markdown.ID != "" || !errors.As(err, &failure) || failure.Code != api.CodeConflict ||
			len(store.snapshotRequests) != 0 || store.sourceCalls != 0 || len(store.retained) != 0 {
			t.Fatalf("foreign template selection reached snapshot lookup: %v", err)
		}
	})
}

func TestOrgRead(t *testing.T) {
	for _, gate := range []string{"validate", "callback"} {
		for _, name := range []string{"config", "org", "stale", "mixed", "zero", "range"} {
			t.Run(gate+"/"+name, func(t *testing.T) {
				service, store, policy, scope, _ := component(t)
				validate := service.OrgValidate
				if gate == "callback" {
					validate = service.ValidateSources
				}
				request := api.OrgValidateRequest{Generation: store.snapshot.Ref.Generation}
				if result, err := validate(context.Background(), scope, request); err != nil || !result.Valid {
					t.Fatalf("valid org read refused: %v", err)
				}
				sources, metadata, reads := store.sourceCalls, store.metadataCalls, len(store.reads)
				policy.failure = errors.New("foreign or stale snapshot reached policy validation")
				store.changeSnapshot = func(snapshot *api.OrgSnapshot) {
					switch name {
					case "config":
						snapshot.Config = "other"
					case "org":
						snapshot.Ref.OrgID = "foreign"
					case "stale":
						snapshot.Ref.Generation--
					case "mixed":
						snapshot.Ref.OrgID = "foreign"
						snapshot.Ref.Generation--
					case "zero":
						snapshot.Ref.Generation = 0
					case "range":
						snapshot.Ref.Generation = 1 << 53
					}
				}
				want := api.CodeIntegrity
				if name == "stale" {
					want = api.CodeConflict
				}
				result, err := validate(context.Background(), scope, request)
				var failure *api.Error
				if result.Valid || !errors.As(err, &failure) || failure.Code != want || failure.Owner != "lb-v2-templates" {
					t.Fatalf("org read confused a foreign projection with a stale generation: %v", err)
				}
				if len(store.snapshotRequests) != 2 || store.snapshotRequests[1] != (api.OrgSnapshotRequest{OrgID: api.ID(scope.Config), Generation: request.Generation}) ||
					store.sourceCalls != sources || store.metadataCalls != metadata || len(store.reads) != reads || store.writes != 0 {
					t.Fatal("invalid org projection reached content or changed its exact selector")
				}
			})
		}
	}
}

func initialSnapshot(store *memoryStore) {
	store.snapshot.Ref.Generation = 1
	store.snapshot.Derived = []api.ResourceFile{}
	for i := range store.snapshot.Sources {
		store.snapshot.Sources[i].Source.Generation = 1
		store.snapshot.Sources[i].RevisionGeneration = 1
	}
}

func TestInitialShape(t *testing.T) {
	service, store, _, scope, request := component(t)
	initialSnapshot(store)
	selected, err := templates.SelectSources(scope, store.snapshot, request.Context)
	if err != nil || selected.Snapshot != store.snapshot.Ref || selected.LocalStatus != "present" {
		t.Fatalf("explicit initial empty derived inventory was refused: %v", err)
	}
	file := store.snapshot.Sources[0]
	retained, err := templates.SelectSource(scope, store.snapshot, file.Source)
	if err != nil || retained.Source != file.Source || retained.Content != file.Content {
		t.Fatalf("initial retained source selection changed: %v", err)
	}
	for _, validate := range []func(context.Context, api.Scope, api.OrgValidateRequest) (api.OrgValidation, error){service.OrgValidate, service.ValidateSources} {
		result, err := validate(context.Background(), scope, api.OrgValidateRequest{Generation: 1})
		if err != nil || !result.Valid || result.Problems == nil || len(result.Problems) != 0 || store.writes != 0 {
			t.Fatalf("full initial source validation refused the exact empty derived shape: %v", err)
		}
	}
}

func TestInitialGuards(t *testing.T) {
	for _, name := range []string{"nil", "unexpected", "later-empty", "later-nil", "sources", "renderer", "ownership", "digest", "revision", "mode", "content"} {
		t.Run(name, func(t *testing.T) {
			service, store, _, scope, _ := component(t)
			derived := store.snapshot.Derived[0]
			initialSnapshot(store)
			switch name {
			case "nil":
				store.snapshot.Derived = nil
			case "unexpected":
				derived.Source.Generation, derived.RevisionGeneration = 1, 1
				store.snapshot.Derived = []api.ResourceFile{derived}
			case "later-empty", "later-nil":
				store.snapshot.Ref.Generation = 2
				for i := range store.snapshot.Sources {
					store.snapshot.Sources[i].Source.Generation = 2
				}
				if name == "later-nil" {
					store.snapshot.Derived = nil
				}
			case "sources":
				store.snapshot.Sources = nil
			case "renderer":
				store.snapshot.Renderer.Version = ""
			case "ownership":
				store.snapshot.OwnershipManifest = api.BlobRef{}
			case "digest":
				store.snapshot.Sources[0].Source.SHA256 = digest([]byte("changed"))
			case "revision":
				store.snapshot.Sources[0].RevisionGeneration = 2
			case "mode":
				store.snapshot.Sources[0].Mode = 0
			case "content":
				store.blobs[store.snapshot.Sources[0].Content.ID][0] ^= 1
			}
			result, err := service.ValidateSources(context.Background(), scope, api.OrgValidateRequest{Generation: store.snapshot.Ref.Generation})
			var failure *api.Error
			if result.Valid || !errors.As(err, &failure) || failure.Code != api.CodeIntegrity || store.writes != 0 {
				t.Fatalf("initial shape repair bypassed an inventory integrity gate: %v", err)
			}
		})
	}
}

func TestSourceClaim(t *testing.T) {
	for _, name := range []string{"id", "path", "digest", "zero", "range"} {
		t.Run(name, func(t *testing.T) {
			_, store, _, scope, _ := component(t)
			ref := store.snapshot.Sources[0].Source
			switch name {
			case "id":
				ref.ID = "bad/id"
			case "path":
				ref.Path = "../outside"
			case "digest":
				ref.SHA256 = "invalid"
			case "zero":
				ref.Generation = 0
			case "range":
				ref.Generation = 1 << 53
			}
			result, err := templates.SelectSource(scope, store.snapshot, ref)
			var failure *api.Error
			if result.Source.ID != "" || !errors.As(err, &failure) || failure.Code != api.CodeInvalid {
				t.Fatalf("malformed source claim reached inventory lookup: %v", err)
			}
		})
	}
	_, store, _, scope, _ := component(t)
	ref := store.snapshot.Sources[0].Source
	ref.ID = "valid-unretained"
	_, err := templates.SelectSource(scope, store.snapshot, ref)
	errorCode(t, err, api.CodeNotFound)
	ref = store.snapshot.Sources[0].Source
	ref.Generation++
	_, err = templates.SelectSource(scope, store.snapshot, ref)
	errorCode(t, err, api.CodeConflict)
}
