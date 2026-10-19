package store

import (
	"context"
	"errors"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/templates"
)

// A supplied-view fixture tests only the adapter's binding and ownership gate.
// It is not a persistent store or evidence for authenticated backend reads.
type sourceTestView struct {
	config string
	closed bool
}

func (v *sourceTestView) Snapshot() api.ReadSnapshot { return api.ReadSnapshot{Config: v.config} }
func (v *sourceTestView) Close() error               { v.closed = true; return nil }

func TestSourceView(t *testing.T) {
	for _, name := range []string{"bound", "foreign", "unbound", "empty", "cross"} {
		t.Run(name, func(t *testing.T) {
			s := &Service{deps: Dependencies{Config: "demo"}}
			view := &sourceTestView{config: "demo"}
			scope := api.Scope{Config: "demo", ReadView: view}
			want := api.ErrorCode("")
			switch name {
			case "foreign":
				view.config, want = "other", api.CodeIntegrity
			case "unbound":
				view.config, want = "", api.CodeIntegrity
			case "empty":
				s.deps.Config, scope.Config, view.config, want = "", "", "", api.CodeForbidden
			case "cross":
				scope.Config, want = "other", api.CodeForbidden
			}
			bound, owned, err := s.sourceView(context.Background(), scope)
			var failure *api.Error
			if want == "" {
				if err != nil || bound.ReadView != view || bound.Config != scope.Config || owned != nil || view.closed {
					t.Fatalf("source adapter did not reuse its borrowed bound view: %v", err)
				}
			} else if !errors.As(err, &failure) || failure.Code != want || bound.ReadView != nil || owned != nil || view.closed {
				t.Fatalf("source adapter accepted an unbound or foreign read view: %v", err)
			}
		})
	}
}

func TestSourceMetadata(t *testing.T) {
	scope := api.Scope{Config: "demo"}
	ref := api.BlobRef{ID: "content", Class: "artifact", Bytes: 3, SHA256: api.Digest(strings.Repeat("a", 64))}
	valid := api.ObjectMetadata{Ref: ref, ACL: api.ObjectACL{Config: "demo", Generation: 2}, Origin: "templates", CommittedAt: "2030-01-01T00:00:00Z"}
	if err := sourceMetadata(scope, ref, valid); err != nil {
		t.Fatalf("committed source metadata refused: %v", err)
	}
	for _, name := range []string{"generation", "config", "ref", "origin", "commit"} {
		t.Run(name, func(t *testing.T) {
			metadata := valid
			switch name {
			case "generation":
				metadata.ACL.Generation = 0
			case "config":
				metadata.ACL.Config = "other"
			case "ref":
				metadata.Ref.ID = "other"
			case "origin":
				metadata.Origin = ""
			case "commit":
				metadata.CommittedAt = ""
			}
			var failure *api.Error
			if err := sourceMetadata(scope, ref, metadata); !errors.As(err, &failure) || failure.Code != api.CodeIntegrity {
				t.Fatalf("source adapter accepted uncommitted object metadata: %v", err)
			}
		})
	}
}

func TestSourceRequests(t *testing.T) {
	for _, name := range []string{"cross-zero", "cross-range", "empty", "zero", "range", "id", "path", "digest"} {
		t.Run(name, func(t *testing.T) {
			s := &Service{deps: Dependencies{Config: "demo"}}
			scope := api.Scope{Config: "demo"}
			ref := api.SourceRef{ID: "source", Path: ".laneboss/shared/workflow.toml", SHA256: api.Digest(strings.Repeat("a", 64)), Generation: 7}
			want := api.CodeInvalid
			switch name {
			case "cross-zero":
				scope.Config, ref.Generation, want = "other", 0, api.CodeForbidden
			case "cross-range":
				scope.Config, ref.Generation, want = "other", 1<<53, api.CodeForbidden
			case "empty":
				s.deps.Config, scope.Config, want = "", "", api.CodeForbidden
			case "zero":
				ref.Generation = 0
			case "range":
				ref.Generation = 1 << 53
			case "id":
				ref.ID = "bad/id"
			case "path":
				ref.Path = "../outside"
			case "digest":
				ref.SHA256 = "invalid"
			}
			result, err := s.Source(context.Background(), scope, ref)
			var failure *api.Error
			if result.Source.ID != "" || !errors.As(err, &failure) || failure.Code != want {
				t.Fatalf("source request crossed its configuration or preflight boundary: %v", err)
			}
			if name == "id" || name == "path" || name == "digest" {
				return
			}
			pairs, err := s.TemplateSources(context.Background(), scope, api.TemplateSourceRequest{OrgID: api.ID(scope.Config), Generation: ref.Generation, Context: api.RoleContext{Level: 3, Role: "executor"}})
			failure = nil
			if pairs.Snapshot.OrgID != "" || !errors.As(err, &failure) || failure.Code != want {
				t.Fatalf("template request crossed its configuration or generation boundary: %v", err)
			}
		})
	}
}

func TestSourceSnapshot(t *testing.T) {
	scope := api.Scope{Config: "demo"}
	base := api.OrgSnapshot{Config: scope.Config, Ref: api.OrgSnapshotRef{OrgID: api.ID(scope.Config), Generation: 7}}
	if err := sourceSnapshot(scope, base.Ref.Generation, base); err != nil {
		t.Fatalf("exact source publication refused: %v", err)
	}
	for _, name := range []string{"config", "org", "stale", "mixed", "zero", "range"} {
		t.Run(name, func(t *testing.T) {
			snapshot := base
			want := api.CodeIntegrity
			switch name {
			case "config":
				snapshot.Config = "other"
			case "org":
				snapshot.Ref.OrgID = "foreign"
			case "stale":
				snapshot.Ref.Generation--
				want = api.CodeConflict
			case "mixed":
				snapshot.Ref.OrgID = "foreign"
				snapshot.Ref.Generation--
			case "zero":
				snapshot.Ref.Generation = 0
			case "range":
				snapshot.Ref.Generation = 1 << 53
			}
			var failure *api.Error
			if err := sourceSnapshot(scope, base.Ref.Generation, snapshot); !errors.As(err, &failure) || failure.Code != want || failure.Owner != "lb-v2-service" {
				t.Fatalf("source projection confused a foreign publication with a stale generation: %v", err)
			}
		})
	}
}

func TestSourceContext(t *testing.T) {
	for _, role := range []api.RoleContext{{Level: 3, Role: "executor"}, {Level: 6, Role: "reviewer", InstanceID: "review-one"}} {
		if err := templates.ValidateTemplateContext(role); err != nil {
			t.Fatalf("valid source context refused: %v", err)
		}
	}
	for _, mode := range []string{"new", "borrowed"} {
		for _, name := range []string{"level", "reserved", "role", "empty", "instance", "cross"} {
			t.Run(mode+"/"+name, func(t *testing.T) {
				s := &Service{deps: Dependencies{Config: "demo"}}
				scope := api.Scope{Config: "demo"}
				view := &sourceTestView{config: scope.Config}
				if mode == "borrowed" {
					scope.ReadView = view
				}
				role := api.RoleContext{Level: 3, Role: "executor"}
				want := api.CodeInvalid
				switch name {
				case "level":
					role.Level = 0
				case "reserved":
					role.Level = 7
				case "role":
					role.Role = "../bad"
				case "empty":
					role.Role = ""
				case "instance":
					role.InstanceID = "bad/id"
				case "cross":
					role.Level, scope.Config, want = 0, "other", api.CodeForbidden
				}
				result, err := s.TemplateSources(context.Background(), scope, api.TemplateSourceRequest{OrgID: api.ID(scope.Config), Generation: 7, Context: role})
				var failure *api.Error
				if result.Snapshot.OrgID != "" || !errors.As(err, &failure) || failure.Code != want || view.closed {
					t.Fatalf("invalid source context reached view or snapshot lookup before preflight: %v", err)
				}
			})
		}
	}
}
