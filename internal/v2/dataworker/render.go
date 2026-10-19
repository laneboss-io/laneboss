package dataworker

import (
	"context"
	"errors"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/orgrender"
)

type renderScopeKey struct{}

func (s *Service) RenderChange(ctx context.Context, scope api.Scope, request api.ChangeRequest) (api.ChangeRequest, error) {
	return s.Render(context.WithValue(ctx, renderScopeKey{}, scope), request)
}

// Canonical policy rendering parses owned JSON/text and produces immutable
// review objects through the installed store. It executes no source program.
func (s *Service) RenderForScope(ctx context.Context, scope api.Scope, request api.ChangeRequest) (api.ChangeRequest, error) {
	if err := checkContext(ctx); err != nil {
		return api.ChangeRequest{}, err
	}
	// The installed helper supplies all native template/plugin effects. The
	// canonical compiler then adds its policy preview to that same review.
	rendered, native := request, false
	if executor, ok := s.deps.Helper.(orgrender.Executor); ok && !missing(executor) {
		if _, ok := s.deps.Store.(orgrender.Store); ok {
			var err error
			rendered, err = s.RenderChange(ctx, scope, request)
			if err != nil {
				return api.ChangeRequest{}, err
			}
			native = true
		}
	}
	port, ok := s.deps.Store.(interface {
		StageCanonicalChange(context.Context, api.Scope, api.ChangeRequest) (api.ChangeRequest, error)
	})
	if !ok {
		if native {
			return rendered, nil
		}
		return s.RenderChange(ctx, scope, request)
	}
	combined, err := port.StageCanonicalChange(ctx, scope, rendered)
	if errors.Is(err, orgrender.ErrNativeRender) {
		if native {
			return rendered, nil
		}
		return s.RenderChange(ctx, scope, request)
	}
	return combined, err
}

func (s *Service) Render(ctx context.Context, request api.ChangeRequest) (api.ChangeRequest, error) {
	var zero api.ChangeRequest
	if err := checkContext(ctx); err != nil {
		return zero, err
	}
	if !manifest.ValidID(request.ID) || !manifest.ValidID(request.OrgID) || request.Files == nil ||
		request.Requester.Kind != "lane" || request.Requester.Level != 6 || !manifest.ValidID(request.Requester.LifeID) {
		return zero, manifest.Invalid("render requires an authenticated L6 staged change")
	}
	if !manifest.Config(request.Config) || request.SourceSnapshot.OrgID != request.OrgID ||
		request.SourceSnapshot.Generation != request.BaseGeneration || request.BaseGeneration == 0 ||
		!manifest.ValidDigest(request.SourceSnapshot.ManifestSHA256) || !manifest.ValidID(request.Renderer.ID) ||
		!manifest.ValidDigest(request.Renderer.SHA256) || request.Renderer.Version == "" {
		return zero, manifest.Invalid("render needs the exact configuration, approved source snapshot and renderer pin")
	}
	if err := manifest.Blob(request.Reason); err != nil {
		return zero, err
	}
	if err := manifest.Blob(request.OwnershipManifest); err != nil {
		return zero, err
	}
	if request.OwnershipManifest.Class != "manifest" {
		return zero, manifest.Invalid("render ownership must be a committed manifest")
	}
	seen := map[string]bool{}
	for _, file := range request.Files {
		if err := manifest.Relative(file.Path); err != nil {
			return zero, err
		}
		if file.Path == "." || seen[file.Path] || file.Mode & ^uint32(0777) != 0 {
			return zero, manifest.Invalid("invalid or duplicate D6 source path or mode")
		}
		seen[file.Path] = true
		switch file.Action {
		case "add":
			if file.BeforeSHA256 != "" || file.After == nil {
				return zero, manifest.Invalid("D6 add needs after bytes and no before digest")
			}
		case "replace":
			if !manifest.ValidDigest(file.BeforeSHA256) || file.After == nil {
				return zero, manifest.Invalid("D6 replace needs before digest and after bytes")
			}
		case "delete":
			if !manifest.ValidDigest(file.BeforeSHA256) || file.After != nil {
				return zero, manifest.Invalid("D6 delete needs before digest and no after bytes")
			}
		default:
			return zero, manifest.Invalid("unknown D6 source action")
		}
		if file.After != nil {
			if err := manifest.Blob(*file.After); err != nil {
				return zero, err
			}
		}
	}
	if err := s.confinement(ctx); err != nil {
		return zero, err
	}
	scope, bound := ctx.Value(renderScopeKey{}).(api.Scope)
	store, stored := s.deps.Store.(orgrender.Store)
	executor, native := s.deps.Helper.(orgrender.Executor)
	if !bound || !stored || !native || missing(store) || missing(executor) {
		return zero, api.NotImplemented("lb-v2-grants", "dataworker.Render pinned renderer, staged source handles and retained derived outputs")
	}
	stage, cached, err := store.BeginRender(ctx, scope, request)
	if err != nil {
		return zero, err
	}
	if cached != nil {
		return *cached, nil
	}
	result, err := executor.RenderOrg(ctx, stage)
	if err != nil {
		return zero, err
	}
	return store.FinishRender(ctx, scope, stage, result)
}
