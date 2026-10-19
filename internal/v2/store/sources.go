package store

import (
	"context"
	"errors"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/templates"
)

func sourceFault(code api.ErrorCode, message string) error {
	return &api.Error{Code: code, Owner: "lb-v2-service", Message: message,
		Instead: "Use the authenticated store read view and exact committed source publication."}
}

func (s *Service) sourceScope(scope api.Scope) error {
	if scope.Config == "" || s.deps.Config == "" || scope.Config != s.deps.Config {
		return sourceFault(api.CodeForbidden, "source read differs from the installed configuration")
	}
	if scope.ReadView != nil && scope.ReadView.Snapshot().Config != scope.Config {
		return sourceFault(api.CodeIntegrity, "source read view omits its bound configuration")
	}
	return nil
}

func (s *Service) sourceView(ctx context.Context, scope api.Scope) (api.Scope, api.ReadView, error) {
	if err := s.sourceScope(scope); err != nil {
		return api.Scope{}, nil, err
	}
	if scope.ReadView != nil {
		return scope, nil, nil
	}
	view, err := s.BeginRead(ctx, scope)
	if err != nil {
		return api.Scope{}, nil, err
	}
	if view == nil || view.Snapshot().Config != scope.Config {
		if view != nil {
			err = view.Close()
		}
		return api.Scope{}, nil, errors.Join(sourceFault(api.CodeIntegrity, "source read view omits its bound configuration"), err)
	}
	scope.ReadView = view
	return scope, view, nil
}

func (s *Service) sourceObject(ctx context.Context, scope api.Scope, ref api.BlobRef) error {
	metadata, err := s.ObjectMetadata(ctx, scope, ref.ID)
	if err != nil {
		return err
	}
	return sourceMetadata(scope, ref, metadata)
}

func sourceMetadata(scope api.Scope, ref api.BlobRef, metadata api.ObjectMetadata) error {
	if metadata.Ref != ref || metadata.ACL.Config != scope.Config || metadata.ACL.Generation == 0 || metadata.CommittedAt == "" || metadata.Origin == "" {
		return sourceFault(api.CodeIntegrity, "source content differs from its committed object metadata")
	}
	return nil
}

func sourceSnapshot(scope api.Scope, generation api.Generation, snapshot api.OrgSnapshot) error {
	return api.ValidateOrgSnapshotSelection(scope, api.OrgSnapshotRequest{OrgID: api.ID(scope.Config), Generation: generation}, snapshot)
}

func (s *Service) TemplateSources(ctx context.Context, scope api.Scope, request api.TemplateSourceRequest) (result api.TemplateSources, resultErr error) {
	if err := s.sourceScope(scope); err != nil {
		return result, err
	}
	if api.ValidateOrgSnapshotRequest(scope, api.OrgSnapshotRequest{OrgID: request.OrgID, Generation: request.Generation}) != nil {
		return result, sourceFault(api.CodeInvalid, "template sources require this org and an exact generation")
	}
	if err := templates.ValidateTemplateContext(request.Context); err != nil {
		return result, err
	}
	scope, owned, err := s.sourceView(ctx, scope)
	if err != nil {
		return result, err
	}
	if owned != nil {
		defer func() { resultErr = errors.Join(resultErr, owned.Close()) }()
	}
	snapshot, err := s.OrgSnapshot(ctx, scope, api.OrgSnapshotRequest{OrgID: request.OrgID, Generation: request.Generation})
	if err != nil {
		return result, err
	}
	if err := sourceSnapshot(scope, request.Generation, snapshot); err != nil {
		return result, err
	}
	result, err = templates.SelectSources(scope, snapshot, request.Context)
	if err != nil {
		return api.TemplateSources{}, err
	}
	pairs := []api.RoleTemplateSources{result.Org}
	if result.Local != nil {
		pairs = append(pairs, *result.Local)
	}
	for _, pair := range pairs {
		for _, source := range []api.TemplateSource{pair.Prompt, pair.Drivers} {
			if err := s.sourceObject(ctx, scope, source.Content); err != nil {
				return api.TemplateSources{}, err
			}
		}
	}
	return result, nil
}

func (s *Service) Source(ctx context.Context, scope api.Scope, request api.SourceRef) (result api.RetainedSource, resultErr error) {
	if err := s.sourceScope(scope); err != nil {
		return result, err
	}
	if err := templates.ValidateSourceRef(request); err != nil {
		return result, err
	}
	scope, owned, err := s.sourceView(ctx, scope)
	if err != nil {
		return result, err
	}
	if owned != nil {
		defer func() { resultErr = errors.Join(resultErr, owned.Close()) }()
	}
	snapshot, err := s.OrgSnapshot(ctx, scope, api.OrgSnapshotRequest{OrgID: api.ID(scope.Config), Generation: request.Generation})
	if err != nil {
		return result, err
	}
	if err := sourceSnapshot(scope, request.Generation, snapshot); err != nil {
		return result, err
	}
	result, err = templates.SelectSource(scope, snapshot, request)
	if err != nil {
		return api.RetainedSource{}, err
	}
	if err := s.sourceObject(ctx, scope, result.Content); err != nil {
		return api.RetainedSource{}, err
	}
	return result, nil
}
