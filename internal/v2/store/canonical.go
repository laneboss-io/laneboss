package store

import (
	"context"
	"errors"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/policy"
	"laneboss.io/laneboss/internal/v2/templates"
)

func canonicalPin(approved api.EffectivePolicy) bool {
	for _, source := range approved.Sources {
		if source.Path == policy.CanonicalPath {
			return true
		}
	}
	return false
}

// policyForRole shares one approved source loader with public configuration
// reads. Legacy initial projections stay readable in their original context;
// they cannot supply another role's policy or complete configuration views.
func (s *Service) policyForRole(ctx context.Context, scope api.Scope, role api.RoleContext) (result api.EffectivePolicy, resultErr error) {
	scope, owned, err := s.sourceView(ctx, scope)
	if err != nil {
		return result, err
	}
	if owned != nil {
		defer func() { resultErr = errors.Join(resultErr, owned.Close()) }()
	}
	approved, err := scopedProjection[api.EffectivePolicy](ctx, s, scope, "policy", api.ID(s.deps.Config))
	if err != nil {
		return result, err
	}
	if role == (api.RoleContext{}) {
		role = approved.Context
	} else if role.Level == approved.Context.Level && role.Role == approved.Context.Role && role.InstanceID == "" {
		role.InstanceID = approved.Context.InstanceID
	}
	pinned := canonicalPin(approved)
	org, err := scopedProjection[api.OrgSnapshot](ctx, s, scope, "org", api.ID(s.deps.Config))
	if err != nil {
		var typed *api.Error
		if errors.As(err, &typed) && typed.Code == api.CodeNotFound {
			if pinned {
				return result, policy.CanonicalMissing()
			}
			return approved, nil
		}
		return result, err
	}
	if !policy.HasCanonical(org) {
		if pinned || role != approved.Context {
			return result, policy.CanonicalMissing()
		}
		return approved, nil
	}
	read := scope
	read.PolicyGeneration = approved.Generation
	view, err := policy.ReadCanonical(ctx, canonicalViewReader{store: s, scope: scope}, read, approved, org, role)
	if err != nil {
		return result, err
	}
	return view.Policy, nil
}

type canonicalViewReader struct {
	store *Service
	scope api.Scope
}

func (r canonicalViewReader) Source(ctx context.Context, _ api.Scope, ref api.SourceRef) (api.RetainedSource, error) {
	return r.store.Source(ctx, r.scope, ref)
}

func (r canonicalViewReader) Blob(ctx context.Context, _ api.Scope, request api.BlobReadRequest) (api.BlobChunk, error) {
	return r.store.Blob(ctx, r.scope, request)
}

type canonicalReader struct {
	store *Service
	db    queryer
	org   api.OrgSnapshot
}

func (r canonicalReader) Source(ctx context.Context, scope api.Scope, ref api.SourceRef) (api.RetainedSource, error) {
	retained, err := templates.SelectSource(scope, r.org, ref)
	if err != nil {
		return api.RetainedSource{}, err
	}
	metadata, _, err := objectRow(ctx, r.db, retained.Content.ID)
	if err != nil {
		return api.RetainedSource{}, err
	}
	if !objectVisible(scope, metadata.ACL) {
		return api.RetainedSource{}, missingObject()
	}
	if err := sourceMetadata(scope, retained.Content, metadata); err != nil {
		return api.RetainedSource{}, err
	}
	return retained, nil
}

func (r canonicalReader) Blob(ctx context.Context, scope api.Scope, request api.BlobReadRequest) (api.BlobChunk, error) {
	return r.store.blob(ctx, scope, r.db, request)
}

// Called only under the store lock with an authenticated view. This does not borrow a
// lane connection or turn a public caller into an internal actor.
func (s *Service) storedRolePolicy(ctx context.Context, db queryer, approved api.EffectivePolicy, lane api.Lane) (api.EffectivePolicy, error) {
	var org api.OrgSnapshot
	if err := storedProjection(ctx, db, "org", api.ID(s.deps.Config), &org); err != nil {
		if absent(err) {
			if canonicalPin(approved) {
				return api.EffectivePolicy{}, policy.CanonicalMissing()
			}
			return approved, nil
		}
		return api.EffectivePolicy{}, err
	}
	if !policy.HasCanonical(org) {
		if canonicalPin(approved) {
			return api.EffectivePolicy{}, policy.CanonicalMissing()
		}
		return approved, nil
	}
	scope := api.Scope{Config: s.deps.Config, Actor: api.Actor{Kind: "service", ID: "lb-v2-policy"}, Source: "service", PolicyGeneration: approved.Generation}
	role := api.RoleContext{Level: lane.Level, Role: lane.Role}
	if role.Level == approved.Context.Level && role.Role == approved.Context.Role {
		role.InstanceID = approved.Context.InstanceID
	}
	view, err := policy.ReadCanonical(ctx, canonicalReader{store: s, db: db, org: org}, scope, approved, org, role)
	if err != nil {
		return api.EffectivePolicy{}, err
	}
	return view.Policy, nil
}
