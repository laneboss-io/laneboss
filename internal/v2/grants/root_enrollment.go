package grants

import (
	"context"
	"errors"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

// A protected handle is an immutable service-origin manifest object containing
// the existing ResourceGrant or SecretGrant shape. Its source_handle is the
// object's identity. Generic uploads are observations and cannot enroll it.
// This reader creates no record, fetches no material and grants no extra scope.
func (s *Service) rootEnrollment(ctx context.Context, scope api.Scope, handle api.ID) (raw []byte, resultErr error) {
	scope, view, err := s.freshAuthority(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, view.Close()) }()
	if err := s.checkScope(ctx, scope); err != nil {
		return nil, err
	}
	policy, err := s.deps.Store.Policy(ctx, scope)
	if err != nil {
		return nil, err
	}
	if policy.Generation == 0 || policy.Generation != scope.PolicyGeneration {
		return nil, conflict("root capability policy generation changed")
	}
	metadata, err := s.deps.Store.ObjectMetadata(ctx, scope, handle)
	if err != nil {
		var typed *api.Error
		if errors.As(err, &typed) && typed.Code == api.CodeNotFound {
			return nil, &api.Error{Code: api.CodeNotFound, Owner: "lb-v2-grants",
				Message: "root capability handle is not enrolled",
				Instead: "Enroll the exact capability through the protected administrator path before root approval."}
		}
		return nil, err
	}
	if metadata.ACL.Config != scope.Config || metadata.ACL.Owner != scope.Actor || metadata.ACL.LifeID != "" || metadata.Origin != "service" {
		return nil, refused("root capability record has a foreign owner, scope or origin")
	}
	// Ordinary immutable objects have generation one in the existing writer.
	// A mutable/private plan generation is not an enrollment record. Replacing
	// enrollment requires a newly retained object and a new opaque handle.
	if metadata.ACL.Generation != 1 {
		return nil, conflict("root capability enrollment generation is stale")
	}
	if metadata.Ref.ID != handle || metadata.Ref.Class != "manifest" {
		return nil, integrity("root capability record identity or class differs")
	}
	return s.readRef(ctx, scope, metadata.Ref)
}

func emptyRootEnrollment() api.RootGrantManifest {
	return api.RootGrantManifest{Schema: "laneboss.root-grants.v2", Resources: []api.ResourceGrant{},
		Data: []api.DataGrant{}, Secrets: []api.SecretGrant{}, Profiles: []api.ProfileGrant{},
		Network: []api.NetworkGrant{}, Channels: []api.ChannelGrant{}}
}

func rootEnrollmentBound(expiry, enrolled api.Timestamp, delegate, mayDelegate bool, now time.Time) error {
	if delegate && !mayDelegate {
		return refused("root capability delegation exceeds protected enrollment")
	}
	requested, err := manifest.Expiry(expiry, now)
	if err != nil {
		return err
	}
	ceiling, err := manifest.Expiry(enrolled, now)
	if err != nil {
		return err
	}
	if requested.After(ceiling) {
		return refused("root capability expiry exceeds protected enrollment")
	}
	return nil
}

func (s *Service) rootEnrollments(ctx context.Context, scope api.Scope, input api.RootGrantManifest) error {
	for _, grant := range input.Resources {
		raw, err := s.rootEnrollment(ctx, scope, grant.SourceHandle)
		if err != nil {
			return err
		}
		var enrolled api.ResourceGrant
		if err := api.DecodeObject(raw, &enrolled); err != nil {
			return integrity("protected resource enrollment shape is invalid")
		}
		check := emptyRootEnrollment()
		check.Resources = []api.ResourceGrant{enrolled}
		if err := manifest.Root(check, s.deps.Clock.Now()); err != nil {
			return err
		}
		if enrolled.SourceHandle != grant.SourceHandle || enrolled.Provider != grant.Provider {
			return refused("root resource differs from protected enrollment")
		}
		if err := rootEnrollmentBound(grant.ExpiresAt, enrolled.ExpiresAt, grant.Delegate, enrolled.Delegate, s.deps.Clock.Now()); err != nil {
			return err
		}
		for _, selection := range [][2][]string{{enrolled.Regions, grant.Regions}, {enrolled.ImageIDs, grant.ImageIDs}, {enrolled.MachineTypes, grant.MachineTypes}} {
			if err := selectionSubset(selection[0], selection[1]); err != nil {
				return err
			}
		}
		if grant.MaxActive > enrolled.MaxActive || grant.MaxHourlyMicros > enrolled.MaxHourlyMicros || grant.TotalBudgetMicros > enrolled.TotalBudgetMicros {
			return refused("root resource concurrency or cost exceeds protected enrollment")
		}
	}
	for _, grant := range input.Secrets {
		raw, err := s.rootEnrollment(ctx, scope, grant.SourceHandle)
		if err != nil {
			return err
		}
		var enrolled api.SecretGrant
		if err := api.DecodeObject(raw, &enrolled); err != nil {
			return integrity("protected secret enrollment shape is invalid")
		}
		check := emptyRootEnrollment()
		check.Secrets = []api.SecretGrant{enrolled}
		if err := manifest.Root(check, s.deps.Clock.Now()); err != nil {
			return err
		}
		if enrolled.SourceHandle != grant.SourceHandle || enrolled.Name != grant.Name || enrolled.Version != grant.Version ||
			enrolled.Delivery != grant.Delivery || enrolled.Target != grant.Target {
			return refused("root secret differs from protected enrollment")
		}
		if err := rootEnrollmentBound(grant.ExpiresAt, enrolled.ExpiresAt, grant.Delegate, enrolled.Delegate, s.deps.Clock.Now()); err != nil {
			return err
		}
	}
	return nil
}
