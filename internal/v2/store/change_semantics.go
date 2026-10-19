package store

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/policy"
	"laneboss.io/laneboss/internal/v2/templates"
)

type orgPolicy struct {
	Before api.EffectivePolicy
	After  api.EffectivePolicy
}

// Compile policy from its exact next source inventory before consuming approval
// or committing a filesystem effect. Other semantic kinds keep their existing
// projection prerequisite; unchanged legacy inputs use provenance rebinding.
func (s *Service) publicationSemantics(ctx context.Context, db queryer, snapshot api.OrgSnapshot, change api.ChangeRequest) (*orgPolicy, error) {
	next, err := nextOrgSnapshot(orgApply{Snapshot: snapshot, Change: change}, api.ChangeReceipt{})
	if err != nil {
		return nil, err
	}
	canonical := policy.HasCanonical(next)
	changed := map[string]bool{}
	for _, group := range [][]api.ResourceDelta{change.Files, change.Derived} {
		for _, file := range group {
			changed[file.Path] = true
		}
	}
	blocked := func() error {
		return &api.Error{Code: api.CodePrerequisite, Owner: "lb-v2-approval", Message: "org generation requires approved semantic and source-provenance projections", Instead: "Install and verify the confined renderer's policy, channel, grant, config or decision projection before applying this change; canonical bytes alone are not application."}
	}
	for _, file := range append(append([]api.ResourceFile{}, snapshot.Sources...), snapshot.Derived...) {
		if !changed[file.Source.Path] {
			continue
		}
		switch file.Kind {
		case "policy":
			if canonical && !policy.CanonicalSourcePath(file.Source.Path) && file.Source.Path != templates.WorkflowPath {
				return nil, blocked()
			}
		case "config", "channel", "grants", "decision":
			return nil, blocked()
		}
	}
	if canonical {
		var current api.EffectivePolicy
		if err := storedProjection(ctx, db, "policy", api.ID(s.deps.Config), &current); err != nil {
			return nil, err
		}
		after, err := s.compileOrgPolicy(ctx, db, current, snapshot, next)
		if err != nil {
			return nil, err
		}
		if err := s.publicationChannels(ctx, db, changed, blocked); err != nil {
			return nil, err
		}
		return &orgPolicy{Before: current, After: after}, nil
	}
	var compiled *orgPolicy
	var current api.EffectivePolicy
	if err := storedProjection(ctx, db, "policy", api.ID(s.deps.Config), &current); err == nil {
		refs := append([]api.SourceRef{}, current.Sources...)
		refs = append(refs, current.GuidanceSource)
		for _, rule := range current.Rules {
			refs = append(refs, rule.Source)
		}
		for _, entry := range current.Skip {
			refs = append(refs, entry.Source)
		}
		for _, ref := range refs {
			if ref.ID != "" || ref.Path != "" {
				p, err := s.compileOrgPolicy(ctx, db, current, snapshot, next)
				if err != nil {
					return nil, err
				}
				for _, source := range current.Sources {
					for _, file := range snapshot.Sources {
						if file.Source.ID != source.ID {
							continue
						}
						meta, _, err := objectRow(ctx, db, file.Content.ID)
						if err != nil {
							return nil, err
						}
						if meta.Ref != file.Content || meta.ACL.Config != change.Config {
							return nil, fault(api.CodeIntegrity, "compiled policy source differs from its retained object")
						}
					}
				}
				compiled = &orgPolicy{Before: current, After: p}
				break
			}
		}
	} else if !absent(err) {
		return nil, err
	}
	if compiled == nil {
		for _, file := range snapshot.Sources {
			if file.Kind == "policy" {
				return nil, blocked()
			}
		}
	}
	if err := s.publicationChannels(ctx, db, changed, blocked); err != nil {
		return nil, err
	}
	return compiled, nil
}

func (s *Service) publicationChannels(ctx context.Context, db queryer, changed map[string]bool, blocked func() error) error {
	// Channels retain their approved source identity separately from policy.
	// Even unchanged source bytes need a new generation-bound projection.
	var count int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM projections WHERE kind='channel' AND (coalesce(json_extract(data,'$.Source.id'),'')!='' OR coalesce(json_extract(data,'$.Source.path'),'')!='')").Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return blocked()
	}
	for name := range changed {
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM projections WHERE kind='channel' AND (json_extract(data,'$.Source.path')=? OR json_extract(data,'$.Source.Path')=?)", name, name).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return blocked()
		}
	}
	return nil
}

func (s *Service) compileOrgPolicy(ctx context.Context, db queryer, before api.EffectivePolicy, base, next api.OrgSnapshot) (api.EffectivePolicy, error) {
	if !policy.HasCanonical(next) {
		return policy.CompileOrgSources(before, base, next, func(ref api.BlobRef) ([]byte, error) {
			meta, raw, err := objectRow(ctx, db, ref.ID)
			if err != nil {
				return nil, err
			}
			if meta.Ref != ref {
				return nil, fault(api.CodeIntegrity, "policy compiler object reference changed")
			}
			return raw, nil
		})
	}
	target := before
	target.Generation++
	scope := api.Scope{Config: s.deps.Config, Actor: api.Actor{Kind: "service", ID: "lb-v2-policy"}, Source: "service", PolicyGeneration: target.Generation}
	view, err := policy.CompileCanonical(ctx, canonicalReader{store: s, db: db, org: next}, scope, target, next)
	if err != nil {
		return api.EffectivePolicy{}, err
	}
	return view.Policy, nil
}
