package dataworker

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/lstate"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

// Both newly acknowledged stages and historical replay use this boundary.
// The source is selected by the store's sourced plan, never by result fields.
func (s *Service) launchSnapshot(ctx context.Context, state *lstate.State, snapshot api.ObjectManifest) error {
	if state.Record.Inputs == nil {
		return lstate.Error(api.CodeIntegrity, "launch snapshot has no retained source authority")
	}
	raw, err := state.Read(ctx, state.Record.Inputs.Sources.Project.Object)
	if err != nil {
		return err
	}
	var source api.ObjectManifest
	if err := api.DecodeObject(raw, &source); err != nil {
		return err
	}
	if err := manifest.Object(source); err != nil {
		return err
	}
	if !sameCopyTree(source, snapshot) {
		return lstate.Error(api.CodeIntegrity, "launch snapshot differs from the exact granted source tree")
	}
	seen := map[api.ID]api.BlobRef{}
	for _, entry := range snapshot.Entries {
		for _, ref := range manifest.ContentRefs(entry) {
			if prior, found := seen[ref.ID]; found {
				if prior != ref {
					return lstate.Error(api.CodeIntegrity, "launch snapshot reuses an artifact identity with different bytes")
				}
				continue
			}
			if len(seen) >= 4096 {
				return lstate.Error(api.CodeBudget, "launch snapshot exceeds its artifact metadata bound")
			}
			seen[ref.ID] = ref
			metadata, err := s.deps.Store.ObjectMetadata(ctx, state.Scope, ref.ID)
			if err != nil {
				return err
			}
			if ref.Class != "artifact" || metadata.Ref != ref || metadata.ACL.Config != state.Scope.Config {
				return lstate.Error(api.CodeIntegrity, "launch snapshot artifact differs from its committed metadata")
			}
		}
	}
	return nil
}
