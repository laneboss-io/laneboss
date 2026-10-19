package store

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/approval"
	"laneboss.io/laneboss/internal/v2/orgrender"
	"laneboss.io/laneboss/internal/v2/policy"
)

const renderedPolicyPath = ".laneboss/shared/policy.md"

// StageCanonicalChange adds the fixed policy preview to native derived outputs
// under the original authenticated operation. Source bytes remain data; the
// compiler retains one combined review without invoking a source program.
func (s *Service) StageCanonicalChange(ctx context.Context, scope api.Scope, change api.ChangeRequest) (result api.ChangeRequest, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return result, err
	}
	if err := s.scope(ctx, s.db, scope); err != nil {
		return result, err
	}
	if scope.Actor.Kind != "lane" || scope.Actor.Level != 6 || change.Requester != scope.Actor || scope.Config != change.Config || scope.Request.Method != "org.change.propose" && scope.Request.Method != "org.change.apply" {
		return result, fault(api.CodeForbidden, "policy render requires its authenticated proposing L6 frame")
	}
	reserved, err := s.lookupReceipt(ctx, s.db, scope, requestKey(scope.Request))
	if err != nil {
		return result, err
	}
	if reserved.Reply != nil || reserved.Actor != scope.Actor {
		return result, fault(api.CodeConflict, "policy render has no pending original operation")
	}
	var base api.OrgSnapshot
	if err := storedProjection(ctx, s.db, "org", change.OrgID, &base); err != nil {
		return result, err
	}
	if base.Ref != change.SourceSnapshot || base.Renderer != change.Renderer || base.OwnershipManifest != change.OwnershipManifest {
		return result, fault(api.CodeConflict, "policy render source generation changed")
	}
	next, err := nextOrgSnapshot(orgApply{Snapshot: base, Change: change}, api.ChangeReceipt{})
	if err != nil {
		return result, err
	}
	if !policy.HasCanonical(next) {
		return result, orgrender.ErrNativeRender
	}
	// This is the editable staged source view at its base generation. The
	// published generation is compiled independently after exact approval.
	preview := next
	preview.Ref.Generation = base.Ref.Generation
	// Source compilation uses the base publication's derived shape. Native
	// outputs belong to the proposed next generation, including generation one
	// whose approved baseline must still have an explicit empty Derived array.
	preview.Derived = base.Derived
	for group, files := range [][]api.ResourceFile{preview.Sources, preview.Derived} {
		copy := append([]api.ResourceFile{}, files...)
		for i := range copy {
			copy[i].Source.Generation = base.Ref.Generation
			copy[i].RevisionGeneration = min(copy[i].RevisionGeneration, base.Ref.Generation)
		}
		if group == 0 {
			preview.Sources = copy
		} else {
			preview.Derived = copy
		}
	}
	var current api.EffectivePolicy
	if err := storedProjection(ctx, s.db, "policy", api.ID(scope.Config), &current); err != nil {
		return result, err
	}
	current.Generation++
	internal := api.Scope{Config: scope.Config, Actor: api.Actor{Kind: "service", ID: "lb-v2-grants"}, Source: "service", PolicyGeneration: current.Generation}
	view, err := policy.CompileCanonical(ctx, canonicalReader{store: s, db: s.db, org: preview}, internal, current, preview)
	if err != nil {
		return result, err
	}
	var markdown bytes.Buffer
	fmt.Fprintf(&markdown, "# Approved policy preview\n\nLevel %d; role %s.\n", view.Policy.Context.Level, view.Policy.Context.Role)
	for _, rule := range view.Policy.Rules {
		fmt.Fprintf(&markdown, "\n- %s [%s]: %s\n  Instead: %s\n", rule.ID, rule.Band, rule.Text, rule.Instead)
	}
	inputs := []api.BlobRef{change.Reason}
	for _, file := range next.Sources {
		inputs = append(inputs, file.Content)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer finish(tx, &resultErr)
	now := api.Timestamp(s.deps.Clock.Now().UTC().Format(time.RFC3339Nano))
	retain := func(kind string, raw []byte, refs []api.BlobRef) (api.BlobRef, error) {
		return s.retain(ctx, tx, internal, api.ObjectWrite{ObjectKey: api.ID("render-" + hash([]byte(string(reserved.Operation.ID) + ":" + string(change.ID) + ":" + kind))[:32]), Class: "artifact", Bytes: raw, SHA256: api.Digest(hash(raw)), Origin: "service", InputRefs: refs,
			ACL: api.ObjectACL{Config: scope.Config, Owner: scope.Actor, LifeID: scope.Actor.LifeID, Audience: "owner", Generation: 1}}, reserved.Operation.ID, now)
	}
	derived, err := retain("policy", markdown.Bytes(), inputs)
	if err != nil {
		return result, err
	}
	delta := api.ResourceDelta{Path: renderedPolicyPath, Action: "add", After: &derived, Mode: 0444}
	for _, file := range base.Derived {
		if file.Source.Path == renderedPolicyPath {
			delta.Action, delta.BeforeSHA256 = "replace", file.Source.SHA256
		}
	}
	result = change
	result.Derived = []api.ResourceDelta{}
	for _, file := range change.Derived {
		if file.Path != renderedPolicyPath {
			result.Derived = append(result.Derived, file)
		}
	}
	result.Derived = append(result.Derived, delta)
	sort.Slice(result.Derived, func(i, j int) bool { return result.Derived[i].Path < result.Derived[j].Path })
	var diff bytes.Buffer
	for group, deltas := range [][]api.ResourceDelta{result.Files, result.Derived} {
		ordered := append([]api.ResourceDelta{}, deltas...)
		sort.Slice(ordered, func(i, j int) bool { return ordered[i].Path < ordered[j].Path })
		original := base.Sources
		if group == 1 {
			original = base.Derived
		}
		for _, file := range ordered {
			fmt.Fprintf(&diff, "--- %s\n+++ %s\n", file.Path, file.Path)
			for _, old := range original {
				if old.Source.Path != file.Path {
					continue
				}
				_, raw, err := objectRow(ctx, tx, old.Content.ID)
				if err != nil {
					return result, err
				}
				for _, line := range bytes.Split(raw, []byte("\n")) {
					fmt.Fprintf(&diff, "-%s\n", line)
				}
			}
			if file.After != nil {
				_, raw, err := objectRow(ctx, tx, file.After.ID)
				if err != nil {
					return result, err
				}
				for _, line := range bytes.Split(raw, []byte("\n")) {
					fmt.Fprintf(&diff, "+%s\n", line)
				}
			}
		}
	}
	for _, file := range result.Derived {
		if file.After != nil {
			inputs = append(inputs, *file.After)
		}
	}
	result.Diff, err = retain("diff", diff.Bytes(), inputs)
	if err != nil {
		return result, err
	}
	result.ManifestSHA256, err = approval.ManifestDigest(result)
	if err != nil {
		return result, err
	}
	if err := approval.ValidateRenderedChange(change, result); err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	return result, nil
}
