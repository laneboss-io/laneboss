//go:build linux

package store

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/approval"
)

func TestChangedPolicyApply(t *testing.T) {
	s, deps, proposal, before := policyProposal(t)
	ctx := context.Background()
	rule := before.Rules[0]
	rule.Text, rule.Instead, rule.Source = "Do not publish customer records.", "Use an approved summary.", api.SourceRef{}
	raw := enrollmentJSON(t, map[string]any{"rules": []api.Rule{rule}, "guidance_half_life_seconds": 7200})
	ref := policyObject(t, s, raw)
	change := proposal.Writes.Changes[0]
	change.Files = append(change.Files, api.ResourceDelta{Path: before.Sources[0].Path, Action: "replace", Mode: 0600, BeforeSHA256: before.Sources[0].SHA256, After: &ref})
	sort.Slice(change.Files, func(i, j int) bool { return change.Files[i].Path < change.Files[j].Path })
	var err error
	change.ManifestSHA256, err = approval.ManifestDigest(change)
	if err != nil {
		t.Fatal(err)
	}
	proposal.Scope.Request = testRequest(t, "org.change.propose", api.ChangeProposeRequest{OrgID: change.OrgID, BaseGeneration: 1, Reason: change.Reason, Files: change.Files})
	proposal.Writes.Changes[0] = change
	proposal.Events[0].Payload = enrollmentJSON(t, api.ChangeEvent{Change: change, Reason: "actual changed policy content"})
	proposal.Reply.Result = enrollmentJSON(t, change)
	s, deps, tx := deferredChangeFrom(t, s, deps, proposal)
	if _, err := s.Transact(ctx, tx); err != nil {
		t.Fatal("approved changed policy could not reserve publication", err)
	}
	scope, lease, request := publicationClaim(t, s, tx)
	receipt, err := s.PublishChange(ctx, scope, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CompleteEffect(ctx, scope, publicationOutcome(t, tx, lease, receipt)); err != nil {
		t.Fatal(err)
	}
	after, err := s.Policy(ctx, scope)
	if err != nil || after.Generation != before.Generation+1 || len(after.Rules) != 1 || after.Rules[0].Text != rule.Text || after.Rules[0].Instead != rule.Instead || after.GuidanceHalfLifeSeconds != 7200 || after.Sources[0].SHA256 != ref.SHA256 || after.Sources[0].Generation != 2 {
		t.Fatal("applied policy did not consume its actual changed source", err)
	}
	actual, err := os.ReadFile(filepath.Join(deps.Directory, "org", "current", filepath.FromSlash(before.Sources[0].Path)))
	if err != nil || string(actual) != string(raw) {
		t.Fatal("canonical policy differs from compiled approved bytes", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(deps)
	if err != nil {
		t.Fatal("changed policy failed restart", err)
	}
	defer reopened.Close()
	if check, err := reopened.Verify(ctx, api.VerifyRequest{Scope: "all"}); err != nil || !check.OK {
		t.Fatal("changed policy failed independent verification", err)
	}
}

func TestCanonicalChannelFence(t *testing.T) {
	s, deps, tx, before := canonicalApplyFixture(t)
	ctx := context.Background()
	channel := api.EnrolledChannel{ID: testID(t), Config: deps.Config,
		Generation: 1, Source: before.Sources[0]}
	fixtureProjection(t, s, "channel", channel.ID, 1, channel)
	if _, err := s.Transact(ctx, tx); err == nil {
		t.Fatal("canonical publication skipped channel source provenance")
	} else {
		expectCode(t, err, api.CodePrerequisite)
	}
	var count int
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM effects WHERE id=?", string(tx.Deferred.EffectID)).Scan(&count); err != nil || count != 0 {
		t.Fatal("channel refusal retained a publication effect", err)
	}
	var current api.EffectivePolicy
	if err := storedProjection(ctx, s.db, "policy", api.ID(deps.Config), &current); err != nil || current.SHA256 != before.SHA256 {
		t.Fatal("channel refusal changed the approved policy", err)
	}
}
