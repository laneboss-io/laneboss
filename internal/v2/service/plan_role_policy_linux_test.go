//go:build linux

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/policy"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
	"laneboss.io/laneboss/internal/v2/templates"
)

// The ticket is explicit component enrollment data, as in fx.New. Reservation,
// source selection, prompt reads and canonical policy resolution use the real
// store. No helper, judge result or authenticated model execution is invented.
func canonicalPromptFixture(t *testing.T, role api.RoleContext) (*fx.Fixture, api.LaunchPromptRequest, api.EffectivePolicy, map[api.ID]api.SourceRef) {
	t.Helper()
	ctx := context.Background()
	f := fx.New(t)
	ticket, err := f.State.Ticket(ctx, f.Human, f.Start.RootTicketID)
	if err != nil {
		t.Fatal(err)
	}
	ticket.Level, ticket.Role = role.Level, role.Role
	f.Replace(t, "ticket", ticket.ID, 1, struct {
		RedeemedBy         api.ID
		PrincipalID        api.ID
		Config             string
		EndpointGeneration api.Generation
		Ticket             api.Ticket
	}{PrincipalID: ticket.PrincipalID, Config: ticket.Config, EndpointGeneration: ticket.EndpointGeneration, Ticket: ticket})
	f.Start.Level, f.Start.Role = role.Level, role.Role
	f.Admit(t, "lane.start", f.Start)
	installPlanningOrg(t, f)
	org, err := f.State.OrgSnapshot(ctx, f.Execution, api.OrgSnapshotRequest{OrgID: api.ID(f.Deps.Config), Generation: 1})
	if err != nil {
		t.Fatal(err)
	}
	judge := policy.DefaultJudgeConfig(fx.Digest([]byte("component deployment")), fx.Digest([]byte("component tokenizer")), 256)
	halfLife, relevance, exclusions := int64(3600), .5, []api.ID{}
	objects, layers := []api.ObjectWrite{}, []policy.Layer{}
	want := map[api.ID]api.SourceRef{}
	for _, pair := range []api.RoleContext{{}, {Level: 3, Role: "executor"}, {Level: 3, Role: "tester"},
		{Level: 3, Role: "fallback"}, {Level: 4, Role: "reviewer"}, {Level: 5, Role: "supervisor"}, {Level: 6, Role: "supervisor"}} {
		path := policy.CanonicalPath
		var defining *api.RoleContext
		if pair.Level != 0 {
			path = fmt.Sprintf(".laneboss/L%d/policy/%s.json", pair.Level, pair.Role)
			copy := pair
			defining = &copy
		}
		thresholds := api.Thresholds{Match: .8, UncertainLow: .4, UncertainHigh: .6, CalibrationID: "component-calibration"}
		rule := api.Rule{ID: fx.ID(t), Text: "Retain evidence from " + path + ".", Instead: "Retain the measured result.",
			Band: "refuse", Scope: api.RuleScope{Levels: []int{}, Roles: []string{}}}
		doc := policy.CanonicalDocument{Schema: "laneboss.policy-source.v2", Thresholds: thresholds,
			Rules: []api.Rule{rule}, Skip: []api.SkipEntry{}, Settings: []api.SettingValue{}}
		if defining == nil {
			doc.Judge, doc.GuidanceHalfLifeSeconds = &judge, &halfLife
			doc.GuidanceMinRelevance, doc.ProfileExclusions = &relevance, &exclusions
		}
		raw := fx.JSON(t, doc)
		ref := api.BlobRef{ID: fx.ID(t), Class: "policy", SHA256: fx.Digest(raw), Bytes: int64(len(raw))}
		source := api.SourceRef{ID: fx.ID(t), Path: path, SHA256: ref.SHA256, Generation: 1}
		org.Sources = append(org.Sources, api.ResourceFile{Source: source, Content: ref, Kind: "policy", Mode: 0444, RevisionGeneration: 1})
		objects = append(objects, api.ObjectWrite{ObjectKey: ref.ID, Class: ref.Class, SHA256: ref.SHA256, Bytes: raw, Origin: "service",
			ACL: api.ObjectACL{Config: f.Deps.Config, Owner: f.Execution.Actor, Audience: "config", Generation: 1}})
		layers = append(layers, policy.Layer{Source: source, DefinedAt: defining, Thresholds: thresholds, Rules: []api.Rule{rule}, Skip: []api.SkipEntry{}})
		if defining == nil || pair == role || pair.Level > role.Level {
			want[rule.ID] = source
		}
	}
	workflow, err := os.ReadFile(filepath.Join("..", "..", "..", "templates", "v2", "org", "workflow.toml"))
	if err != nil {
		t.Fatal(err)
	}
	workflowRef := api.BlobRef{ID: fx.ID(t), Class: "policy", SHA256: fx.Digest(workflow), Bytes: int64(len(workflow))}
	org.Sources = append(org.Sources, api.ResourceFile{Source: api.SourceRef{ID: fx.ID(t), Path: templates.WorkflowPath,
		SHA256: workflowRef.SHA256, Generation: 1}, Content: workflowRef, Kind: "policy", Mode: 0444, RevisionGeneration: 1})
	objects = append(objects, api.ObjectWrite{ObjectKey: workflowRef.ID, Class: workflowRef.Class, SHA256: workflowRef.SHA256, Bytes: workflow, Origin: "service",
		ACL: api.ObjectACL{Config: f.Deps.Config, Owner: f.Execution.Actor, Audience: "config", Generation: 1}})
	cause := f.Intent(t, api.InternalObjectRetain)
	if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause, Writes: api.StateWrites{Objects: objects}}); err != nil {
		t.Fatal(err)
	}
	head, err := policy.Resolve(1, api.RoleContext{Level: 5, Role: "supervisor"}, layers, judge, halfLife)
	if err != nil {
		t.Fatal(err)
	}
	f.Replace(t, "org", api.ID(f.Deps.Config), 1, org)
	f.Replace(t, "policy", api.ID(f.Deps.Config), head.Generation, head)
	f.Reserve(t)
	f.Source(t)
	return f, api.LaunchPromptRequest{ReservationID: f.Reservation.ID, Lease: f.Claim}, head, want
}

func TestLaunchPromptCanonicalRoles(t *testing.T) {
	for _, role := range []api.RoleContext{{Level: 6, Role: "supervisor"}, {Level: 5, Role: "supervisor"},
		{Level: 4, Role: "reviewer"}, {Level: 3, Role: "executor"}, {Level: 3, Role: "tester"}, {Level: 3, Role: "fallback"}} {
		t.Run(fmt.Sprintf("L%d-%s", role.Level, role.Role), func(t *testing.T) {
			f, request, head, want := canonicalPromptFixture(t, role)
			ctx := context.Background()
			input, err := f.State.LaunchBriefingInput(ctx, f.Execution, request)
			if err != nil {
				t.Fatal("approved canonical launch role could not prepare its prompt", err)
			}
			if input.Lane == nil || input.Lane.Level != role.Level || input.Lane.Role != role.Role || input.Policy.Context != role ||
				input.Policy.Generation != f.Reservation.PolicyGeneration || len(input.Policy.Rules) != len(want) {
				t.Fatal("launch prompt did not select its reserved role and complete inherited policy")
			}
			seen := map[api.ID]bool{}
			for _, rule := range input.Policy.Rules {
				if source, ok := want[rule.ID]; !ok || source != rule.Source || seen[rule.ID] {
					t.Fatal("launch prompt relabelled the default policy or lost source provenance")
				}
				seen[rule.ID] = true
			}
			if role != head.Context && input.Policy.SHA256 == head.SHA256 {
				t.Fatal("another role reused the default policy digest")
			}
			renderer, err := templates.New(templates.Dependencies{Store: f.State, Policy: &policy.Service{}, Clock: fx.Clock{}})
			if err != nil {
				t.Fatal(err)
			}
			brief, err := renderer.LaunchBriefing(ctx, f.Execution, request)
			if err != nil || brief.PolicyGeneration != f.Reservation.PolicyGeneration || brief.Markdown.ID == "" {
				t.Fatal("canonical launch role could not render and retain its actual briefing", err)
			}
			markdown, err := f.State.Blob(ctx, f.Execution, api.BlobReadRequest{ObjectID: brief.Markdown.ID, Limit: api.MaxChunkBytes})
			if err != nil || len(markdown.Data) == 0 || int64(len(markdown.Data)) != brief.Markdown.Bytes || fx.Digest(markdown.Data) != brief.Markdown.SHA256 {
				t.Fatal("canonical launch briefing lost its measured retained bytes", err)
			}
			current, err := f.State.Policy(ctx, f.Execution)
			if err != nil || !reflect.DeepEqual(current, head) {
				t.Fatal("launch prompt changed the approved default policy", err)
			}
			// A role-specific read must still verify the approved default's
			// source digest. It cannot repair or merely relabel a corrupt head.
			corrupt := head
			corrupt.SHA256 = fx.Digest([]byte("different approved source bytes"))
			f.Replace(t, "policy", api.ID(f.Deps.Config), corrupt.Generation, corrupt)
			input, err = f.State.LaunchBriefingInput(ctx, f.Execution, request)
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeIntegrity || typed.Message != "canonical sources differ from the approved policy digest" || input.Lane != nil {
				t.Fatal("launch prompt bypassed the approved canonical source digest", err)
			}
		})
	}
}
