//go:build linux

package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/policy"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
	"laneboss.io/laneboss/internal/v2/templates"
)

func TestBriefingClaimBeforePolicy(t *testing.T) {
	for _, claim := range []string{"role", "grants"} {
		t.Run(claim, func(t *testing.T) {
			f := publicBriefingFixture(t)
			request := api.BriefingInputRequest{}
			if claim == "role" {
				request.Context = api.RoleContext{Level: f.Lane.Level, Role: "foreign"}
			} else {
				request.GrantSetID = fx.ID(t)
			}
			// Poison only the unrelated policy projection. A forged request
			// must be rejected against its authentic life before reading it.
			f.Replace(t, "policy", api.ID(f.Deps.Config), 2, api.EffectivePolicy{})
			got, err := f.State.BriefingInput(context.Background(), f.Human, request)
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeForbidden || got.Task != nil {
				t.Fatal("briefing selected policy before rejecting its foreign claim", err)
			}
		})
	}
}

func canonicalFixture(t *testing.T, poison string) *fx.Fixture {
	t.Helper()
	f := publicBriefingFixture(t)
	ctx := context.Background()
	org, err := f.State.OrgSnapshot(ctx, f.Human, api.OrgSnapshotRequest{OrgID: api.ID(f.Deps.Config), Generation: 1})
	if err != nil {
		t.Fatal(err)
	}
	old, err := f.State.Policy(ctx, f.Human)
	if err != nil {
		t.Fatal(err)
	}
	objects := []api.ObjectWrite{}
	layers := []policy.Layer{}
	for i, pair := range []api.RoleContext{{}, {Level: 3, Role: "executor"}, {Level: 5, Role: "supervisor"}, {Level: 5, Role: "peer"}, {Level: 6, Role: "chief"}} {
		path := ".laneboss/policy.json"
		var defining *api.RoleContext
		if pair.Level != 0 {
			path = fmt.Sprintf(".laneboss/L%d/policy/%s.json", pair.Level, pair.Role)
			copy := pair
			defining = &copy
		}
		thresholds := api.Thresholds{Match: .8 + float64(i)/100, UncertainLow: .4, UncertainHigh: .6, CalibrationID: "component-calibration"}
		rules := []api.Rule{{ID: api.ID(fmt.Sprintf("rule-%d", i)), Text: fmt.Sprintf("Retain measured result %d.", i), Instead: "Retain the actual evidence.", Band: "refuse", Scope: api.RuleScope{Levels: []int{}, Roles: []string{}}}}
		settings := []api.SettingValue{}
		if i == 0 || pair.Role == "supervisor" {
			model := fmt.Sprintf("approved-model-%d", i)
			settings = append(settings, api.SettingValue{Key: "model", String: &model})
		}
		doc := map[string]any{"schema": "laneboss.policy-source.v2", "thresholds": thresholds, "rules": rules, "skip": []api.SkipEntry{}, "settings": settings}
		if i == 0 {
			doc["judge"], doc["guidance_half_life_seconds"] = old.Judge, int64(14*86400)
			doc["guidance_min_relevance"], doc["profile_exclusions"] = .5, []api.ID{}
		}
		if poison == "unselected" && pair.Level == 3 {
			doc["thresholds"] = api.Thresholds{Match: 2}
		}
		body := fx.JSON(t, doc)
		if poison == "duplicate" && i == 0 {
			body = append(body[:len(body)-1], []byte(",\"schema\":\"laneboss.policy-source.v2\"}")...)
		}
		ref := api.BlobRef{ID: fx.ID(t), Class: "policy", SHA256: fx.Digest(body), Bytes: int64(len(body))}
		file := api.ResourceFile{Source: api.SourceRef{ID: fx.ID(t), Path: path, SHA256: ref.SHA256, Generation: 1}, Content: ref, Kind: "policy", Mode: 0444, RevisionGeneration: 1}
		org.Sources = append(org.Sources, file)
		objects = append(objects, api.ObjectWrite{ObjectKey: ref.ID, Class: ref.Class, SHA256: ref.SHA256, Bytes: body, Origin: "service", ACL: api.ObjectACL{Config: f.Deps.Config, Owner: f.Execution.Actor, Audience: "config", Generation: 1}})
		layers = append(layers, policy.Layer{Source: file.Source, DefinedAt: defining, Thresholds: thresholds, Rules: rules, Skip: []api.SkipEntry{}})
	}
	for _, name := range []string{"plugins/sample.txt", "channels/default.json"} {
		body := []byte("declared component resource " + name)
		ref := api.BlobRef{ID: fx.ID(t), Class: "artifact", SHA256: fx.Digest(body), Bytes: int64(len(body))}
		org.Sources = append(org.Sources, api.ResourceFile{Source: api.SourceRef{ID: fx.ID(t), Path: name, SHA256: ref.SHA256, Generation: 1}, Content: ref, Kind: "source", Mode: 0444, RevisionGeneration: 1})
		objects = append(objects, api.ObjectWrite{ObjectKey: ref.ID, Class: ref.Class, SHA256: ref.SHA256, Bytes: body, Origin: "service", ACL: api.ObjectACL{Config: f.Deps.Config, Owner: f.Execution.Actor, Audience: "config", Generation: 1}})
	}
	cause := api.InternalIntent{ID: fx.ID(t), Kind: api.InternalObjectRetain, Config: f.Deps.Config, Actor: f.Execution.Actor, RequestedBy: f.Human.Actor}
	if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause, Writes: api.StateWrites{Objects: objects}}); err != nil {
		t.Fatal(err)
	}
	// The retained default projection is for another role. The reader must
	// construct the actual lane's union from the approved source inventory.
	p, err := policy.Resolve(3, api.RoleContext{Level: 6, Role: "chief"}, layers, old.Judge, 14*86400)
	if poison == "unselected" {
		// Keep the projection valid: only the actual unselected source is bad.
		layers[1].Thresholds = layers[0].Thresholds
		p, err = policy.Resolve(3, api.RoleContext{Level: 6, Role: "chief"}, layers, old.Judge, 14*86400)
	}
	if err != nil {
		t.Fatal(err)
	}
	f.Replace(t, "org", api.ID(f.Deps.Config), 1, org)
	f.Replace(t, "policy", api.ID(f.Deps.Config), 3, p)
	f.Human.PolicyGeneration, f.Execution.PolicyGeneration = 3, 3
	return f
}

func TestCanonicalPolicyRealStore(t *testing.T) {
	f := canonicalFixture(t, "")
	request := api.BriefingInputRequest{Context: api.RoleContext{Level: f.Lane.Level, Role: f.Lane.Role}}
	got, err := f.State.BriefingInput(context.Background(), f.Human, request)
	if err != nil {
		t.Fatal("canonical briefing did not select the authentic role before policy", err)
	}
	ids := []api.ID{}
	for _, rule := range got.Policy.Rules {
		ids = append(ids, rule.ID)
	}
	if !reflect.DeepEqual(ids, []api.ID{"rule-0", "rule-2", "rule-4"}) || math.Abs(got.Policy.Rules[1].Thresholds.Match-.82) > 1e-12 {
		t.Fatal("canonical reader omitted a defining layer or inherited lower/peer policy", ids)
	}
	again, err := f.State.BriefingInput(context.Background(), f.Human, request)
	if err != nil || !reflect.DeepEqual(got, again) {
		t.Fatal("canonical read changed on exact replay", err)
	}
}

func TestCanonicalPolicyRefresh(t *testing.T) {
	f := canonicalFixture(t, "")
	ctx := context.Background()
	selected, err := f.State.Policy(ctx, f.Human)
	if err != nil {
		t.Fatal(err)
	}
	before, err := f.State.Lane(ctx, f.Human, f.Reservation.Target)
	if err != nil {
		t.Fatal(err)
	}
	request := api.PolicyAdvanceRequest{Target: f.Reservation.Target, ExpectedLaneGeneration: before.Generation,
		FromGeneration: before.PolicyGeneration, ToGeneration: selected.Generation, CancellationEpoch: before.CancellationEpoch}
	receipt, err := f.State.RefreshLanePolicy(ctx, f.Execution, request)
	if err != nil || receipt.Event.PolicySHA256 != selected.SHA256 || receipt.Event.GrantSetID != before.GrantSetID {
		t.Fatal("policy refresh journal used another role's policy digest", err)
	}
	if err := api.ValidatePolicyAdvance(before, request, selected, receipt); err != nil {
		t.Fatal("role policy refresh changed its actual life fence", err)
	}
	org, err := f.State.OrgSnapshot(ctx, f.Human, api.OrgSnapshotRequest{OrgID: api.ID(f.Deps.Config), Generation: 1})
	if err != nil {
		t.Fatal(err)
	}
	kept := []api.ResourceFile{}
	for _, file := range org.Sources {
		if file.Source.Path != policy.CanonicalPath && !strings.Contains(file.Source.Path, "/policy/") {
			kept = append(kept, file)
		}
	}
	org.Sources = kept
	f.Replace(t, "org", api.ID(f.Deps.Config), 1, org)
	request.ExpectedLaneGeneration, request.FromGeneration = receipt.Lane.Generation, receipt.Lane.PolicyGeneration
	_, err = f.State.RefreshLanePolicy(ctx, f.Execution, request)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodePrerequisite {
		t.Fatal("policy writer used a flattened fallback after losing canonical enrollment", err)
	}
}

func TestCanonicalJudgeView(t *testing.T) {
	f := canonicalFixture(t, "")
	ctx := context.Background()
	selected, err := f.State.Policy(ctx, f.Human)
	if err != nil {
		t.Fatal(err)
	}
	f.Human.Request = api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: f.Deps.Config, Method: "judge.list", RequestID: fx.ID(t), Params: fx.JSON(t, api.Empty{})}
	f.Human.Frame = &fx.Frame{Raw: fx.JSON(t, f.Human.Request)}
	view, err := f.State.JudgeView(ctx, f.Human)
	if err != nil {
		t.Fatal("judge view selected another role's policy", err)
	}
	chunk, err := f.State.Blob(ctx, f.Human, api.BlobReadRequest{ObjectID: view.Projection.ID, Limit: api.MaxChunkBytes})
	var projection api.JudgeView
	if err != nil || json.Unmarshal(chunk.Data, &projection) != nil || projection.Context != selected.Context || projection.PolicySHA256 != selected.SHA256 || !reflect.DeepEqual(projection.Sources, selected.Sources) {
		t.Fatal("judge view lost its canonical role, policy digest or consumed sources", err)
	}
}

func TestConfigViewsRealStore(t *testing.T) {
	for _, name := range []string{"show", "settings", "roles", "plugins", "channels"} {
		t.Run(name, func(t *testing.T) {
			f := canonicalFixture(t, "")
			request := api.ConfigReadRequest{View: name}
			f.Human.Request = api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: f.Deps.Config, Method: "config.read", RequestID: fx.ID(t), Params: fx.JSON(t, request)}
			f.Human.Frame = &fx.Frame{Raw: fx.JSON(t, f.Human.Request)}
			service, err := policy.NewInstalled(policy.Dependencies{Store: f.State, Judge: &struct{ api.ScopedJudge }{}, Clock: fx.Clock{}})
			if err != nil {
				t.Fatal(err)
			}
			view, err := service.ConfigRead(context.Background(), f.Human, request)
			if err != nil {
				t.Fatal("complete canonical configuration view refused", err)
			}
			chunk, err := f.State.Blob(context.Background(), f.Human, api.BlobReadRequest{ObjectID: view.Projection.ID, Limit: api.MaxChunkBytes})
			var got api.ConfigProjection
			if err != nil || json.Unmarshal(chunk.Data, &got) != nil || got.View != name || got.Generation != 1 || got.Context.Level != f.Lane.Level || got.Context.Role != f.Lane.Role {
				t.Fatal("configuration projection lost its actual scope or generation", err)
			}
			if name == "show" || name == "settings" {
				if len(got.Settings) != 1 || got.Settings[0].String == nil || *got.Settings[0].String != "approved-model-2" || got.Settings[0].Source.Path != ".laneboss/L5/policy/supervisor.json" {
					t.Fatal("settings lost the value or actual defining source")
				}
			}
			if name == "show" || name == "roles" {
				if len(got.Names) != 4 {
					t.Fatal("role catalog is incomplete", got.Names)
				}
			}
			wantResources := 0
			if name == "show" {
				wantResources = 2
			}
			if name == "plugins" || name == "channels" {
				wantResources = 1
			}
			if len(got.Resources) != wantResources {
				t.Fatal("resource catalog is incomplete")
			}
			for _, resource := range got.Resources {
				if !resource.Declared || resource.VerifiedLoaded || resource.Source.ID == "" || resource.Source.SHA256 != resource.SHA256 {
					t.Fatal("resource declaration invented verified loading or lost its content pin")
				}
			}
		})
	}
}

func TestConfigInstanceBinding(t *testing.T) {
	f := canonicalFixture(t, "")
	role := api.RoleContext{Level: f.Lane.Level, Role: f.Lane.Role, InstanceID: f.Human.Actor.ID}
	request := api.ConfigReadRequest{View: "show", Context: &role}
	f.Human.Request = api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: f.Deps.Config, Method: "config.read", RequestID: fx.ID(t), Params: fx.JSON(t, request)}
	f.Human.Frame = &fx.Frame{Raw: fx.JSON(t, f.Human.Request)}
	service, err := policy.NewInstalled(policy.Dependencies{Store: f.State, Judge: &struct{ api.ScopedJudge }{}, Clock: fx.Clock{}})
	if err != nil {
		t.Fatal(err)
	}
	view, err := service.ConfigRead(context.Background(), f.Human, request)
	if err != nil {
		t.Fatal("current authenticated instance cannot read its configuration", err)
	}
	chunk, err := f.State.Blob(context.Background(), f.Human, api.BlobReadRequest{ObjectID: view.Projection.ID, Limit: api.MaxChunkBytes})
	var projection api.ConfigProjection
	if err != nil || json.Unmarshal(chunk.Data, &projection) != nil || projection.Context == nil || *projection.Context != role {
		t.Fatal("configuration did not retain its authenticated instance context", err)
	}
	foreign := role
	foreign.InstanceID = fx.ID(t)
	if _, err := service.ConfigRead(context.Background(), f.Human, api.ConfigReadRequest{View: "show", Context: &foreign}); err == nil {
		t.Fatal("foreign instance was treated as this native binding")
	}
}

func TestCanonicalUnfundedEval(t *testing.T) {
	f := canonicalFixture(t, "")
	ctx := context.Background()
	command := []byte("read current approved policy\n")
	request := api.PolicyEvaluateRequest{Target: f.Reservation.Target, LogicalTurnID: f.Lane.LogicalTurnID,
		Command: api.CommandData{Tool: "shell", Command: command, RawSHA256: fx.Digest(command), CWD: f.Lane.Workspace.LogicalCWD, Argv: []string{}, DeclaredPaths: []string{}}}
	f.Admit(t, "policy.evaluate", request)
	service, err := policy.NewInstalled(policy.Dependencies{Store: f.State, Judge: &struct{ api.ScopedJudge }{}, Clock: fx.Clock{}})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := service.PolicyEvaluate(ctx, f.Human, request)
	if err != nil {
		t.Fatal("installed canonical evaluation could not finish its unfunded audit", err)
	}
	if decision.Result != "allow" || !decision.AuditComplete || len(decision.Rules) != 3 {
		t.Fatal("ordinary canonical work lost its actual unscored audit")
	}
	for _, rule := range decision.Rules {
		if rule.Probability != nil || rule.Result != "allow" || !strings.Contains(rule.Reason, "budget_exhausted") {
			t.Fatal("unfunded canonical rule invented a judgment")
		}
	}
	retained, err := f.State.LookupReceipt(ctx, f.Human, api.RequestKey{Method: f.Human.Request.Method, IdempotencyKey: f.Human.Request.IdempotencyKey, RequestSHA256: f.Human.Request.RequestSHA256})
	var durable api.PolicyDecision
	if err != nil || retained.Reply == nil || retained.Operation.ID != f.Receipt.Operation.ID || json.Unmarshal(retained.Reply.Result, &durable) != nil || !reflect.DeepEqual(decision, durable) {
		t.Fatal("canonical evaluation did not seal its original public operation", err)
	}
	chunk, err := f.State.Blob(ctx, f.Human, api.BlobReadRequest{ObjectID: decision.Input.ID, Limit: api.MaxChunkBytes})
	var input struct {
		Request         api.PolicyEvaluateRequest
		CostLimitMicros int64 `json:"cost_limit_micros"`
		Batches         []struct{ Error string }
	}
	if err != nil || json.Unmarshal(chunk.Data, &input) != nil || string(input.Request.Command.Command) != string(command) || input.CostLimitMicros != 0 || len(input.Batches) != 1 || input.Batches[0].Error != "budget_exhausted" {
		t.Fatal("canonical evaluation lost its exact command or unfunded observation", err)
	}
}

func TestCanonicalSourceFences(t *testing.T) {
	for _, name := range []string{"foreign", "stale", "unselected", "duplicate", "missing", "partial_role"} {
		t.Run(name, func(t *testing.T) {
			f := canonicalFixture(t, name)
			scope := f.Human
			switch name {
			case "foreign":
				scope.Config = "foreign"
			case "stale":
				scope.PolicyGeneration++
			case "partial_role":
				org, err := f.State.OrgSnapshot(context.Background(), scope, api.OrgSnapshotRequest{OrgID: api.ID(f.Deps.Config), Generation: 1})
				if err != nil {
					t.Fatal(err)
				}
				file := org.Sources[0]
				file.Source.ID, file.Source.Path = fx.ID(t), ".laneboss/L3/roles/extra.md"
				org.Sources = append(org.Sources, file)
				f.Replace(t, "org", api.ID(f.Deps.Config), 1, org)
			case "missing":
				org, err := f.State.OrgSnapshot(context.Background(), scope, api.OrgSnapshotRequest{OrgID: api.ID(f.Deps.Config), Generation: 1})
				if err != nil {
					t.Fatal(err)
				}
				for i, file := range org.Sources {
					if file.Source.Path == ".laneboss/policy.json" {
						org.Sources = append(org.Sources[:i], org.Sources[i+1:]...)
						break
					}
				}
				f.Replace(t, "org", api.ID(f.Deps.Config), 1, org)
			}
			got, err := f.State.BriefingInput(context.Background(), scope, api.BriefingInputRequest{})
			var typed *api.Error
			if !errors.As(err, &typed) || got.Task != nil {
				t.Fatal("canonical reader accepted "+name, err)
			}
			want := api.CodeInvalid
			if name == "foreign" {
				want = api.CodeForbidden
			}
			if name == "stale" {
				want = api.CodeConflict
			}
			if name == "missing" {
				want = api.CodePrerequisite
			}
			if typed.Code != want {
				t.Fatal("canonical control failed at a different gate", name, err)
			}
		})
	}
}

func publicBriefingFixture(t *testing.T) *fx.Fixture {
	t.Helper()
	f, _ := judgeExecutionFixture(t)
	snapshot := api.OrgSnapshot{Config: f.Deps.Config, Ref: api.OrgSnapshotRef{OrgID: api.ID(f.Deps.Config), Generation: 1, ManifestSHA256: fx.Digest([]byte("source inventory"))},
		Sources: []api.ResourceFile{}, Derived: []api.ResourceFile{}, Renderer: api.Executable{ID: fx.ID(t), SHA256: fx.Digest([]byte("renderer")), Version: "fixture-v2"}}
	objects := []api.ObjectWrite{}
	for _, source := range []struct{ path, kind, file string }{{templates.OrgTemplatePath, "prompt", "default.md"}, {templates.OrgDriversPath, "drivers", "drivers.toml"}, {templates.WorkflowPath, "policy", "workflow.toml"}} {
		body, err := os.ReadFile(filepath.Join("..", "..", "..", "templates", "v2", "org", source.file))
		if err != nil {
			t.Fatal(err)
		}
		ref := api.BlobRef{ID: fx.ID(t), Class: "policy", SHA256: fx.Digest(body), Bytes: int64(len(body))}
		objects = append(objects, api.ObjectWrite{ObjectKey: ref.ID, Class: ref.Class, Bytes: body, SHA256: ref.SHA256, Origin: "service", ACL: api.ObjectACL{Config: f.Deps.Config, Owner: f.Execution.Actor, Audience: "config", Generation: 1}})
		snapshot.Sources = append(snapshot.Sources, api.ResourceFile{Source: api.SourceRef{ID: fx.ID(t), Path: source.path, SHA256: ref.SHA256, Generation: 1}, Content: ref, Kind: source.kind, Mode: 0444, RevisionGeneration: 1})
	}
	ownerBytes := []byte("protected ownership manifest")
	snapshot.OwnershipManifest = api.BlobRef{ID: fx.ID(t), Class: "manifest", SHA256: fx.Digest(ownerBytes), Bytes: int64(len(ownerBytes))}
	objects = append(objects, api.ObjectWrite{ObjectKey: snapshot.OwnershipManifest.ID, Class: "manifest", Bytes: ownerBytes, SHA256: snapshot.OwnershipManifest.SHA256, Origin: "service", ACL: api.ObjectACL{Config: f.Deps.Config, Owner: f.Execution.Actor, Audience: "config", Generation: 1}})
	cause := api.InternalIntent{ID: fx.ID(t), Kind: api.InternalObjectRetain, Config: f.Deps.Config, Actor: f.Execution.Actor, RequestedBy: f.Human.Actor}
	if _, err := f.State.Transact(context.Background(), api.Transaction{Scope: f.Execution, Internal: &cause, Writes: api.StateWrites{Objects: objects}}); err != nil {
		t.Fatal(err)
	}
	f.Replace(t, "org", api.ID(f.Deps.Config), 1, snapshot)
	return f
}

func TestItem4PublicBriefingInput(t *testing.T) {
	f := publicBriefingFixture(t)
	request := api.BriefingInputRequest{Context: api.RoleContext{Level: f.Lane.Level, Role: f.Lane.Role}}
	got, err := f.State.BriefingInput(context.Background(), f.Human, request)
	if err != nil || got.Mode != "lane" || got.Lane == nil || got.Task == nil || got.GrantSet == nil || *got.Task != f.Lane.Task || got.GrantSet.ID != f.Lane.GrantSetID || got.Sources.LocalStatus != "absent" {
		t.Fatal("public briefing did not resolve its real current life and approved sources", err)
	}
	again, err := f.State.BriefingInput(context.Background(), f.Human, request)
	if err != nil || !reflect.DeepEqual(got, again) {
		t.Fatal("read-only briefing changed its source projection", err)
	}
}

func TestItem4PublicBriefingClaims(t *testing.T) {
	for _, name := range []string{"life", "grants", "role", "stale", "missing_sources"} {
		t.Run(name, func(t *testing.T) {
			f := publicBriefingFixture(t)
			request := api.BriefingInputRequest{Context: api.RoleContext{Level: f.Lane.Level, Role: f.Lane.Role}}
			scope := f.Human
			switch name {
			case "life":
				request.LifeID = fx.ID(t)
			case "grants":
				request.GrantSetID = fx.ID(t)
			case "role":
				request.Context.Role = "reviewer"
			case "stale":
				scope.PolicyGeneration++
			case "missing_sources":
				f.Replace(t, "org", api.ID(f.Deps.Config), 1, api.OrgSnapshot{Config: f.Deps.Config})
			}
			if got, err := f.State.BriefingInput(context.Background(), scope, request); err == nil || got.Task != nil {
				t.Fatal("briefing accepted " + name)
			}
		})
	}
}
