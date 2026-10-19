//go:build linux

package store_test

import (
	"bytes"
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/policy"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
	"laneboss.io/laneboss/internal/v2/templates"
)

func TestItem4PublicBriefStartRealStore(t *testing.T) {
	f := publicBriefingFixture(t)
	ctx := context.Background()
	org, err := f.State.OrgSnapshot(ctx, f.Human, api.OrgSnapshotRequest{OrgID: api.ID(f.Deps.Config), Generation: 1})
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.State.Policy(ctx, f.Human)
	if err != nil {
		t.Fatal(err)
	}
	var workflow api.ResourceFile
	for _, file := range org.Sources {
		if file.Source.Path == templates.WorkflowPath {
			workflow = file
		}
	}
	chunk, err := f.State.Blob(ctx, f.Human, api.BlobReadRequest{ObjectID: workflow.Content.ID, Limit: api.MaxChunkBytes})
	if err != nil {
		t.Fatal(err)
	}
	thresholds := api.Thresholds{Match: .85, UncertainLow: .4, UncertainHigh: .6, CalibrationID: "component-calibration"}
	rules, err := templates.SeedRules(templates.Source{Ref: workflow.Source, Bytes: chunk.Data}, thresholds)
	if err != nil {
		t.Fatal(err)
	}
	p, err = policy.Resolve(3, p.Context, []policy.Layer{{Source: workflow.Source, Thresholds: thresholds, Rules: rules, Skip: []api.SkipEntry{}}}, p.Judge, 14*86400)
	if err != nil {
		t.Fatal(err)
	}
	f.Replace(t, "policy", api.ID(f.Deps.Config), p.Generation, p)
	f.Lane.State = "running"
	f.Replace(t, "lane", f.Lane.LifeID, f.Lane.Generation, f.Lane)
	f.Human.PolicyGeneration = p.Generation
	request := api.BriefingRequest{Level: f.Lane.Level, Role: f.Lane.Role, LifeID: f.Lane.LifeID}
	f.Human.Request = api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: f.Deps.Config, Method: "brief.start", RequestID: fx.ID(t), Params: fx.JSON(t, request)}
	f.Human.Frame = &fx.Frame{Raw: fx.JSON(t, f.Human.Request)}
	rulesService, err := policy.NewInstalled(policy.Dependencies{Store: f.State, Judge: &struct{ api.ScopedJudge }{}, Clock: fx.Clock{}, MaxCostMicros: 19})
	if err != nil {
		t.Fatal(err)
	}
	service, err := templates.New(templates.Dependencies{Store: f.State, Policy: rulesService, Clock: fx.Clock{}})
	if err != nil {
		t.Fatal(err)
	}
	brief, err := service.BriefStart(ctx, f.Human, request)
	if err != nil {
		t.Fatal("public brief.start did not render and retain its real store inputs", err)
	}
	prompt, err := f.State.Blob(ctx, f.Human, api.BlobReadRequest{ObjectID: brief.Markdown.ID, Limit: api.MaxChunkBytes})
	if err != nil {
		t.Fatal(err)
	}
	task, err := f.State.Blob(ctx, f.Human, api.BlobReadRequest{ObjectID: f.Lane.Task.ID, Limit: api.MaxChunkBytes})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(prompt.Data, task.Data) || !bytes.Contains(prompt.Data, []byte("laneboss org blacklist list")) || brief.PolicyGeneration != p.Generation {
		t.Fatal("public briefing lost its assigned task, policy or rule discovery")
	}
	current, err := f.State.Lane(ctx, f.Human, f.Reservation.Target)
	if err != nil || current.Generation != f.Lane.Generation || current.Run != f.Lane.Run {
		t.Fatal("public briefing changed the running life", err)
	}
	renderRequest := api.TemplateRequest{Context: p.Context, Task: f.Lane.Task, GrantSetID: f.Lane.GrantSetID}
	f.Human.Request.Method, f.Human.Request.RequestID, f.Human.Request.Params = "brief.render", fx.ID(t), fx.JSON(t, renderRequest)
	f.Human.Frame = &fx.Frame{Raw: fx.JSON(t, f.Human.Request)}
	rendered, err := service.BriefRender(ctx, f.Human, renderRequest)
	if err != nil || rendered.Markdown.SHA256 != brief.Markdown.SHA256 {
		t.Fatal("public brief.render did not retain the same authentic prompt", err)
	}
	configRequest := api.ConfigReadRequest{View: "path"}
	f.Human.Request.Method, f.Human.Request.RequestID, f.Human.Request.Params = "config.read", fx.ID(t), fx.JSON(t, configRequest)
	f.Human.Frame = &fx.Frame{Raw: fx.JSON(t, f.Human.Request)}
	view, err := f.State.BeginRead(ctx, f.Human)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := view.Close(); err != nil {
			t.Error(err)
		}
	}()
	f.Human.ReadView = view
	projection, err := rulesService.ConfigRead(ctx, f.Human, configRequest)
	if err != nil || projection.Projection.ID == "" {
		t.Fatal("public config projection could not read back its retained output after the pinned input snapshot", err)
	}
}
