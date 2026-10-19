//go:build linux

package store_test

import (
	"context"
	"encoding/json"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

func judgeViewFixture(t *testing.T) *fx.Fixture {
	t.Helper()
	f := publicBriefingFixture(t)
	snapshot, err := f.State.OrgSnapshot(context.Background(), f.Human, api.OrgSnapshotRequest{OrgID: api.ID(f.Deps.Config), Generation: 1})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := f.State.Policy(context.Background(), f.Human)
	if err != nil {
		t.Fatal(err)
	}
	policy.Sources = []api.SourceRef{}
	for _, file := range snapshot.Sources {
		policy.Sources = append(policy.Sources, file.Source)
	}
	policy.Generation++
	f.Human.PolicyGeneration = policy.Generation
	f.Replace(t, "policy", api.ID(f.Deps.Config), policy.Generation, policy)
	f.Human.Request = api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: f.Deps.Config, Method: "judge.list", RequestID: fx.ID(t), Params: []byte("{}")}
	f.Human.Frame = &fx.Frame{Raw: fx.JSON(t, f.Human.Request)}
	return f
}

func TestItem4JudgeView(t *testing.T) {
	f := judgeViewFixture(t)
	view, err := f.State.JudgeView(context.Background(), f.Human)
	if err != nil || view.Projection.ID == "" {
		t.Fatal("judge list has no actual protected projection", err)
	}
	read := f.Human
	chunk, err := f.State.Blob(context.Background(), read, api.BlobReadRequest{ObjectID: view.Projection.ID, Limit: api.MaxChunkBytes})
	if err != nil {
		t.Fatal(err)
	}
	var result api.JudgeView
	if err := json.Unmarshal(chunk.Data, &result); err != nil || result.Config != f.Deps.Config || result.Judge.Provider != api.DefaultJudgeProvider || result.Judge.Model != api.DefaultJudgeModel || len(result.Sources) != 3 {
		t.Fatal("judge projection omitted its actual approved policy", err)
	}
	again, err := f.State.JudgeView(context.Background(), f.Human)
	if err != nil || again.Projection != view.Projection {
		t.Fatal("same read frame did not retain immutable projection", err)
	}
	foreign := f.Human
	foreign.Config = "foreign"
	if _, err := f.State.JudgeView(context.Background(), foreign); err == nil {
		t.Fatal("foreign scope obtained judge projection")
	}
}
