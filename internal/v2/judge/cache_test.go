package judge

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/judge/wire"
)

func testConfig() api.JudgeConfig {
	return api.JudgeConfig{Provider: "clef-sglang", Model: "Cloudflare/clef-flash",
		DeploymentSHA256: wire.Digest([]byte("stack")),
		TokenizerSHA256:  wire.Digest([]byte("tokenizer")), ContextTokens: 16384,
		MaxBytes: api.MaxJudgeBytes, MaxQuestions: 12, CommandDeadlineMS: 2000,
		GuidanceDeadlineMS: 5000, CacheTTLMS: 30000, OutagePolicy: "critical-only"}
}

func testRequest() api.JudgeRequest {
	command := []byte("build project")
	return api.JudgeRequest{ID: "ask-one", Purpose: "blacklist", Config: testConfig(),
		Rules: []api.JudgeRule{{ID: "rule-a", Text: "Do not publish artifacts.",
			SourceSHA256: wire.Digest([]byte("rule source")), CriteriaVersion: wire.CriteriaVersion}},
		Decisions: []api.DecisionCandidate{}, Task: []byte{}, DeadlineMS: 2000,
		MaxCostMicros: 100000, Command: &api.CommandData{Tool: "shell", Command: command,
			Argv: []string{}, DeclaredPaths: []string{}, CWD: "/work", RawSHA256: wire.Digest(command)},
		Context: api.JudgeContext{Config: "example", Target: api.LifeRef{LifeID: "life-a", Run: 1},
			Role: api.RoleContext{Level: 3, Role: "executor"}, LogicalTurnID: "turn-a",
			GrantSetID: "grants-a", GrantsSHA256: wire.Digest([]byte("grants")),
			PolicyGeneration: 1, CWD: "/work"}}
}

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type countingJudge struct {
	calls   atomic.Int64
	started chan struct{}
	release chan struct{}
	failed  atomic.Bool
}

func (j *countingJudge) Fit(ctx context.Context, r api.JudgeRequest) (api.TokenFit, error) {
	body, _, err := wire.Payload(r)
	return api.TokenFit{InputBytes: len(body), Reason: "fixture fit only"}, err
}

func (j *countingJudge) Evaluate(ctx context.Context, r api.JudgeRequest) (api.JudgeReply, error) {
	j.calls.Add(1)
	if j.started != nil {
		select {
		case j.started <- struct{}{}:
		default:
		}
		<-j.release
	}
	if ctx.Err() != nil || r.MaxCostMicros == 0 || j.failed.Load() {
		return api.JudgeReply{ID: r.ID, Status: "unavailable",
			Results: []api.Judgment{}, UnavailableReason: "fixture unavailable"}, nil
	}
	body, ids, err := wire.Payload(r)
	if err != nil {
		return api.JudgeReply{}, err
	}
	reply := api.JudgeReply{ID: r.ID, Status: "scored", Results: []api.Judgment{},
		Request: &api.BlobRef{ID: "request-a", Class: "judge_request",
			Bytes: int64(len(body)), SHA256: wire.Digest(body)}, BatchIDs: []api.ID{r.ID},
		SelectedModel: r.Config.Model, ReportedModel: r.Config.Model,
		InputBytes: len(body), InputTokens: len(body), CostMicros: int64(len(body)),
		DeploymentSHA256: r.Config.DeploymentSHA256, Raw: &api.BlobRef{ID: "raw-a",
			SHA256: wire.Digest(body), Bytes: int64(len(body)), Class: "judge_raw"}}
	for _, id := range ids {
		p := float64(len(body)+len(id)) / float64(len(body)+len(id)+1)
		reply.Results = append(reply.Results, api.Judgment{QuestionID: id, Status: "scored", Probability: &p})
	}
	return reply, nil
}

func TestCacheKeysAndCopies(t *testing.T) {
	j := &countingJudge{}
	clock := &testClock{now: time.Now()}
	c, err := NewCache(j, testConfig(), clock, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	r := testRequest()
	first, err := c.Evaluate(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	original := *first.Results[0].Probability
	*first.Results[0].Probability = -1
	first.Raw.ID = "mutated"
	first.Request.ID = "mutated"
	first.BatchIDs[0] = "mutated"
	hit, err := c.Evaluate(context.Background(), r)
	if err != nil || j.calls.Load() != 1 || *hit.Results[0].Probability != original || hit.Raw.ID == "mutated" ||
		hit.Request.ID == "mutated" || hit.BatchIDs[0] == "mutated" {
		t.Fatal("cache result aliases caller")
	}
	for _, mutate := range []func(*api.JudgeRequest){
		func(r *api.JudgeRequest) { r.Rules[0].Text += " changed" },
		func(r *api.JudgeRequest) { r.Rules[0].SourceSHA256 = wire.Digest([]byte("other source")) },
		func(r *api.JudgeRequest) { r.Rules[0].CriteriaVersion += "-new" },
		func(r *api.JudgeRequest) { r.Context.Role.Role = "reviewer" },
		func(r *api.JudgeRequest) { r.Context.Role.InstanceID = "instance-b" },
		func(r *api.JudgeRequest) { r.Context.GrantsSHA256 = wire.Digest([]byte("other grants")) },
		func(r *api.JudgeRequest) { r.Context.PolicyGeneration++ },
		func(r *api.JudgeRequest) {
			r.Command.Command = append(r.Command.Command, ' ')
			r.Command.RawSHA256 = wire.Digest(r.Command.Command)
		},
		func(r *api.JudgeRequest) { r.Command.Argv = []string{"quoted value"} },
		func(r *api.JudgeRequest) { r.Task = []byte("another task") },
		func(r *api.JudgeRequest) { r.Config.DeploymentSHA256 = wire.Digest([]byte("another stack")) },
		func(r *api.JudgeRequest) { r.Config.TokenizerSHA256 = wire.Digest([]byte("another tokenizer")) },
	} {
		r := testRequest()
		mutate(&r)
		before := j.calls.Load()
		if _, err := c.Evaluate(context.Background(), r); err != nil || j.calls.Load() != before+1 {
			t.Fatal("changed request reused cache")
		}
	}
}

func TestCacheExpiryBytesAndFailures(t *testing.T) {
	j := &countingJudge{}
	clock := &testClock{now: time.Now()}
	r := testRequest()
	reply, err := j.Evaluate(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(reply)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCache(j, r.Config, clock, (len(raw)+256)*2-1)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []api.ID{"rule-a", "rule-b", "rule-a"} {
		r.Rules[0].ID = id
		before := j.calls.Load()
		if _, err := c.Evaluate(context.Background(), r); err != nil || j.calls.Load() != before+1 {
			t.Fatal("byte eviction failed")
		}
	}
	clock.advance(31 * time.Second)
	before := j.calls.Load()
	if _, err := c.Evaluate(context.Background(), r); err != nil || j.calls.Load() != before+1 {
		t.Fatal("expired result was reused")
	}
	r.ID = "failed-a"
	r.Task = []byte("failure fixture")
	j.failed.Store(true)
	before = j.calls.Load()
	for range 2 {
		if got, err := c.Evaluate(context.Background(), r); err != nil || got.Status == "scored" {
			t.Fatal("unavailable became cached score")
		}
	}
	if j.calls.Load() != before+2 {
		t.Fatal("unavailable result was cached")
	}
	r = testRequest()
	r.MaxCostMicros = 0
	if got, err := c.Evaluate(context.Background(), r); err != nil || got.Status == "scored" {
		t.Fatal("budget borrowed a cached score")
	}
}

func TestCacheAcrossAsks(t *testing.T) {
	j := &countingJudge{}
	c, err := NewCache(j, testConfig(), &testClock{now: time.Now()}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	r := testRequest()
	first, err := c.Evaluate(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"id", "deadline", "budget", "all"} {
		next := r
		if name == "id" || name == "all" {
			next.ID = "another-ask"
		}
		if name == "deadline" || name == "all" {
			next.DeadlineMS = 1000
		}
		if name == "budget" || name == "all" {
			next.MaxCostMicros = 200000
		}
		hit, err := c.Evaluate(context.Background(), next)
		if err != nil || j.calls.Load() != 1 || hit.ID != first.ID ||
			!reflect.DeepEqual(hit.Results, first.Results) || hit.Request == nil || *hit.Request != *first.Request {
			t.Fatalf("per-ask fields split cache: %s", name)
		}
	}
}

type observeWait struct {
	context.Context
	joined chan<- struct{}
}

func (c observeWait) Done() <-chan struct{} {
	c.joined <- struct{}{}
	return c.Context.Done()
}

func TestCacheCoalescesMisses(t *testing.T) {
	j := &countingJudge{started: make(chan struct{}, 32), release: make(chan struct{})}
	c, err := NewCache(j, testConfig(), &testClock{now: time.Now()}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var failed atomic.Bool
	call := func(ctx context.Context) {
		defer wg.Done()
		got, err := c.Evaluate(ctx, testRequest())
		if err != nil || got.Status != "scored" {
			failed.Store(true)
		}
	}
	wg.Add(1)
	go call(context.Background())
	select {
	case <-j.started:
	case <-time.After(2 * time.Second):
		close(j.release)
		wg.Wait()
		t.Fatal("leader did not reach provider")
	}
	joined := make(chan struct{}, 64)
	for range 16 {
		wg.Add(1)
		go call(observeWait{Context: context.Background(), joined: joined})
	}
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	missed := false
	for i := 0; i < 16 && !missed; i++ {
		select {
		case <-joined:
		case <-timer.C:
			missed = true
		}
	}
	close(j.release)
	wg.Wait()
	if missed || failed.Load() || j.calls.Load() != 1 {
		t.Fatal("identical misses were not merged")
	}
}

func TestCacheRejectsTypedNil(t *testing.T) {
	var j *countingJudge
	_, err := NewCache(j, testConfig(), &testClock{}, 1000)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeInvalid {
		t.Fatal("typed nil judge was accepted")
	}
}
