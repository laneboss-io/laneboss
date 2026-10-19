package guidance

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func testTime() time.Time {
	return time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
}

func candidate(id string, effective time.Time, binding bool) api.DecisionCandidate {
	return api.DecisionCandidate{
		Authority: api.DecisionAuthority{Kind: "d6", ReceiptID: api.ID("approval-" + id), OrgGeneration: 2, SourceSeq: 1},
		AppliesTo: api.DecisionApplicability{Levels: []int{}, Roles: []string{}, ProjectIDs: []api.ID{}, LifeIDs: []api.ID{}},
		ID:        api.ID(id), Text: "Use the recorded review workflow for " + id,
		Source: api.SourceRef{
			ID: api.ID("source-" + id), Path: "decisions/" + id,
			SHA256: api.Digest(strings.Repeat("a1", 32)), Generation: 2,
		},
		EffectiveAt: api.Timestamp(effective.Format(time.RFC3339Nano)), Binding: binding,
	}
}

func answer(id string, probability float64) api.Judgment {
	return api.Judgment{QuestionID: api.ID(id), Status: "scored", Probability: &probability}
}

func scored(answers ...api.Judgment) api.JudgeReply {
	return api.JudgeReply{ID: "judge-receipt", Status: "scored", Results: answers}
}

func assertNear(t *testing.T, got, want float64) {
	t.Helper()
	if math.IsNaN(got) || math.IsInf(got, 0) || math.Abs(got-want) > 1e-12 {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func assertCode(t *testing.T, err error, code api.ErrorCode) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("got %v, want typed %s", err, code)
	}
}

func itemIDs(items []api.GuidanceItem) []api.ID {
	ids := make([]api.ID, 0, len(items))
	for _, item := range items {
		ids = append(ids, item.DecisionID)
	}
	return ids
}

func TestRankRecency(t *testing.T) {
	now := testTime()
	inputs := []api.DecisionCandidate{
		candidate("old", now.Add(-1000*time.Second), false),
		candidate("recent", now, false),
		candidate("unrelated", now, false),
		candidate("future", now.Add(time.Hour), false),
		candidate("binding", now.AddDate(-100, 0, 0), true),
	}
	result, err := rankSelection(now, 1000, inputs, scored(
		answer("old", 1), answer("recent", .8),
		answer("unrelated", .49), answer("future", .6)))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := itemIDs(result.Items), []api.ID{"binding", "recent", "future", "old"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	assertNear(t, *result.WeightedScore, .76)
	if result.Items[0].Weight != 1 || result.Items[0].Probability != nil || result.Items[0].Score != nil {
		t.Fatal("binding policy was relevance scored or decayed")
	}
	if result.Items[2].AgeSeconds != 0 || result.Items[2].Weight != 1 {
		t.Fatal("future effective time has negative age or inflated weight")
	}
	assertNear(t, result.Items[3].Weight, .5)
	if result.Items[3].Source != inputs[0].Source || result.JudgmentID != "judge-receipt" {
		t.Fatal("selection lost exact source/version or judge provenance")
	}
}

func TestRankCapAndMean(t *testing.T) {
	now := testTime()
	inputs := []api.DecisionCandidate{}
	answers := []api.Judgment{}
	for index := 0; index < 8; index++ {
		inputs = append(inputs, candidate(fmt.Sprintf("binding-%d", index), now.AddDate(-30, 0, 0), true))
	}
	for index := 0; index < 7; index++ {
		id := fmt.Sprintf("reminder-%d", index)
		inputs = append(inputs, candidate(id, now, false))
		answers = append(answers, answer(id, .9-float64(index)*.03))
	}
	result, err := rankSelection(now, 0, inputs, scored(answers...))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Items) != 13 || result.Notice == "" {
		t.Fatal("five reminders plus every binding source and omission notice are required")
	}
	for index, item := range result.Items[:8] {
		if !item.Binding || item.DecisionID != api.ID(fmt.Sprintf("binding-%d", index)) {
			t.Fatal("binding sources consumed reminder slots")
		}
	}
	for index, item := range result.Items[8:] {
		if item.Binding || item.DecisionID != api.ID(fmt.Sprintf("reminder-%d", index)) {
			t.Fatal("wrong historical reminder cap or ordering")
		}
	}
	// All seven eligible candidates contribute, including the omitted two.
	assertNear(t, *result.WeightedScore, .81)
}

func TestRankRelevance(t *testing.T) {
	now := testTime()
	inputs := []api.DecisionCandidate{
		candidate("zero", now, false), candidate("below", now, false),
		candidate("edge", now, false),
	}
	result, err := rankSelection(now, 0, inputs, scored(
		answer("zero", 0), answer("below", .499999), answer("edge", .5)))
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "scored" || !reflect.DeepEqual(itemIDs(result.Items), []api.ID{"edge"}) {
		t.Fatal("below-cutoff decisions filled historical reminder slots")
	}
	assertNear(t, *result.WeightedScore, .5)
	result, err = rankSelection(now, 0, inputs[:1], scored(answer("zero", 0)))
	if err != nil || result.Status != "scored" || len(result.Items) != 0 || result.WeightedScore == nil || *result.WeightedScore != 0 {
		t.Fatalf("valid scored zero changed into an outage: %+v, %v", result, err)
	}
}

func TestRankEmpty(t *testing.T) {
	result, err := rankSelection(testTime(), 0, nil, api.JudgeReply{})
	if err != nil || result.Status != "empty" || result.Items == nil || len(result.Items) != 0 ||
		result.WeightedScore == nil || *result.WeightedScore != 0 || result.JudgmentID != "" {
		t.Fatalf("actual empty set did not yield an explicit zero: %+v, %v", result, err)
	}
	serialized, err := json.Marshal(result)
	if err != nil || !strings.Contains(string(serialized), `"items":[]`) {
		t.Fatal("empty items must serialize as an array")
	}
}

func TestRankUnscored(t *testing.T) {
	now := testTime()
	inputs := []api.DecisionCandidate{
		candidate("a", now, false), candidate("b", now, false),
		candidate("binding", now.AddDate(-70, 0, 0), true),
	}
	cases := map[string]api.JudgeReply{
		"absent":         {},
		"missing":        scored(answer("a", .9)),
		"duplicate":      scored(answer("a", .9), answer("a", .2)),
		"unknown":        scored(answer("a", .9), answer("other", .9)),
		"binding":        scored(answer("a", .9), answer("binding", .9)),
		"nil":            scored(answer("a", .9), api.Judgment{QuestionID: "b", Status: "scored"}),
		"negative":       scored(answer("a", .9), answer("b", -.01)),
		"above-one":      scored(answer("a", .9), answer("b", 1.01)),
		"nan":            scored(answer("a", .9), answer("b", math.NaN())),
		"infinite":       scored(answer("a", .9), answer("b", math.Inf(1))),
		"partial":        {ID: "judge", Status: "partial", Results: []api.Judgment{answer("a", .9), answer("b", .9)}},
		"unavailable":    {ID: "judge", Status: "unavailable"},
		"unknown-status": {ID: "judge", Status: "other", Results: []api.Judgment{answer("a", .9), answer("b", .9)}},
		"unscored":       scored(answer("a", .9), api.Judgment{QuestionID: "b", Status: "unscored"}),
	}
	for name, reply := range cases {
		t.Run(name, func(t *testing.T) {
			result, err := rankSelection(now, 0, inputs, reply)
			if err != nil || result.Status != "unavailable" || result.WeightedScore != nil || result.Notice == "" {
				t.Fatalf("unscored input became success/zero: %+v, %v", result, err)
			}
			if len(result.Items) != 1 || !result.Items[0].Binding || result.Items[0].Weight != 1 ||
				result.Items[0].Probability != nil || result.Items[0].Score != nil {
				t.Fatal("unavailable history lost binding context or invented probabilities")
			}
		})
	}
}

func TestRankAncientHistory(t *testing.T) {
	now := time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
	older := time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
	younger := older.AddDate(1, 0, 0)
	inputs := []api.DecisionCandidate{
		candidate("a-older", older, false), candidate("z-younger", younger, false),
	}
	result, err := rankSelection(now, 1, inputs, scored(answer("a-older", .9), answer("z-younger", .7)))
	if err != nil {
		t.Fatal(err)
	}
	if result.Items[0].DecisionID != "z-younger" || result.Items[0].AgeSeconds != now.Unix()-younger.Unix() {
		t.Fatal("old ages saturated or underflow changed the ranking")
	}
	assertNear(t, *result.WeightedScore, .7)
}

func TestRankClockAndHalfLife(t *testing.T) {
	now := testTime()
	inputs := []api.DecisionCandidate{
		candidate("old", now.Add(-1000*time.Second), false),
		candidate("upcoming", now.Add(1000*time.Second), false),
	}
	reply := scored(answer("old", 1), answer("upcoming", .6))
	early, err := rankSelection(now.Add(-1000*time.Second), 1000, inputs, reply)
	if err != nil {
		t.Fatal(err)
	}
	late, err := rankSelection(now.Add(1000*time.Second), 1000, inputs, reply)
	if err != nil {
		t.Fatal(err)
	}
	long, err := rankSelection(now.Add(1000*time.Second), 10000, inputs, reply)
	if err != nil {
		t.Fatal(err)
	}
	if early.Items[0].DecisionID != "old" || late.Items[0].DecisionID != "upcoming" || long.Items[0].DecisionID != "old" {
		t.Fatal("controlled clock or configured half-life was ignored")
	}
}

func TestRankStableTies(t *testing.T) {
	now := testTime()
	inputs := []api.DecisionCandidate{
		candidate("b", now, false), candidate("a", now, false),
	}
	reply := scored(answer("b", .7), answer("a", .7))
	first, err := rankSelection(now, 0, inputs, reply)
	if err != nil {
		t.Fatal(err)
	}
	inputs[0], inputs[1] = inputs[1], inputs[0]
	reply.Results[0], reply.Results[1] = reply.Results[1], reply.Results[0]
	second, err := rankSelection(now, 0, inputs, reply)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) || first.Items[0].DecisionID != "a" {
		t.Fatal("input order changed a tied selection")
	}
}

func TestRankBadProvenance(t *testing.T) {
	now := testTime()
	changes := map[string]func(*api.DecisionCandidate){
		"id":            func(item *api.DecisionCandidate) { item.ID = "bad/id" },
		"text":          func(item *api.DecisionCandidate) { item.Text = "" },
		"source":        func(item *api.DecisionCandidate) { item.Source.ID = "" },
		"digest":        func(item *api.DecisionCandidate) { item.Source.SHA256 = "invalid" },
		"version":       func(item *api.DecisionCandidate) { item.Source.Generation = 0 },
		"large-version": func(item *api.DecisionCandidate) { item.Source.Generation = 1 << 53 },
		"path":          func(item *api.DecisionCandidate) { item.Source.Path = "" },
		"time":          func(item *api.DecisionCandidate) { item.EffectiveAt = "yesterday" },
		"non-UTC":       func(item *api.DecisionCandidate) { item.EffectiveAt = "2026-10-16T12:00:00+00:00" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			input := candidate("a", now, false)
			change(&input)
			_, err := rankSelection(now, 0, []api.DecisionCandidate{input}, scored(answer("a", .9)))
			assertCode(t, err, api.CodeIntegrity)
		})
	}
	input := candidate("a", now, false)
	_, err := rankSelection(now, 0, []api.DecisionCandidate{input, input}, scored(answer("a", .9)))
	assertCode(t, err, api.CodeIntegrity)
	_, err = rankSelection(now, -1, nil, api.JudgeReply{})
	assertCode(t, err, api.CodeInvalid)
}

func TestRankDefaultHalfLife(t *testing.T) {
	now := testTime()
	input := candidate("history", now.Add(-14*24*time.Hour), false)
	result, err := rankSelection(now, 0, []api.DecisionCandidate{input}, scored(answer("history", .8)))
	if err != nil || len(result.Items) != 1 {
		t.Fatalf("default half-life selection did not complete: %v", err)
	}
	if math.Abs(result.Items[0].Weight-.5) > 1e-12 || result.Items[0].Score == nil ||
		math.Abs(*result.Items[0].Score-.4) > 1e-12 {
		t.Fatal("default half-life did not preserve the fourteen-day weight")
	}
}

func TestRankBindingContext(t *testing.T) {
	now := testTime()
	inputs := []api.DecisionCandidate{
		candidate("binding-b", now.AddDate(-100, 0, 0), true),
		candidate("binding-a", now.AddDate(-120, 0, 0), true),
	}
	result, err := rankSelection(now, 0, inputs, api.JudgeReply{Status: "unavailable"})
	if err != nil || len(result.Items) != len(inputs) || result.Status != "empty" ||
		result.WeightedScore == nil || *result.WeightedScore != 0 || result.JudgmentID != "" {
		t.Fatalf("binding context was lost without history: %+v, %v", result, err)
	}
	for _, item := range result.Items {
		if !item.Binding || item.Weight != 1 || item.Probability != nil || item.Score != nil ||
			item.AgeSeconds < 3650*24*60*60 {
			t.Fatal("old binding policy was scored or decayed")
		}
	}
}

func TestRankFutureAge(t *testing.T) {
	now := testTime()
	input := candidate("upcoming", now.Add(1500*time.Millisecond), false)
	result, err := rankSelection(now, 2, []api.DecisionCandidate{input}, scored(answer("upcoming", .7)))
	if err != nil || len(result.Items) != 1 {
		t.Fatalf("future-age selection did not complete: %v", err)
	}
	item := result.Items[0]
	if item.AgeSeconds != 0 || item.Weight != 1 || item.Score == nil || *item.Score != .7 {
		t.Fatal("future age was not clamped")
	}
}
