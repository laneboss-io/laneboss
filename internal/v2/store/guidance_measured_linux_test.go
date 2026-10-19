//go:build linux

package store_test

import (
	"context"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/guidance"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

func scoredGuidanceFixture(t *testing.T) (*fx.Fixture, api.Transaction) {
	t.Helper()
	return scoredGuidanceCount(t, 1)
}

func scoredGuidanceCount(t *testing.T, count int) (*fx.Fixture, api.Transaction) {
	t.Helper()
	f, judgeRequest := judgeExecutionFixture(t)
	candidates := []api.DecisionCandidate{}
	for index := 0; index < count; index++ {
		id := fx.ID(t)
		candidate := api.DecisionCandidate{ID: id, Text: "Retain the full measured build result.", Source: api.SourceRef{ID: id, SHA256: fx.Digest([]byte("measured decision " + string(id))), Generation: 1},
			EffectiveAt: api.Timestamp(time.Now().Add(-time.Duration(24+index) * time.Hour).UTC().Format(time.RFC3339Nano)),
			Authority:   api.DecisionAuthority{Kind: "human", ReceiptID: fx.ID(t), SourceSeq: 1},
			AppliesTo:   api.DecisionApplicability{Levels: []int{}, Roles: []string{}, ProjectIDs: []api.ID{}, LifeIDs: []api.ID{}}}
		f.Replace(t, "decision", id, 1, api.DecisionProjection{RecordID: id, Candidate: candidate, Status: "active"})
		candidates = append(candidates, candidate)
	}
	request := api.GuidanceRequest{Target: f.Reservation.Target, LogicalTurnID: f.Lane.LogicalTurnID, Task: f.Lane.Task}
	f.Admit(t, "guidance.select", request)
	page, err := f.State.DecisionCandidates(context.Background(), f.Human, api.DecisionQuery{Target: request.Target, Kind: "binding", Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	claim, err := f.State.ReserveGuidance(context.Background(), f.Human, api.GuidanceReservationRequest{AttemptID: fx.ID(t), Target: request.Target, LogicalTurnID: request.LogicalTurnID,
		ExpectedTask: request.Task, ExpectedTurnGeneration: 1, CancellationEpoch: f.Lane.CancellationEpoch, PolicyGeneration: f.Human.PolicyGeneration, CandidateSnapshotID: page.SnapshotID, MaxCostMicros: 19, Deadline: api.Timestamp(time.Now().Add(4 * time.Second).UTC().Format(time.RFC3339Nano))})
	if err != nil {
		t.Fatal(err)
	}
	judgeRequest.Request.Purpose, judgeRequest.Request.Command, judgeRequest.Request.Rules = "guidance", nil, []api.JudgeRule{}
	ids := []api.ID{}
	answers := []api.Judgment{}
	remaining := int64(19)
	for offset := 0; offset < len(candidates); offset += 12 {
		judgeRequest.Request.ID = fx.ID(t)
		judgeRequest.Request.MaxCostMicros = remaining
		judgeRequest.Request.Decisions = candidates[offset:min(offset+12, len(candidates))]
		judgeRequest.Deadline = api.Timestamp(time.Now().Add(time.Second).UTC().Format(time.RFC3339Nano))
		execution, audit := measuredJudgeAudit(t, f, judgeRequest)
		worker := api.Scope{Config: f.Deps.Config, Actor: execution.Intent.Actor, Source: "worker", PolicyGeneration: f.Human.PolicyGeneration}
		if _, err := f.State.CompleteJudgeExecution(context.Background(), worker, execution, audit); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, audit.ID)
		answers = append(answers, audit.Reply.Results...)
		remaining -= audit.Reply.CostMicros
	}
	policy, err := f.State.Policy(context.Background(), f.Human)
	if err != nil {
		t.Fatal(err)
	}
	asOf, err := time.Parse(time.RFC3339Nano, string(claim.ReservedAt))
	if err != nil {
		t.Fatal(err)
	}
	ranked, err := guidance.RankMeasuredSnapshot(asOf, policy, candidates, api.JudgeReply{ID: ids[0], Status: "scored", Results: answers})
	if err != nil || ranked.Status != "scored" {
		t.Fatal("measured fixture did not rank", err)
	}
	ranked.JudgmentIDs = ids
	if len(ids) > 1 {
		ranked.JudgmentID = ""
	}
	input := guidanceCompletion(t, f, claim)
	result := &input.Writes.Guidance[0].Result
	result.AsOf, result.Items, result.WeightedScore, result.JudgmentID, result.JudgmentIDs, result.Status, result.Notice = ranked.AsOf, ranked.Items, ranked.WeightedScore, ranked.JudgmentID, ranked.JudgmentIDs, ranked.Status, ranked.Notice
	input.Events[0].Payload = fx.JSON(t, *result)
	return f, input
}

func TestItem4GuidanceMeasuredBatches(t *testing.T) {
	f, input := scoredGuidanceCount(t, 13)
	result := input.Writes.Guidance[0].Result
	if len(result.JudgmentIDs) != 2 || len(result.Items) != 5 {
		t.Fatal("multi-batch fixture lost coverage or reminder limit")
	}
	if _, err := f.State.Transact(context.Background(), input); err != nil {
		t.Fatal("store refused complete measured multi-batch guidance", err)
	}
}

func TestItem4GuidanceLostBatch(t *testing.T) {
	f, input := scoredGuidanceCount(t, 13)
	result := &input.Writes.Guidance[0].Result
	result.JudgmentIDs = result.JudgmentIDs[:1]
	input.Events[0].Payload = fx.JSON(t, *result)
	if _, err := f.State.Transact(context.Background(), input); err == nil {
		t.Fatal("store accepted scored guidance after losing a measured batch")
	}
}

func TestItem4GuidanceMeasuredCommit(t *testing.T) {
	f, input := scoredGuidanceFixture(t)
	if _, err := f.State.Transact(context.Background(), input); err != nil {
		t.Fatal("scored guidance still refuses its measured complete provenance", err)
	}
	result := input.Writes.Guidance[0].Result
	read, err := f.State.GuidanceReservation(context.Background(), f.Human, result.Target, result.LogicalTurnID)
	if err != nil || read.Result == nil || read.Result.Status != "scored" || len(read.Result.Items) != 1 || read.Result.Items[0].Probability == nil {
		t.Fatal("measured guidance was not retained", err)
	}
	if replay, err := f.State.Transact(context.Background(), input); err != nil || !replay.Replayed {
		t.Fatal("guidance did not replay its original scored completion", err)
	}
}

func TestItem4GuidanceMeasuredFences(t *testing.T) {
	for _, name := range []string{"foreign_judgment", "missing_batch", "duplicate_batch", "score", "task", "stale_attempt", "missing_cas"} {
		t.Run(name, func(t *testing.T) {
			f, input := scoredGuidanceFixture(t)
			result := &input.Writes.Guidance[0].Result
			switch name {
			case "foreign_judgment":
				result.JudgmentIDs = []api.ID{fx.ID(t)}
				result.JudgmentID = result.JudgmentIDs[0]
			case "missing_batch":
				result.JudgmentIDs = []api.ID{}
				result.JudgmentID = ""
			case "duplicate_batch":
				result.JudgmentIDs = append(result.JudgmentIDs, result.JudgmentIDs[0])
			case "score":
				value := *result.Items[0].Probability / 2
				result.Items[0].Probability = &value
			case "task":
				result.Task.SHA256 = fx.Digest([]byte("another task"))
			case "stale_attempt":
				input.Writes.Guidance[0].AttemptID = fx.ID(t)
			case "missing_cas":
				input.Compare = nil
			}
			input.Events[0].Payload = fx.JSON(t, *result)
			if _, err := f.State.Transact(context.Background(), input); err == nil {
				t.Fatal("guidance accepted " + name)
			}
		})
	}
}
