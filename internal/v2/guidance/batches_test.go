package guidance

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestBatchesCoverEveryCandidate(t *testing.T) {
	request := stageRequest()
	request.Decisions = request.Decisions[1:]
	for index := 0; index < 25; index++ {
		request.Decisions = append(request.Decisions, candidate(fmt.Sprintf("choice-%02d", index), testTime(), false))
	}
	var deadline time.Time
	seen := make(map[api.ID]bool)
	probe := &judgeProbe{fit: fixtureFit}
	probe.evaluate = func(ctx context.Context, batch api.JudgeRequest) (api.JudgeReply, error) {
		current, exists := ctx.Deadline()
		if !exists || !bytes.Equal(batch.Task, request.Task) || len(batch.Decisions) > 12 ||
			!deadline.IsZero() && !current.Equal(deadline) {
			t.Fatal("batch changed task bytes, question bound or total deadline")
		}
		deadline = current
		answers := []api.Judgment{}
		for _, item := range batch.Decisions {
			if item.Binding || seen[item.ID] {
				t.Fatal("batch repeated a candidate or judged binding policy")
			}
			seen[item.ID] = true
			answers = append(answers, answer(string(item.ID), .8))
		}
		reply := stageReply(batch, answers...)
		reply.ID = api.ID(fmt.Sprintf("batch-receipt-%d", probe.evalCalls))
		return reply, nil
	}
	policy := stagePolicy()
	result, err := stage(probe).evaluateBatches(context.Background(), stageScope(), request, policy)
	if err != nil || result.Status != "scored" || len(seen) != 25 || probe.fitCalls != 3 || probe.evalCalls != 3 ||
		len(result.Items) != 6 || len(result.JudgmentIDs) != 3 || result.JudgmentID != "" {
		t.Fatalf("multi-batch selection lost coverage, provenance or binding slots: %v", err)
	}
	assertNear(t, *result.WeightedScore, .8)
}

func TestBatchFailureKeepsBinding(t *testing.T) {
	request := stageRequest()
	request.Decisions = request.Decisions[1:]
	for index := 0; index < 13; index++ {
		request.Decisions = append(request.Decisions, candidate(fmt.Sprintf("choice-%d", index), testTime(), false))
	}
	probe := &judgeProbe{fit: fixtureFit}
	probe.evaluate = func(_ context.Context, batch api.JudgeRequest) (api.JudgeReply, error) {
		if probe.evalCalls == 2 {
			return api.JudgeReply{}, &api.Error{Code: api.CodeUnavailable, Message: "fixture outage"}
		}
		answers := []api.Judgment{}
		for _, item := range batch.Decisions {
			answers = append(answers, answer(string(item.ID), .9))
		}
		return stageReply(batch, answers...), nil
	}
	result, err := stage(probe).evaluateBatches(context.Background(), stageScope(), request,
		stagePolicy())
	if err != nil || result.Status != "unavailable" || result.WeightedScore != nil ||
		len(result.Items) != 1 || !result.Items[0].Binding || len(result.JudgmentIDs) != 1 {
		t.Fatalf("partial batch success became scored guidance or lost binding context: %v", err)
	}
}

func TestBatchesShareCostCap(t *testing.T) {
	for _, over := range []bool{false, true} {
		t.Run(fmt.Sprintf("over-%t", over), func(t *testing.T) {
			request := stageRequest()
			request.Decisions = request.Decisions[1:]
			for index := 0; index < 13; index++ {
				request.Decisions = append(request.Decisions, candidate(fmt.Sprintf("choice-%d", index), testTime(), false))
			}
			caps := []int64{}
			probe := &judgeProbe{fit: fixtureFit}
			probe.evaluate = func(_ context.Context, batch api.JudgeRequest) (api.JudgeReply, error) {
				caps = append(caps, batch.MaxCostMicros)
				answers := []api.Judgment{}
				for _, item := range batch.Decisions {
					answers = append(answers, answer(string(item.ID), .8))
				}
				reply := stageReply(batch, answers...)
				reply.ID = api.ID(fmt.Sprintf("cost-receipt-%d", probe.evalCalls))
				reply.CostMicros = 60
				if probe.evalCalls == 2 {
					reply.CostMicros = 40
					if over {
						reply.CostMicros++
					}
				}
				return reply, nil
			}
			result, err := stage(probe).evaluateBatches(context.Background(), stageScope(), request, stagePolicy())
			if err != nil || len(caps) != 2 || caps[0] != 100 || caps[1] != 40 {
				t.Fatalf("batches did not share the remaining cost cap: %v", err)
			}
			if over {
				if result.Status != "unavailable" || result.WeightedScore != nil || len(result.Items) != 1 || !result.Items[0].Binding {
					t.Fatal("cumulative over-cap reply was scored")
				}
			} else if result.Status != "scored" || result.WeightedScore == nil || len(result.JudgmentIDs) != 2 {
				t.Fatal("costed complete batches were not scored")
			}
		})
	}
}
