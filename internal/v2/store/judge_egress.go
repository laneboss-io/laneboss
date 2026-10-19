package store

import (
	"context"
	"database/sql"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
	judgewire "laneboss.io/laneboss/internal/v2/judge/wire"
)

// The retained sent/outcome record schema is shared with the public judge
// case. A sent row records the durable reservation before provider transport;
// a missing outcome is explicitly pending/unknown, never a zero-cost success.
func (s *Service) judgeEgress(ctx context.Context, tx *sql.Tx, e api.JudgeExecution, event string, reply *api.JudgeReply) error {
	body, _, err := judgewire.Payload(e.Request)
	if err != nil {
		return err
	}
	value := map[string]any{"event": event, "ask": e.Request.ID, "at": e.ReservedAt,
		"request_sha256": hash(body), "request_bytes": len(body), "outcome_reserve": e.Request.MaxCostMicros,
		"cut": false, "withheld": false, "claim_id": e.ClaimID, "attempt_id": e.AttemptID,
		"reserved_micros": e.Request.MaxCostMicros}
	if reply != nil {
		value["at"] = api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat))
		value["duration_ms"] = reply.LatencyMS
		value["outcome"] = "unscored"
		value["cost_micros"] = reply.CostMicros
		probabilities := map[api.ID]float64{}
		if reply.Status == "scored" {
			value["outcome"] = "answered"
			for _, answer := range reply.Results {
				if answer.Probability != nil {
					probabilities[answer.QuestionID] = *answer.Probability
				}
			}
		}
		value["probabilities"] = probabilities
		if reply.Raw != nil {
			_, raw, err := objectRow(ctx, tx, reply.Raw.ID)
			if err != nil {
				return err
			}
			var provider map[string]json.RawMessage
			if json.Unmarshal(raw, &provider) == nil {
				var request string
				if json.Unmarshal(provider["request"], &request) == nil {
					value["request"] = request
				}
			}
			_, _, known := judgewire.MeasuredUsage(raw, e.Request)
			value["usage_known"] = known
		} else {
			value["usage_known"] = false
		}
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	id := api.ID("judge-" + event + "-" + string(e.ID))
	scope := api.Scope{Config: s.deps.Config, Actor: e.Intent.Actor, Source: "worker"}
	ref, err := s.retain(ctx, tx, scope, api.ObjectWrite{ObjectKey: id, Class: "record", Bytes: raw, SHA256: api.Digest(hash(raw)), Origin: "service",
		ACL: api.ObjectACL{Config: s.deps.Config, Owner: e.Intent.RequestedBy, LifeID: e.Intent.Target.LifeID, Audience: "owner", Generation: 1}},
		e.Intent.CauseOperationID, api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat)))
	if err != nil {
		return err
	}
	record := api.Record{ID: id, Collection: "judge_egress", LifeID: e.Intent.Target.LifeID, Run: e.Intent.Target.Run, Content: ref, Actor: e.Intent.Actor, Origin: "service",
		RecordedAt: api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat)), Generation: 1, RelatedIDs: []api.ID{e.ID}}
	return put(ctx, tx, "record", id, 1, record)
}
