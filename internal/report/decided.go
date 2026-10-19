package report

import (
	"strings"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/decisionsrv"
	"laneboss.io/laneboss/internal/eventstore"
	"laneboss.io/laneboss/internal/rolepolicy"
)

// Scope comes from the authenticated sender's recorded lane, never an actor
// supplied in a flag or environment label. A supervisor uses its recorded level.
func decidedQuestion(c *config.Configuration, from caller.Principal, data []byte) (map[string]any, map[string]any) {
	check := map[string]any{"decided": false, "judge": "no-org", "related": []any{}}
	root, err := rolepolicy.ConfigRoot(c.Home, c.Data)
	if err != nil || root == "" {
		return nil, check
	}
	project, level := "", from.Level
	if strings.HasPrefix(from.ID, "lane:") {
		lanes, err := caller.Lanes(c)
		if err != nil {
			check["judge"] = "state-error"
			return nil, check
		}
		lane, ok := lanes[strings.TrimPrefix(from.ID, "lane:")]
		if !ok {
			check["judge"] = "no-lane"
			return nil, check
		}
		project, level = text(lane.Payload["project"]), lane.Principal.Level
	}
	g, err := decisionsrv.OpenGuide(root)
	if err != nil {
		check["judge"] = "store-error"
		return nil, check
	}
	answer, err := g.AnswerFor(string(data), project, level)
	if err != nil {
		check["judge"] = "store-error"
		return nil, check
	}
	related := []any{}
	holds := eventstore.HoldsCredential
	for _, item := range answer.Related {
		related = append(related, map[string]any{"id": decisionsrv.SafeEchoLabel(item.Decision.ID, holds), "score": item.Score})
	}
	check["judge"], check["related"] = answer.Judge, related
	if answer.Decided == nil {
		return nil, check
	}
	d, withheld := answer.Decided.Decision.ScreenedEcho(holds)
	return map[string]any{
		"decided": true, "sent": false, "match": answer.Decided.Match, "score": answer.Decided.Score,
		"withheld": withheld,
		"judge":    answer.Judge, "related": related,
		"decision": map[string]any{"id": d.ID, "kind": d.Kind, "project": d.Project,
			"answered_at": d.AnsweredAt, "question": d.Question, "answer": d.Answer},
	}, check
}
