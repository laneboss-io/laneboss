package dashboard

import (
	"context"
	"laneboss.io/laneboss/internal/eventstore"
	"laneboss.io/laneboss/internal/judge"
)

// Missing decision totals, rule links and policy results remain null. A judge
// probability is not converted into a permission decision by this reader.
func judgmentView(ctx context.Context, name string) (object, error) {
	rows, err := judge.ReadDecisionsContext(ctx, name)
	if err != nil {
		return nil, err
	}
	binding, err := eventstore.Bind(name)
	if err != nil {
		return nil, err
	}
	_, events, err := eventstore.ReadDisplayContext(ctx, binding)
	if err != nil {
		return nil, err
	}
	byAsk := map[string]object{}
	for _, row := range rows {
		byAsk[str(row["ask"])] = row
	}
	total, judged := 0, 0
	for _, e := range events {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if e["kind"] != "guard.decision" && e["kind"] != "refusal.decision" {
			continue
		}
		p := obj(e["payload"])
		total++
		row := byAsk[str(p["ask"])]
		if row == nil {
			continue
		}
		judged++
		row["rule_id"], row["result"], row["decision_event"] = p["rule_id"], p["result"], e["seq"]
	}
	var share any
	if total > 0 {
		share = float64(judged) / float64(total)
	}
	return object{"rows": rows, "decisions_judged": judged, "recorded_decisions": total, "judged_share": share, "share_basis": "explicit recorded guard/refusal decisions only"}, nil
}
