package judge

import (
	"bytes"
	"context"
)

// ReadDecisions uses the judge CLI's bound configuration, contained egress
// reader and strict log parser. It reads neither input files nor provider state.
func ReadDecisions(name string) ([]map[string]any, error) {
	return ReadDecisionsContext(context.Background(), name)
}

func ReadDecisionsContext(ctx context.Context, name string) ([]map[string]any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c, err := loadConfiguration(options{config: name, configSet: true})
	if err != nil {
		return nil, err
	}
	var log bytes.Buffer
	if err = readEgressContext(ctx, c, options{}, &log); err != nil {
		return nil, err
	}
	result := []map[string]any{}
	byAsk := map[string]map[string]any{}
	for _, raw := range bytes.Split(log.Bytes(), []byte{'\n'}) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if blankLogLine(raw) {
			continue
		}
		record, err := parseLogLine(raw)
		if err != nil {
			return nil, integrity("the judge log contains an invalid record")
		}
		ask := record["ask"].(string)
		if record["event"] == "sent" {
			if byAsk[ask] != nil {
				return nil, integrity("the judge log repeats an ask")
			}
			// The current judge contract records a Noul probability. No Choice,
			// Score or input text is invented when the log does not hold it.
			decision := map[string]any{"ask": ask, "time": record["at"], "judge": record["judge"], "question": record["question"], "lane": record["lane"], "outcome": "pending", "answer": map[string]any{"type": "noul", "probability": nil}, "model": nil, "summary": nil, "latency_ms": nil, "rule_id": nil, "result": nil, "low_confidence": nil}
			byAsk[ask] = decision
			result = append(result, decision)
		} else {
			decision := byAsk[ask]
			if decision == nil || decision["outcome"] != "pending" {
				return nil, integrity("the judge outcome has no unique recorded ask")
			}
			decision["time"], decision["outcome"], decision["model"] = record["at"], record["outcome"], record["model"]
			decision["answer"] = map[string]any{"type": "noul", "probability": record["probability"]}
			decision["latency_ms"] = record["duration_ms"]
			if values, batch := record["probabilities"].(map[string]any); batch {
				decision["answer"] = map[string]any{"type": "noul-batch", "probabilities": values}
				uncertain := false
				for _, value := range values {
					if p, ok := probability(value); ok && p > 0.25 && p < 0.75 {
						uncertain = true
					}
				}
				decision["low_confidence"] = uncertain
			}
			if p, ok := probability(record["probability"]); ok {
				decision["low_confidence"] = p > 0.25 && p < 0.75
			}
		}
	}
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return result, nil
}
