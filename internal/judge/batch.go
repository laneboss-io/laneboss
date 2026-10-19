package judge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/faults"
	"laneboss.io/laneboss/internal/typesafe"
)

type BatchVerdict struct {
	Outcome, Model, Detail string
	Probabilities          map[string]float64
}

// The guide uses at most 12 decisions times 3 windows. Bounding IDs and count
// also makes the per-attempt egress outcome reserve sufficient for every batch.
const maxBatchQuestions = 36

// AskNoulsContext evaluates independent binary judgments over one named state
// in one bounded, screened, logged adapter invocation. It never sends partial
// state or accepts partial answers. The adapter must support kind=typed.
func AskNoulsContext(ctx context.Context, configuration, name, question string, state, questions map[string]any) (BatchVerdict, error) {
	if ctx.Err() != nil {
		return BatchVerdict{Outcome: "timeout"}, nil
	}
	o := options{config: configuration, configSet: true, judge: name, question: question, questionSet: true}
	if lane := os.Getenv("LANEBOSS_LANE"); lanePattern.MatchString(lane) {
		o.lane, o.laneSet = lane, true
	}
	if !namePattern.MatchString(name) || !questionPattern.MatchString(question) || len(question) > 64 || hasCredential(name) || hasCredential(question) {
		return BatchVerdict{}, refused("batch judge needs valid configured names")
	}
	body := map[string]any{"laneboss_judge": 1, "question": question, "kind": "typed", "state": state, "questions": questions}
	data := append(encodeJSON(body), '\n')
	canonical, err := typesafe.Decode(data)
	if err != nil || !typesafe.Questions(tableValue(canonical["questions"])) {
		return BatchVerdict{}, refused("batch needs documented typed questions")
	}
	questions = tableValue(canonical["questions"])
	if len(questions) > maxBatchQuestions {
		return BatchVerdict{Outcome: "cut"}, nil
	}
	for id, q := range questions {
		if len(id) > 64 || !identifierPattern.MatchString(id) || tableValue(q)["type"] != "noul" {
			return BatchVerdict{}, refused("binary batch requires Noul questions")
		}
	}
	if _, found := credentialField(body, ""); found {
		return BatchVerdict{Outcome: "withheld"}, nil
	}
	if len(data) > 256*1024 || !wholeBatchText(canonical) {
		return BatchVerdict{Outcome: "cut"}, nil
	}
	c, err := loadConfiguration(o)
	if err != nil {
		return BatchVerdict{}, err
	}
	j, exists := c.judges[name]
	if !exists {
		return BatchVerdict{}, refused("the batch judge is not configured")
	}
	sum := sha256.Sum256(data)
	r := request{data: data, hash: hex.EncodeToString(sum[:]), withheld: []string{}, cut: []string{}, batch: true,
		decode: func(raw []byte) (answer, bool) { return readBatchAnswer(raw, questions) }}
	// Both points panic at the real batch boundary. The second also removes
	// the caller's recover so the same advisory row detects that regression.
	for _, point := range []string{"guide-batch-panic", "guide-batch-no-recover"} {
		if faults.Get(point).Point != "" {
			if err := faults.Reach(point); err != nil {
				panic(err)
			}
			panic("injected guide batch panic")
		}
	}
	result, detail, interrupted, err := askJudgeContext(ctx, c, o, j, r)
	if ctx.Err() != nil {
		return BatchVerdict{Outcome: "timeout"}, nil
	}
	if err != nil {
		return BatchVerdict{}, err
	}
	v := BatchVerdict{Outcome: result.Outcome, Detail: detail, Probabilities: result.nouls}
	if interrupted {
		v.Outcome, v.Probabilities = "exit", nil
	}
	if result.Model != nil {
		v.Model = *result.Model
	}
	return v, nil
}

func wholeBatchText(value any) bool {
	switch v := value.(type) {
	case string:
		return utf8.ValidString(v) && utf8.RuneCountInString(v) <= 4000
	case map[string]any:
		for key, item := range v {
			if !wholeBatchText(key) || !wholeBatchText(item) {
				return false
			}
		}
	case []any:
		for _, item := range v {
			if !wholeBatchText(item) {
				return false
			}
		}
	case []string:
		for _, item := range v {
			if !wholeBatchText(item) {
				return false
			}
		}
	}
	return true
}

func readBatchAnswer(raw []byte, questions map[string]any) (answer, bool) {
	var a answer
	root, err := typesafe.Response(raw, questions)
	if err != nil {
		return a, false
	}
	if _, found := credentialField(root, ""); found {
		return a, false
	}
	model, modelOK := optionalIdentifier(root["model"])
	id, idOK := optionalIdentifier(root["request"])
	if !modelOK || !idOK {
		return a, false
	}
	nouls := map[string]float64{}
	for key, value := range tableValue(root["answers"]) {
		p, ok := probability(tableValue(value)["noul"])
		if !ok {
			return a, false
		}
		nouls[key] = p
	}
	return answer{nouls: nouls, model: model, request: id}, true
}
