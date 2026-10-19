package typesafe

import (
	"encoding/json"
	"os"
	"testing"
)

// These fixtures use api.md's literal answer fields and ordered Score levels.
// Deliberately malformed variants must fail before the corresponding valid
// envelope is accepted. This does not measure service/model accuracy.
func TestOfficialResponseRows(t *testing.T) {
	questionsRaw, err := os.ReadFile("testdata/questions.json")
	if err != nil {
		t.Fatal(err)
	}
	questions, err := Decode(questionsRaw)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("testdata/response.json")
	if err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		name   string
		change func(map[string]any)
	}{
		{"missing-model", func(r map[string]any) { delete(r, "model") }},
		{"missing-usage", func(r map[string]any) { delete(r, "usage") }},
		{"partial-answers", func(r map[string]any) { delete(r["answers"].(map[string]any), "is_urgent") }},
		{"legacy-probability-field", func(r map[string]any) {
			a := r["answers"].(map[string]any)["is_urgent"].(map[string]any)
			a["probability"] = a["noul"]
			delete(a, "noul")
		}},
		{"wrong-type", func(r map[string]any) { r["answers"].(map[string]any)["is_urgent"].(map[string]any)["type"] = "score" }},
		{"boolean-noul", func(r map[string]any) { r["answers"].(map[string]any)["is_urgent"].(map[string]any)["noul"] = true }},
		{"numeric-string", func(r map[string]any) { r["answers"].(map[string]any)["is_urgent"].(map[string]any)["noul"] = "0.95" }},
		{"out-of-range-before-rounding", func(r map[string]any) {
			r["answers"].(map[string]any)["is_urgent"].(map[string]any)["noul"] = json.Number("1.0000000000000001")
		}},
		{"missing-choice-distribution", func(r map[string]any) {
			delete(r["answers"].(map[string]any)["department"].(map[string]any), "probabilities")
		}},
		{"missing-confidence", func(r map[string]any) {
			delete(r["answers"].(map[string]any)["department"].(map[string]any), "confidence")
		}},
		{"choice-is-not-maximum", func(r map[string]any) {
			r["answers"].(map[string]any)["department"].(map[string]any)["choice"] = "sales"
		}},
		{"distribution-is-not-normalized", func(r map[string]any) {
			r["answers"].(map[string]any)["department"].(map[string]any)["probabilities"].(map[string]any)["technical"] = json.Number("0.9")
		}},
		{"missing-option", func(r map[string]any) {
			delete(r["answers"].(map[string]any)["department"].(map[string]any)["probabilities"].(map[string]any), "sales")
		}},
		{"missing-score-value", func(r map[string]any) { delete(r["answers"].(map[string]any)["frustration"].(map[string]any), "score") }},
		{"score-is-not-weighted-mean", func(r map[string]any) {
			r["answers"].(map[string]any)["frustration"].(map[string]any)["score"] = json.Number("0.5")
		}},
		{"wrong-score-legend", func(r map[string]any) {
			r["answers"].(map[string]any)["frustration"].(map[string]any)["legend"].(map[string]any)["1"] = "Unrelated"
		}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			bad, err := Decode(raw)
			if err != nil {
				t.Fatal(err)
			}
			row.change(bad)
			mutated, err := json.Marshal(bad)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Response(mutated, questions); err == nil {
				t.Fatal("malformed official response was accepted")
			}
			got, err := Response(raw, questions)
			if err != nil {
				t.Fatal(err)
			}
			answers := got["answers"].(map[string]any)
			if p, ok := Number(answers["is_urgent"].(map[string]any)["noul"], 1); !ok || p != 0.95 {
				t.Fatal("official Noul changed")
			}
			if answers["department"].(map[string]any)["choice"] != "billing" {
				t.Fatal("official Choice changed")
			}
			if score, ok := Number(answers["frustration"].(map[string]any)["score"], 2); !ok || score != 1.05 {
				t.Fatal("official Score changed")
			}
		})
	}
	for _, broken := range []string{`{"model":"jev-1.13.0","model":"jev-1.13.0"}`, string(raw) + `{}`, `{"model":"\ud800"}`} {
		if _, err := Response([]byte(broken), questions); err == nil {
			t.Fatal("invalid JSON shape was accepted")
		}
	}
}

func TestProbabilitySumRoundingRows(t *testing.T) {
	q, err := os.ReadFile("testdata/questions.json")
	if err != nil {
		t.Fatal(err)
	}
	questions, err := Decode(q)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("testdata/response.json")
	if err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		probability string
		accepted    bool
	}{
		{"0.11984", false}, // Sum 0.99984 is outside the 3-option budget.
		{"0.4", false},     // Sum 1.28 remains clearly malformed.
		{"0.11986", true},  // Sum 0.99986 is inside the 3-option budget.
		{"0.12014", true},  // Sum 1.00014 is inside the same budget.
	}
	for _, row := range rows {
		t.Run(row.probability, func(t *testing.T) {
			root, err := Decode(raw)
			if err != nil {
				t.Fatal(err)
			}
			choice := root["answers"].(map[string]any)["department"].(map[string]any)
			choice["probabilities"].(map[string]any)["technical"] = json.Number(row.probability)
			changed, err := json.Marshal(root)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Response(changed, questions)
			if (err == nil) != row.accepted {
				t.Fatal("distribution rounding boundary did not match its documented budget")
			}
		})
	}
}
