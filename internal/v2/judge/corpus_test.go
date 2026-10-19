package judge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/judge/wire"
)

// This is a structure/payload check, not label validation or model evaluation.
// Choice rows cannot be sent under the frozen Noul-only API; that contract gap
// is reported explicitly rather than casting their labels into probabilities.
func TestCorpusRowsReachPayload(t *testing.T) {
	path := filepath.Join("testdata", "corpus.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Rules []struct{ ID, Text, Source string }
		Items []struct {
			ID, Group, Command, Reason, Source string
			RuleID                             string `json:"rule_id"`
			Label                              any
			Question                           struct {
				Type, Instructions string
				Criteria           map[string]string
			}
		}
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	rules := make(map[string]api.JudgeRule)
	for _, source := range corpus.Rules {
		if !wire.ValidID(api.ID(source.ID)) || source.Text == "" || source.Source == "" || rules[source.ID].ID != "" {
			t.Fatal("invalid corpus rule")
		}
		rules[source.ID] = api.JudgeRule{ID: api.ID(source.ID), Text: source.Text,
			SourceSHA256:    wire.Digest([]byte(source.Source + "\n" + source.Text)),
			CriteriaVersion: wire.CriteriaVersion}
	}
	ids, counts := map[string]bool{}, map[string]int{}
	constructed, choice := 0, 0
	for i, item := range corpus.Items {
		if ids[item.ID] || item.ID == "" || rules[item.RuleID].ID == "" || item.Command == "" ||
			item.Reason == "" || strings.ContainsAny(item.Reason, "\r\n") || item.Source == "" {
			t.Fatalf("invalid corpus row %d", i)
		}
		ids[item.ID], counts[item.Group] = true, counts[item.Group]+1
		switch item.Question.Type {
		case "", "noul":
			if _, ok := item.Label.(bool); !ok {
				t.Fatal("non-binary corpus label")
			}
			r := testRequest()
			r.ID = api.ID("corpus-" + string(wire.Digest([]byte(item.ID)))[:24])
			r.Rules = []api.JudgeRule{rules[item.RuleID]}
			r.Command.Command = []byte(item.Command)
			r.Command.RawSHA256 = wire.Digest(r.Command.Command)
			body, questions, err := wire.Payload(r)
			if err != nil || len(body) == 0 || len(questions) != 1 || questions[0] != r.Rules[0].ID {
				t.Fatalf("corpus payload failed at %d", i)
			}
			constructed++
		case "choice":
			label, ok := item.Label.(string)
			if !ok || item.Question.Instructions == "" || len(item.Question.Criteria) < 2 ||
				item.Question.Criteria[label] == "" {
				t.Fatal("invalid Choice corpus row")
			}
			for id, description := range item.Question.Criteria {
				if !wire.ValidID(api.ID(id)) || description == "" {
					t.Fatal("invalid Choice option ID")
				}
			}
			choice++
		default:
			t.Fatal("unknown corpus question type")
		}
	}
	for group, want := range map[string]int{"blacklist": 120, "adversarial": 32,
		"decision": 90, "choice": 20, "robustness": 40} {
		if counts[group] != want {
			t.Fatalf("invalid inventory: %s", group)
		}
	}
	if len(corpus.Items) != 302 || len(counts) != 5 || constructed != 282 || choice != 20 {
		t.Fatal("corpus coverage is incomplete")
	}
}
