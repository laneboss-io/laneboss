package wire

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestGuidanceStateAndQuestionIDs(t *testing.T) {
	r := request()
	r.Purpose, r.Command, r.Rules = "guidance", nil, []api.JudgeRule{}
	r.Task = []byte("Review the build plan.")
	for i, id := range []api.ID{"partial", "decision-b"} {
		r.Decisions = append(r.Decisions, api.DecisionCandidate{ID: id,
			Authority:   api.DecisionAuthority{Kind: "human", ReceiptID: "receipt-a", SourceSeq: 1},
			AppliesTo:   api.DecisionApplicability{Levels: []int{}, Roles: []string{}, ProjectIDs: []api.ID{}, LifeIDs: []api.ID{}},
			Text:        fmt.Sprintf("Keep decision %d complete.", i),
			Source:      api.SourceRef{ID: "source-a", SHA256: Digest([]byte("source")), Generation: 1},
			EffectiveAt: "2026-01-01T00:00:00Z", Binding: i == 0})
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		raw, err := io.ReadAll(req.Body)
		if err != nil {
			t.Error("request read failed")
		}
		var wire payload
		if err := json.Unmarshal(raw, &wire); err != nil {
			t.Error("request decoding failed")
		}
		if len(wire.State.Decisions) != 2 || len(wire.State.Commands) != 0 ||
			wire.State.Task != string(r.Task) || !wire.State.Decisions[0].Binding {
			t.Error("guidance state was lost")
		}
		for i, decision := range r.Decisions {
			if !reflect.DeepEqual(wire.State.Decisions[i], decision) {
				t.Error("decision authority lost bytes")
			}
			instructions := wire.Questions[decision.ID].Instructions
			if !strings.Contains(instructions, fmt.Sprintf("state.decisions[%d]", i)) ||
				strings.Contains(instructions, decision.Text) {
				t.Error("guidance instructions changed")
			}
		}
		writeJSON(t, w, response(raw))
	}))
	defer server.Close()
	adapter, err := New(options(server.URL, r, &retained{}))
	if err != nil {
		t.Fatal(err)
	}
	got, err := adapter.Evaluate(context.Background(), r)
	if err != nil || got.Status != "scored" || len(got.Results) != 2 ||
		got.Results[0].QuestionID != "partial" || got.Results[0].Probability == nil {
		t.Fatal("guidance or data ID rejected")
	}
}

func TestQuestionCoverageAndZero(t *testing.T) {
	r := request()
	body, ids, err := Payload(r)
	if err != nil {
		t.Fatal(err)
	}
	root := response(body)
	root["answers"].(map[string]any)["rule-a"].(map[string]any)["noul"] = 0
	raw, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeResponse(raw, ids, r.Config.Model)
	if err != nil || got.answers["rule-a"] != 0 || len(got.answers) != 1 {
		t.Fatal("valid scored zero was lost")
	}
	for _, name := range []string{"duplicate", "too-many", "empty", "unknown-id", "bad-hash"} {
		t.Run(name, func(t *testing.T) {
			r := request()
			switch name {
			case "duplicate":
				r.Rules = append(r.Rules, r.Rules[0])
			case "too-many":
				for i := range 12 {
					rule := r.Rules[0]
					rule.ID = api.ID(fmt.Sprintf("rule-%d", i))
					r.Rules = append(r.Rules, rule)
				}
			case "empty":
				r.Rules = []api.JudgeRule{}
			case "unknown-id":
				r.Rules[0].ID = "not an id"
			case "bad-hash":
				r.Command.RawSHA256 = Digest([]byte("other command"))
			}
			if _, _, err := Payload(r); err == nil {
				t.Fatal("invalid question set accepted")
			}
		})
	}
}

func TestStrictFrozenJSON(t *testing.T) {
	raw, err := json.Marshal(request())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"valid", "unknown", "duplicate", "null", "missing", "trailing", "negative", "bytes-array"} {
		t.Run(name, func(t *testing.T) {
			var root map[string]any
			if err := json.Unmarshal(raw, &root); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "unknown":
				root["questions"] = map[string]any{}
			case "null":
				root["rules"] = nil
			case "missing":
				delete(root, "deadline_ms")
			case "negative":
				root["max_cost_micros"] = -1
			case "bytes-array":
				root["task"] = []int{65}
			}
			input, err := json.Marshal(root)
			if err != nil {
				t.Fatal(err)
			}
			if name == "duplicate" {
				input = append([]byte(`{"id":"duplicate",`), input[1:]...)
			}
			if name == "trailing" {
				input = append(input, []byte("{}")...)
			}
			var parsed api.JudgeRequest
			if err := DecodeStrict(input, &parsed); (err == nil) != (name == "valid") {
				t.Fatal("strict shape control failed")
			}
		})
	}
}
