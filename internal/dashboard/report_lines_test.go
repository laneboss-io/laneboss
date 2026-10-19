package dashboard

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/config"
)

func TestGraphRecordedParents(t *testing.T) {
	c := &config.Configuration{Name: "recorded", Data: object{"supervisors": object{
		"mini-a": object{"level": 5}, "mini-b": object{"level": 6},
	}}}
	lanes := []object{{"lane": "a1"}, {"lane": "b1"}, {"lane": "old"}, {"lane": "child"}, {"lane": "missing"}}
	events := []object{
		{"kind": "lane.started", "lane": "a1", "payload": object{"level": 3, "level_source": "protocol", "starter": "supervisor:mini-a"}},
		{"kind": "lane.adopted", "lane": "b1", "payload": object{"level": 4, "level_source": "supervisors", "starter": "human"}},
		{"kind": "lane.started", "lane": "old", "payload": object{}},
		{"kind": "lane.started", "lane": "child", "payload": object{"level": 3, "level_source": "protocol", "starter": "lane:b1"}},
		{"kind": "lane.started", "lane": "missing", "payload": object{"level": 3, "level_source": "protocol", "starter": "supervisor:absent"}},
	}
	index, err := buildGraphInputs(context.Background(), c, lanes, events, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	data, err := index.view(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if root := obj(data["root"]); root["id"] != "human" || root["parent"] != nil || root["level"] != nil {
		t.Fatal("the human root acquired a level or a parent")
	}
	expected := map[string]any{"lane:a1": "supervisor:mini-a", "lane:b1": "human", "lane:old": unrecordedSupervisor, "lane:child": "lane:b1", "lane:missing": unrecordedSupervisor, "supervisor:mini-a": "human", "supervisor:mini-b": "human"}
	check := func(nodes []object) error {
		if len(nodes) != len(expected) {
			return fmt.Errorf("graph lost an input principal")
		}
		seen := map[string]bool{}
		last := 7.0
		for _, node := range nodes {
			id := str(node["id"])
			if seen[id] || expected[id] == nil || node["parent"] != expected[id] {
				return fmt.Errorf("parent was lost or invented for %s", id)
			}
			seen[id] = true
			if level := node["level"]; level != nil {
				if number(level) > last {
					return fmt.Errorf("bands do not descend from the highest recorded level")
				}
				last = number(level)
			}
			if id == "lane:old" && (node["level"] != nil || node["level_source"] != nil || node["starter"] != nil) {
				return fmt.Errorf("old event metadata was inferred")
			}
			if id == "lane:a1" && (node["level"] != 3 || node["level_source"] != "protocol") {
				return fmt.Errorf("recorded level/source changed")
			}
			if node["kind"] != "lane" && node["parent_recorded"] != false {
				return fmt.Errorf("configured principal acquired a recorded supervisor")
			}
		}
		return nil
	}
	nodes := data["nodes"].([]object)
	mutated := make([]object, len(nodes))
	for i, node := range nodes {
		mutated[i] = object{}
		for key, value := range node {
			mutated[i][key] = value
		}
		if node["id"] == "lane:old" {
			mutated[i]["parent"] = "human"
		}
	}
	if err := check(mutated); err == nil || !strings.Contains(err.Error(), "invented") {
		t.Fatal("invented-human-parent control was accepted")
	} else {
		t.Log("negative control rejected:", err)
	}
	if err := check(nodes); err != nil {
		t.Fatal(err)
	}
	groups := data["groups"].([]object)
	if len(groups) != 1 || groups[0]["id"] != unrecordedSupervisor || groups[0]["level"] != nil {
		t.Fatal("missing supervisors were drawn on a numbered rail")
	}
}

func TestLifecycleActorView(t *testing.T) {
	cases := []struct {
		kind, step string
		payload    object
	}{
		{"lane.started", "start", object{"how": "start"}},
		{"lane.adopted", "adopt", object{}},
		{"lane.resumed", "resume", object{}},
		{"lane.started", "turn", object{"how": "resume", "mail": []any{1}}},
		{"lane.ended", "stop", object{"reason": "stopped"}},
		{"lane.state", "accepted", object{"state": "accepted"}},
		{"lane.merged", "merged", object{}},
		{"lane.state", "abandoned", object{"state": "abandoned"}},
		{"lane.cleaned", "clean", object{}},
		{"lane.lost", "lost", object{}},
	}
	actors := []string{"supervisor:mini-a", "human", "laneboss", "lane:a1"}
	events := make([]object, len(cases))
	for i, row := range cases {
		events[i] = object{"id": fmt.Sprintf("lifecycle-%d", i), "seq": i + 1, "kind": row.kind, "lane": "a1", "actor": actors[i%len(actors)], "payload": row.payload}
	}
	rows := eventView(events, len(events))
	check := func(rows []object) error {
		if len(rows) != len(events) {
			return fmt.Errorf("lifecycle event disappeared")
		}
		for i, row := range rows {
			input := len(events) - 1 - i
			if row["id"] != events[input]["id"] || row["actor"] != events[input]["actor"] {
				return fmt.Errorf("recorded actor was replaced at sequence %v", row["seq"])
			}
			if row["step"] != cases[input].step || row["kind"] != cases[input].kind {
				return fmt.Errorf("recorded lifecycle step changed at sequence %v", row["seq"])
			}
		}
		return nil
	}
	mutated := make([]object, len(rows))
	for i, row := range rows {
		mutated[i] = object{}
		for key, value := range row {
			mutated[i][key] = value
		}
		mutated[i]["actor"] = "laneboss"
	}
	if err := check(mutated); err == nil || !strings.Contains(err.Error(), "actor") {
		t.Fatal("fixed-launcher-actor control was accepted")
	} else {
		t.Log("negative control rejected:", err)
	}
	if err := check(rows); err != nil {
		t.Fatal(err)
	}
	old := eventView([]object{{"kind": "lane.started", "payload": object{}}}, 1)
	if old[0]["actor"] != nil {
		t.Fatal("an old event acquired an actor")
	}
}

func TestDashboardUnauthorizedStatus(t *testing.T) {
	token, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	h := &handler{host: "127.0.0.1:1234", token: token}
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		r := httptest.NewRequest(method, "http://127.0.0.1:1234/api/messages/send", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized || w.Body.Len() != 0 {
			t.Fatalf("unauthenticated %s was not rejected with an empty 401", method)
		}
	}
	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:1234/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "<!doctype html>") {
		t.Fatal("the static shell no longer returns 200")
	}
	r.Host = "foreign.invalid"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatal("a foreign Host reached the shell")
	}
}

func TestReportHumanFallbackView(t *testing.T) {
	c := &config.Configuration{Name: "recorded", Data: object{}}
	events := []object{{"id": "report-record", "seq": 1, "kind": "report.sent", "actor": "lane:a1", "payload": object{"from": "lane:a1", "from_level": 3, "to": "human", "to_level": nil, "text": "Recorded progress"}}}
	data, err := messageView(context.Background(), c, nil, events)
	if err != nil {
		t.Fatal(err)
	}
	rows := data["human_agent"].([]object)
	if len(rows) != 1 || rows[0]["from"] != "lane:a1" || rows[0]["to"] != "human" || rows[0]["text"] != events[0]["payload"].(object)["text"] {
		t.Fatal("a human fallback report disappeared or changed")
	}
	if rows[0]["direction"] != "outbound" {
		t.Fatal("a report to the human has the wrong direction")
	}
}
