package dashboard

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/eventstore"
)

func TestEventBoardRecordedLevels(t *testing.T) {
	now := time.Now().UTC()
	c := &config.Configuration{Name: "levels", Data: object{"supervisors": object{
		"orphan": object{"level": 5}, "lead": object{"level": 6},
	}}}
	events := []eventstore.Object{
		{"id": "before", "kind": "demo.note", "lane": "work", "payload": object{}},
		{"id": "start", "kind": "lane.started", "lane": "work", "payload": object{"level": 3}},
		{"id": "end", "kind": "lane.ended", "lane": "work", "payload": object{}},
		{"id": "explicit", "kind": "demo.note", "lane": "work", "payload": object{"level": 6}},
		{"id": "resume", "kind": "lane.resumed", "lane": "work", "payload": object{}},
		{"id": "adopt", "kind": "lane.adopted", "lane": "other", "payload": object{"level": 4}},
		{"id": "adopt-end", "kind": "lane.ended", "lane": "other", "payload": object{}},
		{"id": "new-start", "kind": "lane.started", "lane": "work", "payload": object{"level": 5}},
		{"id": "new-end", "kind": "lane.ended", "lane": "work", "payload": object{}},
		{"id": "missing-start", "kind": "lane.started", "lane": "work", "payload": object{}},
		{"id": "missing-end", "kind": "lane.ended", "lane": "work", "payload": object{}},
		{"id": "orphan", "kind": "demo.note", "lane": "orphan", "payload": object{}},
		{"id": "supervisor", "kind": "supervisor.heartbeat", "payload": object{"supervisor": "lead"}},
		{"id": "unscoped", "kind": "demo.note", "payload": object{}},
	}
	for i, event := range events {
		event["seq"] = i + 1
		event["recorded_at"] = now.Add(time.Duration(i-20) * time.Second).Format(time.RFC3339Nano)
	}
	value, err := eventBoard(c, events, eventOptions{limit: 100}, now)
	if err != nil {
		t.Fatal(err)
	}
	rows := value.([]object)
	expected := map[string]any{"before": nil, "start": 3, "end": 3, "explicit": 6, "resume": 3, "adopt": 4, "adopt-end": 4, "new-start": 5, "new-end": 5, "missing-start": nil, "missing-end": nil, "orphan": nil, "supervisor": 6, "unscoped": nil}
	check := func(rows []object) error {
		if len(rows) != len(expected) {
			return fmt.Errorf("event rows were lost")
		}
		seen := map[string]bool{}
		for _, row := range rows {
			id := str(row["id"])
			want, exists := expected[id]
			if !exists || seen[id] || row["level"] != want {
				return fmt.Errorf("recorded level was lost or backfilled for %s", str(row["id"]))
			}
			seen[id] = true
		}
		return nil
	}
	control := make([]object, len(rows))
	for i, row := range rows {
		control[i] = object{}
		for key, value := range row {
			control[i][key] = value
		}
		if row["id"] == "end" {
			control[i]["level"] = nil
		}
	}
	if err := check(control); err == nil || !strings.Contains(err.Error(), "lost") {
		t.Fatal("missing-level negative control was accepted")
	} else {
		t.Log("negative control rejected:", err)
	}
	if err := check(rows); err != nil {
		t.Fatal(err)
	}
	filtered, err := eventBoard(c, events, eventOptions{limit: 1, level: 3, board: true}, now)
	if err != nil {
		t.Fatal(err)
	}
	board := obj(filtered)
	filteredRows := board["events"].([]object)
	if len(filteredRows) != 1 || filteredRows[0]["id"] != "resume" || filteredRows[0]["level"] != 3 {
		t.Fatal("level filtering used the latest run or applied the limit before filtering")
	}
	if counts := obj(board["counts_last_hour"]); number(counts["lane.ended"]) != 1 || number(counts["lane.resumed"]) != 1 {
		t.Fatal("hourly counts lost events that inherited their lane level")
	}
}

func TestHeartbeatGraphMetadata(t *testing.T) {
	c := &config.Configuration{Name: "heartbeat", Data: object{"supervisors": object{
		"lead": object{"level": 5}, "stream": object{"level": 4},
	}}}
	now := time.Now().UTC()
	events := []object{
		{"kind": "supervisor.heartbeat", "recorded_at": now.Format(time.RFC3339Nano), "payload": object{"supervisor": "lead", "model": "example-model-large-1", "state": "running", "starter": "human"}},
		{"kind": "supervisor.heartbeat", "recorded_at": now.Format(time.RFC3339Nano), "payload": object{"supervisor": "stream", "model": "example-model-medium-1", "state": "running", "starter": "supervisor:lead"}},
	}
	index, err := buildGraphInputs(context.Background(), c, nil, events, now)
	if err != nil {
		t.Fatal(err)
	}
	data, err := index.view(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	nodes := data["nodes"].([]object)
	if len(nodes) != 2 {
		t.Fatal("heartbeat graph lost a configured supervisor")
	}
	check := func(nodes []object, recorded bool) error {
		parents := map[string]string{"supervisor:lead": "human", "supervisor:stream": "supervisor:lead"}
		models := map[string]string{"supervisor:lead": "example-model-large-1", "supervisor:stream": "example-model-medium-1"}
		if len(nodes) != len(parents) {
			return fmt.Errorf("heartbeat graph lost a configured supervisor")
		}
		seen := map[string]bool{}
		for _, node := range nodes {
			id := str(node["id"])
			if parents[id] == "" || seen[id] {
				return fmt.Errorf("heartbeat graph duplicated or invented a principal")
			}
			seen[id] = true
			if !recorded {
				if node["state"] != "unknown" || node["model"] != nil || node["starter"] != nil || flag(node["parent_recorded"]) {
					return fmt.Errorf("configuration alone fabricated state, model or a parent")
				}
				continue
			}
			if node["state"] != "running" || node["model"] != models[id] {
				return fmt.Errorf("recorded heartbeat state/model was lost")
			}
			if node["parent"] != parents[id] || node["starter"] != parents[id] || !flag(node["parent_recorded"]) {
				return fmt.Errorf("recorded heartbeat parent was lost")
			}
		}
		return nil
	}
	clone := func(rows []object) []object {
		result := make([]object, len(rows))
		for i, row := range rows {
			result[i] = object{}
			for key, value := range row {
				result[i][key] = value
			}
		}
		return result
	}
	for _, field := range []string{"state", "parent"} {
		control := clone(nodes)
		control[0][field] = "unknown"
		if err := check(control, true); err == nil || !strings.Contains(err.Error(), field) {
			t.Fatal("missing-heartbeat-metadata negative control was accepted")
		} else {
			t.Log("negative control rejected:", err)
		}
	}
	if err := check(nodes, true); err != nil {
		t.Fatal(err)
	}
	index, err = buildGraphInputs(context.Background(), c, nil, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	control := clone(index.nodes)
	if len(control) != 2 {
		t.Fatal("unrecorded graph lost a configured supervisor")
	}
	control[0]["state"] = "running"
	if err := check(control, false); err == nil || !strings.Contains(err.Error(), "fabricated") {
		t.Fatal("fabricated-state negative control was accepted")
	} else {
		t.Log("negative control rejected:", err)
	}
	if err := check(index.nodes, false); err != nil {
		t.Fatal(err)
	}
}

func TestCompactEventLevelMarkup(t *testing.T) {
	document := experiencePage()
	check := func(document string) error {
		cell := between(document, "function eventLevelCell(", "\n")
		if !strings.Contains(cell, "recordNode('span','—')") || !strings.Contains(cell, "cell.title=tr('Level not recorded')") {
			return fmt.Errorf("unknown level has no compact glyph and tooltip")
		}
		if !strings.Contains(document, ".event-level-cell,.event-level-cell span{white-space:nowrap!important") || !strings.Contains(document, "eventLevelCell(e.level)") {
			return fmt.Errorf("the event board did not wire the compact level cell")
		}
		return nil
	}
	control := strings.Replace(document, "recordNode('span','—')", "node('span','Level not recorded')", 1)
	if err := check(control); err == nil {
		t.Fatal("verbose-level negative control was accepted")
	} else {
		t.Log("negative control rejected:", err)
	}
	if err := check(document); err != nil {
		t.Fatal(err)
	}
}
