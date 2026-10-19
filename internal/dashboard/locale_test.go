package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/eventstore"
)

func checkMessages(data []byte) error {
	var table map[string]map[string]string
	if err := json.Unmarshal(data, &table); err != nil {
		return err
	}
	if len(table) == 0 {
		return fmt.Errorf("message table is empty")
	}
	parameters := regexp.MustCompile(`\{([A-Za-z][A-Za-z0-9_]*)\}`)
	for key, row := range table {
		if len(row) != 2 || strings.TrimSpace(row["en"]) == "" || strings.TrimSpace(row["zh-TW"]) == "" {
			return fmt.Errorf("message %q lacks a language", key)
		}
		placeholders := func(value string) string {
			names := []string{}
			for _, match := range parameters.FindAllStringSubmatch(value, -1) {
				names = append(names, match[1])
			}
			sort.Strings(names)
			return strings.Join(names, ",")
		}
		if placeholders(row["en"]) != placeholders(row["zh-TW"]) {
			return fmt.Errorf("message %q has inconsistent arguments", key)
		}
	}
	return nil
}

func TestMessageLanguages(t *testing.T) {
	if err := checkMessages([]byte(localeData)); err != nil {
		t.Fatal(err)
	}
	var table map[string]map[string]string
	if err := json.Unmarshal([]byte(localeData), &table); err != nil {
		t.Fatal(err)
	}
	delete(table["Time"], "zh-TW")
	data, err := json.Marshal(table)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkMessages(data); err == nil {
		t.Fatal("missing-language control was accepted")
	}
}

func TestUnrecordedGraphLevel(t *testing.T) {
	// Input records model the reader's future schema, never a production fixture.
	metadata := []object{{"kind": "lane.started", "lane": "anonymous", "payload": object{}}, {"kind": "lane.started", "lane": "declared", "payload": object{"level": 4, "starter": "L5-top"}}}
	info := eventstore.RecordedLaneInfo(metadata)
	if info["anonymous"]["level"] != nil || info["anonymous"]["starter"] != nil {
		t.Fatal("unrecorded lane metadata was inferred")
	}
	if info["declared"]["level"] != 4 || info["declared"]["starter"] != "L5-top" {
		t.Fatal("explicit metadata was lost")
	}
	c := &config.Configuration{Name: "observed", Data: object{}}
	index, err := buildGraphInputs(context.Background(), c, []object{{"lane": "anonymous"}, {"lane": "declared"}}, metadata, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	check := func(nodes []object) error {
		byID := map[string]object{}
		for _, node := range nodes {
			byID[str(node["id"])] = node
		}
		if len(nodes) != 2 || len(byID) != 2 || byID["lane:anonymous"] == nil || byID["lane:declared"] == nil {
			return fmt.Errorf("graph lost an input lane")
		}
		if byID["lane:anonymous"]["level"] != nil || byID["lane:anonymous"]["starter"] != nil {
			return fmt.Errorf("anonymous lane landed on a numbered rail or acquired a starter")
		}
		if byID["lane:declared"]["level"] != 4 || byID["lane:declared"]["starter"] != "L5-top" {
			return fmt.Errorf("graph lost recorded metadata")
		}
		return nil
	}
	if err := check(index.nodes); err != nil {
		t.Fatal(err)
	}
	// The same assertion must reject the former all-L3 behavior.
	mutated := make([]object, len(index.nodes))
	for i, node := range index.nodes {
		mutated[i] = object{}
		for key, value := range node {
			mutated[i][key] = value
		}
		if node["id"] == "lane:anonymous" {
			mutated[i]["level"] = 3
		}
	}
	if err := check(mutated); err == nil || !strings.Contains(err.Error(), "numbered rail") {
		t.Fatal("all-L3 control was not rejected for inventing a level")
	}
	for _, value := range []any{nil, "4", 2, 7, 3.5} {
		if eventstore.RecordedLevel(value) != nil {
			t.Fatalf("invalid recorded level %v was accepted", value)
		}
	}
}
