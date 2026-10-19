package judge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Published capacity contracts, independent of the implementation constants so
// these rows can also run against the release base without compile changes.
const scalarCapacityReserve = 1024
const batchCapacityReserve = 4096

func capacitySent(id string, batch bool) []byte {
	record := map[string]any{"at": "2026-10-15T00:00:00.000000Z", "ask": id, "event": "sent", "judge": "capacity",
		"question": "capacity.check", "lane": nil, "request_sha256": strings.Repeat("a", 64), "request_bytes": 100,
		"withheld": []string{}, "cut": []string{}}
	if batch {
		record["outcome_reserve"] = batchCapacityReserve
	}
	return logBytes(record)
}

func capacityOutcome(id string, batch bool) []byte {
	record := map[string]any{"at": "2026-10-15T00:00:00.000000Z", "ask": id, "event": "outcome", "outcome": "answered",
		"probability": 0.25, "model": strings.Repeat("m", 128), "request": strings.Repeat("r", 128), "duration_ms": int64(9223372036854775807)}
	if batch {
		record["probability"] = nil
		values := map[string]float64{}
		for i := 0; i < 36; i++ {
			values[fmt.Sprintf("d%02d-%s", i, strings.Repeat("x", 60))] = 0.0000010000000000000002
		}
		record["probabilities"] = values
	}
	return logBytes(record)
}

func TestCapacityReserveClasses(t *testing.T) {
	ids := []string{strings.Repeat("a", 32), strings.Repeat("b", 32), strings.Repeat("c", 32)}
	for _, row := range []struct {
		name       string
		pending    []bool
		newBatch   bool
		finishLast bool
	}{
		{"scalar", nil, false, false},
		{"batch", nil, true, false},
		{"unfinished-scalar", []bool{false}, false, false},
		{"unfinished-batch", []bool{true}, false, false},
		{"mixed", []bool{false, true}, true, false},
		{"scalar-completes-before-batch", []bool{true, false}, false, true},
		{"batch-completes-before-scalar", []bool{false, true}, true, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			d, err := openDirectory(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer d.close()
			var before []byte
			reserved := 0
			for i, batch := range row.pending {
				before = append(before, capacitySent(ids[i], batch)...)
				reserve := scalarCapacityReserve
				if batch {
					reserve = batchCapacityReserve
				}
				if row.finishLast && i == len(row.pending)-1 {
					before = append(before, capacityOutcome(ids[i], batch)...)
				} else {
					reserved += reserve
				}
			}
			if err := d.writeNew("egress.jsonl", before, false); err != nil {
				t.Fatal(err)
			}
			sent := capacitySent(ids[2], row.newBatch)
			reserve := scalarCapacityReserve
			if row.newBatch {
				reserve = batchCapacityReserve
			}
			exact := len(before) + len(sent) + reserved + reserve
			d.logLimit = exact - 1
			err = d.writeLog(sent, true, nothingAsked)
			var ce *commandError
			if !errors.As(err, &ce) || ce.code != 7 || !strings.Contains(ce.message, "is full") {
				t.Fatalf("one byte short must refuse as full: %v", err)
			}
			got, err := d.readLog()
			if err != nil || !bytes.Equal(got, before) {
				t.Fatalf("refusal changed or made the log unreadable: %v", err)
			}
			d.logLimit = exact
			if err := d.writeLog(sent, true, nothingAsked); err != nil {
				t.Fatalf("exact fit for the outstanding reserve classes was refused: %v", err)
			}
			if err := d.writeLog(capacityOutcome(ids[2], row.newBatch), false, outcomeUnlogged); err != nil {
				t.Fatal("admitted outcome did not fit", err)
			}
			for i, batch := range row.pending {
				if row.finishLast && i == len(row.pending)-1 {
					continue
				}
				if err := d.writeLog(capacityOutcome(ids[i], batch), false, outcomeUnlogged); err != nil {
					t.Fatal("pending outcome spent another ask's reserve", err)
				}
			}
			got, err = d.readLog()
			if err != nil || len(got) > exact {
				t.Fatalf("completed log exceeded its reader: %d > %d, %v", len(got), exact, err)
			}
			for _, raw := range bytes.Split(got, []byte{'\n'}) {
				if len(raw) != 0 {
					if _, err := parseLogLine(raw); err != nil {
						t.Fatal("completed record failed validation", err)
					}
				}
			}
		})
	}
}

func TestCapacityReserveMarkerValidation(t *testing.T) {
	valid, err := parseLogLine(capacitySent(strings.Repeat("a", 32), true))
	if err != nil {
		t.Fatal("bounded batch sent record was rejected", err)
	}
	for _, invalid := range []any{nil, true, "4096", 0, 1024, 4095, 4097, 4096.5} {
		valid["outcome_reserve"] = invalid
		if _, err := parseLogLine(logBytes(valid)); err == nil {
			t.Fatalf("invalid reserve marker %v was accepted", invalid)
		}
	}
}

func TestCapacityRealBatchProtocol(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("the disposable test machine needs python3 for the adapter", err)
	}
	adapter, err := filepath.Abs("testdata/capacity_adapter.py")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	home := filepath.Join(root, "config")
	states := filepath.Join(root, "state")
	records := filepath.Join(root, "adapter-records")
	configDir := filepath.Join(home, "configs", "capacity")
	for _, path := range []string{configDir, records} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("LANEBOSS_CONFIG", "capacity")
	t.Setenv("LANEBOSS_HOME", home)
	t.Setenv("LANEBOSS_STATE_HOME", states)
	t.Setenv("LANEBOSS_LANE", "")
	t.Setenv("LANEBOSS_JUDGE_MAX_EGRESS_BYTES", "32768")
	config := "schema_version = 1\nname = \"capacity\"\n[runners.unused]\ncommand = [\"/bin/true\", \"{brief}\"]\n"
	for _, mode := range []string{"answer", "partial", "no-usage"} {
		command := []string{python, adapter, records, filepath.Join(root, "release"), mode}
		config += fmt.Sprintf("[judges.%s]\ncommand = %s\n", mode, encodeJSON(command))
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.toml"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	questions := map[string]any{}
	for i := 0; i < 36; i++ {
		questions[fmt.Sprintf("d%02d-%s", i, strings.Repeat("x", 60))] = map[string]any{
			"type": "noul", "instructions": fmt.Sprintf("Check the actual state item %d.", i)}
	}
	for _, mode := range []string{"partial", "no-usage", "answer"} {
		verdict, err := AskNoulsContext(context.Background(), "capacity", mode, "capacity.check",
			map[string]any{"text": "complete batch input"}, questions)
		if err != nil {
			t.Fatal("real batch invocation failed", err)
		}
		if mode != "answer" {
			if verdict.Outcome != "output" || len(verdict.Probabilities) != 0 {
				t.Fatal("invalid official envelope was accepted", mode, verdict)
			}
			continue
		}
		if verdict.Outcome != "answered" || len(verdict.Probabilities) != len(questions) {
			t.Fatal("complete independent batch was lost", verdict)
		}
		for id, question := range questions {
			instructions := question.(map[string]any)["instructions"].(string)
			if verdict.Probabilities[id] != float64(len(instructions)%10)/10 {
				t.Fatal("batch result did not come from the actual question", id)
			}
		}
	}
	entries, err := os.ReadDir(records)
	if err != nil || len(entries) != 3 {
		t.Fatalf("each batch must use one adapter invocation: %d, %v", len(entries), err)
	}
	for _, entry := range entries {
		raw, err := os.ReadFile(filepath.Join(records, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var record struct {
			Request map[string]any `json:"request"`
		}
		if err := json.Unmarshal(raw, &record); err != nil {
			t.Fatal(err)
		}
		if record.Request["kind"] != "typed" || len(tableValue(record.Request["questions"])) != len(questions) ||
			tableValue(record.Request["state"])["text"] != "complete batch input" {
			t.Fatal("adapter did not receive the complete typed state and question set")
		}
	}
	c, err := loadConfiguration(options{config: "capacity", configSet: true})
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := readEgress(c, options{}, &output); err != nil {
		t.Fatal("real batch egress was unreadable", err)
	}
	lines := bytes.Split(bytes.TrimSpace(output.Bytes()), []byte{'\n'})
	if len(lines) != 6 {
		t.Fatal("each batch must have one sent and one outcome record", len(lines))
	}
	for i, raw := range lines {
		record, err := parseLogLine(raw)
		if err != nil {
			t.Fatal(err)
		}
		if i%2 == 0 && record["outcome_reserve"] != json.Number("4096") {
			t.Fatal("real batch did not persist its reserve class")
		}
	}
	if len(lines[5])+1 <= scalarCapacityReserve || len(lines[5])+1 > batchCapacityReserve {
		t.Fatal("real batch outcome did not exercise the larger bounded reserve", len(lines[5])+1)
	}
}
