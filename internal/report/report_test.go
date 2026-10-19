package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/eventstore"
)

func TestDeliveryContinuesAfterFailure(t *testing.T) {
	directory := t.TempDir()
	payload := eventstore.Object{"report_id": "report-" + strings.Repeat("1", 32), "text": "file delivery after the failing channel"}
	var outcomes []Delivery
	var stdout, stderr bytes.Buffer
	channels := []channel{
		{"dashboard", true, func() error { return appendFile(directory, "dashboard.jsonl", payload) }},
		{"discord", true, func() error { return fmt.Errorf("Discord REST request failed (HTTP 500)") }},
		{"file", true, func() error { return appendFile(directory, "owner/queue.jsonl", payload) }},
		{"terminal", false, nil},
	}
	code := deliver(text(payload["report_id"]), channels, func(d Delivery) error { outcomes = append(outcomes, d); return nil }, &stdout, &stderr)
	if code != 4 {
		t.Fatalf("partial report exit = %d, want 4", code)
	}
	if len(outcomes) != 4 || outcomes[0].Status != "delivered" || outcomes[1].Status != "failed" || outcomes[2].Status != "delivered" || outcomes[3].Status != "skipped" {
		t.Fatalf("every channel must have an independent outcome: %+v", outcomes)
	}
	data, err := os.ReadFile(filepath.Join(directory, "owner/queue.jsonl"))
	if err != nil || !bytes.Contains(data, []byte(text(payload["text"]))) {
		t.Fatal("the file channel after HTTP 500 did not retain the report")
	}
	decoder := json.NewDecoder(&stdout)
	for _, expected := range outcomes {
		var actual Delivery
		if err := decoder.Decode(&actual); err != nil || actual != expected {
			t.Fatal("stdout did not repeat each recorded channel outcome")
		}
	}
	if stderr.Len() != 0 {
		t.Fatal("successful outcome records unexpectedly failed")
	}
	for _, spec := range []struct {
		channels []channel
		code     int
	}{
		{[]channel{{"dashboard", true, func() error { return appendFile(directory, "all.jsonl", payload) }}}, 0},
		{[]channel{{"dashboard", true, func() error { return fmt.Errorf("store unavailable") }}}, 3},
	} {
		var out, errOut bytes.Buffer
		if actual := deliver(text(payload["report_id"]), spec.channels, func(d Delivery) error {
			return appendFile(directory, "outcomes.jsonl", eventstore.Object{"status": d.Status})
		}, &out, &errOut); actual != spec.code {
			t.Fatalf("delivery exit = %d, want %d", actual, spec.code)
		}
	}
	var out, errOut bytes.Buffer
	if code := deliver(text(payload["report_id"]), channels[:1], func(Delivery) error { return fmt.Errorf("store unavailable") }, &out, &errOut); code != 4 || !strings.Contains(errOut.String(), "cannot record report.delivered") {
		t.Fatal("an outcome-store failure was hidden")
	}
}

func TestReportBoundariesAndFiles(t *testing.T) {
	if err := validateText([]byte(strings.Repeat("報", 4000))); err != nil {
		t.Fatal("the limit counts characters, not bytes")
	}
	token := "gh" + "p_" + strings.Repeat("X", 40)
	for _, bad := range [][]byte{[]byte(strings.Repeat("報", 4001)), {}, []byte(" \n\t"), {0xff}, []byte("a credential: " + token)} {
		if err := validateText(bad); err == nil {
			t.Fatal("invalid report text reached channel delivery")
		}
	}
	root := t.TempDir()
	payload := eventstore.Object{"text": "the canary report"}
	if err := appendFile(root, "owner/queue.jsonl", payload); err != nil {
		t.Fatal(err)
	}
	if err := appendFile(root, "../outside.jsonl", payload); err == nil {
		t.Fatal("the file channel escaped its root")
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	if err := appendFile(root, "alias/queue.jsonl", payload); err == nil {
		t.Fatal("the file channel followed a symlink")
	}
	if _, err := os.Stat(filepath.Join(outside, "queue.jsonl")); !os.IsNotExist(err) {
		t.Fatal("a refused file channel wrote its canary outside the root")
	}
	if err := os.Link(filepath.Join(root, "owner/queue.jsonl"), filepath.Join(root, "linked.jsonl")); err != nil {
		t.Fatal(err)
	}
	if err := appendFile(root, "linked.jsonl", payload); err == nil {
		t.Fatal("the file channel accepted a multiply linked file")
	}
	for _, args := range [][]string{{"--to", "lane:a1", "--file", "-"}, {"watch", "--as", "human", "--file", "-"}, {"--file", "-", "--file", "-"}} {
		if _, err := parse(args); err == nil {
			t.Fatal("an unsupported or ambiguous report command was accepted")
		}
	}
}

func TestReportTargetsAndRefusalText(t *testing.T) {
	recorded := map[string]caller.Principal{
		"lane:a1": {ID: "lane:a1", Level: 3, Starter: "supervisor:mini-a"},
		"lane:a2": {ID: "lane:a2", Level: 3, Starter: "supervisor:mini-a"},
		"lane:a3": {ID: "lane:a3", Level: 3, Starter: "supervisor:mini-a"},
		"lane:b1": {ID: "lane:b1", Level: 3, Starter: "supervisor:mini-b"},
	}
	want := "lane a1 (L3, supervisor supervisor:mini-a) may not message lane b1 (L3, supervisor supervisor:mini-b): lanes talk only to lanes of the same level under the same supervisor.\nInstead: report up with laneboss report (to supervisor:mini-a), or message a2, a3 (L3, supervisor supervisor:mini-a)."
	if err := refusal(recorded["lane:a1"], recorded["lane:b1"], recorded, "message"); err.Error() != want {
		t.Fatalf("refusal text = %q", err.Error())
	}
	c := &config.Configuration{Data: map[string]any{"supervisors": map[string]any{"mini-a": map[string]any{"level": int64(4)}}}}
	if got := target(c, caller.Principal{ID: "lane:a1", Level: 3}, recorded); got.ID != "supervisor:mini-a" || got.Level != 4 {
		t.Fatal("the report did not use the recorded supervisor and its configured level")
	}
	recorded["lane:old"] = caller.Principal{ID: "lane:old", Level: 0, Starter: "supervisor:mini-a"}
	for _, p := range []caller.Principal{{ID: "lane:old"}, {ID: "lane:missing"}, {ID: "supervisor:mini-a", Level: 4}, {ID: "instance:root", Level: 6}, {}} {
		if got := target(c, p, recorded); got.ID != "human" || got.Level != 0 {
			t.Fatal("a missing level or parent was guessed instead of reporting to the human")
		}
	}
	if got := principalNode(caller.Principal{ID: "lane:a1", Level: 6}, recorded); !reflect.DeepEqual(got, recorded["lane:a1"]) {
		t.Fatal("caller-supplied level replaced a recorded lane level")
	}
}

func TestTerminalCanary(t *testing.T) {
	state := t.TempDir()
	root, err := terminalRoot(state, true)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	directory, err := root.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if err = createFIFO(root, directory, "human.fifo"); err != nil {
		t.Fatal(err)
	}
	pipe, err := root.OpenFile("human.fifo", os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer pipe.Close()
	start, err := processStart(os.Getpid())
	if err != nil || start == "" {
		t.Fatal("cannot record the canary's actual process identity")
	}
	writeTicket := func(value string) {
		t.Helper()
		data, err := json.Marshal(terminalTicket{PID: os.Getpid(), Start: value, Target: "human"})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(state, "reports/terminals/human.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeTicket(start + "-stale")
	if live, err := terminalLive(state, "human"); err != nil || live {
		t.Fatal("a stale process start was accepted as a live terminal")
	}
	writeTicket(start)
	if live, err := terminalLive(state, "human"); err != nil || !live {
		t.Fatal("the actual process identity did not install the terminal")
	}
	id := "report-" + strings.Repeat("2", 32)
	payload := eventstore.Object{"report_id": id, "to": "human", "text": strings.Repeat("報", 4000)}
	if err := sendTerminal(state, "human", payload); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 128)
	n, err := syscall.Read(int(pipe.Fd()), buffer)
	if err != nil || string(buffer[:n]) != id+"\n" {
		t.Fatal("terminal delivery did not notify the real FIFO")
	}
	data, err := root.ReadFile(id + ".json")
	var received eventstore.Object
	if err != nil || json.Unmarshal(data, &received) != nil || received["text"] != payload["text"] {
		t.Fatal("terminal delivery lost the full multibyte report")
	}
	writeTicket(start + "-stale")
	if err := sendTerminal(state, "human", eventstore.Object{"report_id": "report-" + strings.Repeat("3", 32), "to": "human", "text": "stale canary"}); err == nil {
		t.Fatal("a stale watcher received a report")
	}
}
