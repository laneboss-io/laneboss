package lane

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/testdata"
	"laneboss.io/laneboss/internal/textcontext"
)

func TestObservationContract(t *testing.T) {
	testdata.Contract(t, parseJSON, func(payload map[string]any) error {
		return validatePayload(testdata.EventKind, testdata.Lane, payload)
	})
}

func TestObservationStoredBytes(t *testing.T) {
	fixture := testdata.OpenStore(t)
	s := &session{db: fixture.DB}
	events, err := s.laneEvents(testdata.Lane)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatal("the lane reader must read every stored fixture event")
	}
	row := emptyProjection(testdata.Lane)
	for _, event := range events {
		if err := checkTransition(row, event); err != nil {
			t.Fatal(err)
		}
		row = applyProjection(row, event)
	}
	testdata.AssertState(t, row)
	if err := checkTransition(row, events[1]); err == nil {
		t.Fatal("replay accepted a repeated observation")
	}
	var stored string
	if err := fixture.DB.QueryRow("SELECT projection FROM lanes WHERE lane = ?", testdata.Lane).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if string(canonical(row)) != stored {
		t.Fatal("lane replay disagrees with the writer's stored projection")
	}
}

func TestObservationWriterBytes(t *testing.T) {
	payload := testdata.Payload(t, parseJSON)
	command := str(obj(payload["command"])["text"])
	call := obj(payload["call"])
	pos := obj(call["record"])
	item := &scanItem{kind: "call", id: str(call["id"]), tool: str(payload["tool"]), class: "shell", text: command,
		length: len([]rune(command)), sha: digest([]byte(command)), run: integer(payload["run"]),
		line: integer(pos["line"]), offset: int64(integer(pos["offset"])), index: integer(pos["item"]),
		record: &scanRecord{path: str(pos["path"]), shown: str(pos["path"])}}
	var emitted []object
	scan := &refusalScan{lane: testdata.Lane, known: map[string]bool{}, emit: func(event object) error {
		emitted = append(emitted, event)
		return validatePayload(str(event["kind"]), str(event["lane"]), obj(event["payload"]))
	}}
	for i := 0; i < 2; i++ {
		if err := scan.substitutionCall(item); err != nil {
			t.Fatal(err)
		}
	}
	if len(emitted) != 1 || emitted[0]["kind"] != testdata.EventKind {
		t.Fatal("ordinary scanning must emit and deduplicate the actual observation")
	}
	if !bytes.Equal(canonical(emitted[0]["payload"]), testdata.PayloadBytes()) {
		t.Fatal("the ordinary scanner emitted a different observation shape or identity")
	}
}

func TestObservationPolicySource(t *testing.T) {
	org := t.TempDir()
	path := filepath.Join(org, textcontext.Source)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	data := []byte("schema_version = 1\n[[tools]]\ncommand = ['record-tool', 'send']\ntext_from = 3\n")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	configuration := object{"org_dir": org}
	tools, err := textcontext.Load("", configuration, screenRoleSource)
	if err != nil || len(tools) != 1 || tools[0].Command[0] != "record-tool" || tools[0].TextFrom != 3 {
		t.Fatal("the lane scanner must load the real TOML observation policy")
	}
	if err := os.WriteFile(path, append(data, []byte("# Authorization: Bearer "+strings.Repeat("x", 32)+"\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := textcontext.Load("", configuration, screenRoleSource); err == nil || !strings.Contains(err.Error(), "credential shapes") {
		t.Fatal("the lane's credential checker must screen policy source bytes, including comments")
	}
}
