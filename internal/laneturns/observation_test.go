package laneturns

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/testdata"
	"laneboss.io/laneboss/internal/textcontext"
)

func decodeObservation(data []byte) (any, error) { return decodeJSON(data) }

func TestObservationContract(t *testing.T) {
	testdata.Contract(t, decodeObservation, func(payload map[string]any) error {
		return checkPayload(testdata.EventKind, payload)
	})
}

func TestObservationStoredBytes(t *testing.T) {
	fixture := testdata.OpenStore(t)
	root, err := os.OpenRoot(fixture.Config.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	info, err := os.Stat(fixture.Path)
	if err != nil {
		t.Fatal(err)
	}
	store := &eventStore{state: &stateDir{path: fixture.Config.StatePath, root: root}, db: fixture.DB, fileInfo: info}
	events, err := store.events(testdata.Lane, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatal("the turn reader must read every stored fixture event")
	}
	row := emptyRow(testdata.Lane)
	for _, event := range events {
		if err := checkPayload(str(event["kind"]), obj(event["payload"])); err != nil {
			t.Fatal(err)
		}
		if err := checkTransition(row, event); err != nil {
			t.Fatal(err)
		}
		row = applyEvent(row, event)
	}
	testdata.AssertState(t, row)
	if err := checkTransition(row, events[1]); err == nil {
		t.Fatal("turn replay accepted a repeated observation")
	}
	var stored string
	if err := fixture.DB.QueryRow("SELECT projection FROM lanes WHERE lane = ?", testdata.Lane).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	data, err := canonical(row)
	if err != nil || string(data) != stored {
		t.Fatal("turn replay disagrees with the writer's stored projection")
	}
}

func TestObservationWriterBytes(t *testing.T) {
	payload := testdata.Payload(t, decodeObservation)
	command := str(obj(payload["command"])["text"])
	call := obj(payload["call"])
	pos := obj(call["record"])
	item := &scanItem{kind: "call", id: str(call["id"]), idGiven: true, tool: str(payload["tool"]), class: "shell", text: command,
		fullLength: len([]rune(command)), fullHash: digest([]byte(command)), run: integer(payload["run"]),
		line: integer(pos["line"]), offset: int64(integer(pos["offset"])), index: integer(pos["item"]),
		record: &scanRecord{path: str(pos["path"]), shown: str(pos["path"])}}
	var emitted []object
	scan := &laneScan{lane: testdata.Lane, known: map[string]bool{}, emit: func(kind string, payload object, at any) error {
		emitted = append(emitted, payload)
		return checkPayload(kind, payload)
	}}
	for i := 0; i < 2; i++ {
		if err := scan.substitutionCall(item); err != nil {
			t.Fatal(err)
		}
	}
	if len(emitted) != 1 {
		t.Fatal("live turn scanning must emit and deduplicate the actual observation")
	}
	data, err := canonical(emitted[0])
	if err != nil || !bytes.Equal(data, testdata.PayloadBytes()) {
		t.Fatal("the live turn scanner emitted a different observation shape or identity")
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
		t.Fatal("the turn scanner must load the real TOML observation policy")
	}
	if err := os.WriteFile(path, append(data, []byte("# Authorization: Bearer "+strings.Repeat("x", 32)+"\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := textcontext.Load("", configuration, screenRoleSource); err == nil || !strings.Contains(err.Error(), "credential shapes") {
		t.Fatal("the turn's credential checker must screen policy source bytes, including comments")
	}
}
