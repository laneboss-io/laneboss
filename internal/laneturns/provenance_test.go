package laneturns

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/testdata"
)

func turnFixture(t *testing.T) (*laneSession, *testdata.StoreFixture, object) {
	t.Helper()
	f := testdata.OpenStore(t)
	root, err := os.OpenRoot(f.Config.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	info, err := os.Stat(f.Path)
	if err != nil {
		t.Fatal(err)
	}
	c := &configuration{name: f.Config.Name}
	state := &stateDir{path: f.Config.StatePath, root: root, c: c}
	s := &laneSession{state: state, c: c, store: &eventStore{state: state, db: f.DB, fileInfo: info}}
	events, err := f.Store.Events(0)
	if err != nil {
		t.Fatal(err)
	}
	return s, f, obj(events[0]["payload"])
}

func TestTurnAuthority(t *testing.T) {
	s, f, original := turnFixture(t)
	row, empty, err := s.turnState(testdata.Lane, false)
	if err != nil || empty || integer(row["run"]) != 1 {
		t.Fatalf("the genuine recorded-life control failed: %v", err)
	}
	forged := copyObject(original)
	forged["run"], forged["how"] = 2, "resume"
	forged["worktree"], forged["claims"], forged["project"] = t.TempDir(), t.TempDir(), "other"
	forged["session_id"] = "12345678-1234-4234-8234-123456789abc"
	forged["level"], forged["level_source"], forged["starter"] = 6, "org", "supervisor:other"
	start := testdata.Envelope(forged)
	start["id"], start["kind"] = "external-start", "lane.started"
	if _, err := f.Store.AppendExternal(start, "supervisor:top"); err != nil {
		t.Fatal(err)
	}
	end := testdata.Envelope(object{"run": 2, "reason": "exit", "exit_code": 0, "signal": nil,
		"duration_seconds": 0, "pattern": nil, "classification": nil, "survivors": 0})
	end["id"], end["kind"] = "external-end", "lane.ended"
	if _, err := f.Store.AppendExternal(end, "supervisor:top"); err != nil {
		t.Fatal(err)
	}
	previous, err := s.latest(testdata.Lane)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"worktree", "session_id", "claims", "project", "starter", "level", "level_source"} {
		if !equalJSON(previous[key], original[key]) {
			t.Fatalf("the operational reader trusted appended %s", key)
		}
	}
	if line := caller.LineFrom(previous); line.Starter != "" || line.Level != 0 {
		t.Fatal("an appended report line ended the launcher's legacy life")
	}
	recorded, err := s.recordedRow(testdata.Lane)
	if err != nil || integer(recorded["run"]) != 1 || recorded["worktree"] != original["worktree"] {
		t.Fatalf("the operational projection trusted an appended run: %v", err)
	}
	if _, _, err := s.turnState(testdata.Lane, false); err == nil || !strings.Contains(err.Error(), "launcher-recorded run") || !strings.Contains(err.Error(), "Instead:") || !strings.Contains(err.Error(), "lane mark --state abandoned") {
		t.Fatal("a divergent observed run could reach turn execution")
	}
	if _, err := newLaneScan(s, testdata.Lane, 2, 0, nil); err == nil || !strings.Contains(err.Error(), "current run has not started") {
		t.Fatal("the live scanner trusted an appended run's paths")
	}
	closing, err := latestClosing(s, testdata.Lane)
	if err != nil || integer(obj(closing["payload"])["run"]) != 1 {
		t.Fatalf("loop backoff trusted an appended end: %v", err)
	}
	observed, err := s.known(testdata.Lane)
	if err != nil || integer(observed["run"]) != 2 || observed["worktree"] != forged["worktree"] {
		t.Fatalf("display lost the appended observation: %v", err)
	}
	if _, err := f.Store.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestTurnExternalOnly(t *testing.T) {
	s, f, original := turnFixture(t)
	lane := "observed"
	p := copyObject(original)
	for _, key := range []string{"run", "how", "launch"} {
		delete(p, key)
	}
	p["session_id"], p["idle_seconds"] = "12345678-1234-4234-8234-123456789abc", nil
	p["runner"] = "unconfigured"
	p["brief"] = object{"sha256": obj(original["brief"])["sha256"], "path": filepath.Join(f.Config.StatePath, "lanes", lane, "rendered", str(obj(original["brief"])["sha256"])+".md")}
	p["log"] = filepath.Join(f.Config.StatePath, "lanes", lane, "output.log")
	p["session"] = object{"socket": f.Config.Socket(f.Config.StatePath), "name": lane}
	e := testdata.Envelope(p)
	e["id"], e["kind"], e["lane"] = "external-adopt", "lane.adopted", lane
	if _, err := f.Store.AppendExternal(e, "supervisor:top"); err != nil {
		t.Fatal(err)
	}
	if previous, err := s.latest(lane); err != nil || previous != nil {
		t.Fatalf("an appended adoption supplied operational metadata: %v", err)
	}
	if row, empty, err := s.turnState(lane, false); err != nil || !empty || row != nil {
		t.Fatalf("an empty adopted observation did not preserve no-mail behavior: %v", err)
	}
	if _, _, err := s.turnState(lane, true); err == nil || !strings.Contains(err.Error(), "Instead: lane adopt") {
		t.Fatal("idle execution trusted an appended adoption")
	}
	if _, err := mailTarget(s, lane); err == nil || !strings.Contains(err.Error(), "has not run yet, so it takes no mail\nInstead: lane adopt") {
		t.Fatalf("an appended-only life was allowed to receive mail: %v", err)
	}
	mail := testdata.Envelope(object{"sequence": 1, "sender": "human", "sha256": digest([]byte("mail")), "bytes": 4})
	mail["id"], mail["kind"], mail["lane"] = "real-mail", "lane.mailed", lane
	if _, err := f.Store.Append(mail); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.turnState(lane, false); err == nil || !strings.Contains(err.Error(), "Instead: lane adopt") {
		t.Fatal("queued mail authorized an appended-only life")
	}
}

func TestTurnLiveEvidence(t *testing.T) {
	s, f, original := turnFixture(t)
	p := copyObject(original)
	p["run"], p["how"] = 2, "resume"
	start := testdata.Envelope(p)
	start["id"], start["kind"] = "real-open-run", "lane.started"
	if _, err := f.Store.Append(start); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"lane.ended", "lane.gone"} {
		p := object{"run": 2, "launch": original["launch"]}
		if kind == "lane.ended" {
			p = object{"run": 2, "reason": "exit", "exit_code": 0, "signal": nil,
				"duration_seconds": 0, "pattern": nil, "classification": nil, "survivors": 0}
		}
		e := testdata.Envelope(p)
		e["id"], e["kind"] = "external-"+kind, kind
		if _, err := f.Store.AppendExternal(e, "supervisor:top"); err != nil {
			t.Fatal(err)
		}
		if err := refuseLive(s, testdata.Lane); err == nil || !strings.Contains(err.Error(), "no run record") {
			t.Fatal("an appended close supplied proof that launcher processes were gone")
		}
	}
}

func TestTurnCleaned(t *testing.T) {
	s, f, _ := turnFixture(t)
	for _, row := range []struct {
		kind    string
		payload object
	}{
		{"lane.state", object{"state": "merged"}},
		{"lane.cleaned", object{"removed": []any{}, "kept": []any{}}},
	} {
		e := testdata.Envelope(row.payload)
		e["id"], e["kind"] = "real-"+row.kind, row.kind
		if _, err := f.Store.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	row, _, err := s.turnState(testdata.Lane, false)
	if err != nil || !flag(row["cleaned"]) {
		t.Fatalf("the operational projection lost the launcher's cleanup: %v", err)
	}
}
