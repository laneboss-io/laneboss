package lane

import (
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/testdata"
)

func TestLifecycleAuthorityIgnoresProjection(t *testing.T) {
	fixture := testdata.OpenStore(t)
	events, err := fixture.Store.Events(0)
	if err != nil {
		t.Fatal(err)
	}
	original := events[0]["payload"].(map[string]any)
	merged := testdata.Envelope(map[string]any{"state": "merged"})
	merged["id"], merged["kind"] = "launcher-merged", "lane.state"
	if _, err := fixture.Store.Append(merged); err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{}
	for key, value := range original {
		payload[key] = value
	}
	payload["run"], payload["how"] = 2, "reuse"
	payload["worktree"], payload["branch"], payload["repository"] = t.TempDir(), "spare", filepath.Join(t.TempDir(), "repo")
	started := testdata.Envelope(payload)
	started["id"], started["kind"] = "external-run", "lane.started"
	if _, err := fixture.Store.AppendExternal(started, "supervisor:top"); err != nil {
		t.Fatal(err)
	}
	ended := testdata.Envelope(map[string]any{"run": 2, "reason": "exit", "exit_code": 0, "signal": nil,
		"duration_seconds": 0, "pattern": nil, "classification": nil, "survivors": 0})
	ended["id"], ended["kind"] = "external-end", "lane.ended"
	if _, err := fixture.Store.AppendExternal(ended, "supervisor:top"); err != nil {
		t.Fatal(err)
	}
	abandoned := testdata.Envelope(map[string]any{"state": "abandoned"})
	abandoned["id"], abandoned["kind"] = "external-state", "lane.state"
	if _, err := fixture.Store.AppendExternal(abandoned, "supervisor:top"); err != nil {
		t.Fatal(err)
	}
	s := &session{db: fixture.DB, authority: true}
	row, err := s.known(testdata.Lane)
	if err != nil || integer(row["run"]) != 1 || row["state"] != "merged" || row["worktree"] != original["worktree"] {
		t.Fatalf("an authority path selected the external run or state: %v", err)
	}
	previous, _, err := s.latest(testdata.Lane)
	if err != nil || integer(previous["run"]) != 1 || previous["branch"] != original["branch"] || previous["worktree"] != original["worktree"] {
		t.Fatalf("the latest-life reader selected an external removal/resume target: %v", err)
	}
	if err := s.checkLaunchProjection(testdata.Lane, row); err == nil || !strings.Contains(err.Error(), "Instead:") ||
		!strings.Contains(err.Error(), "lane mark --state abandoned") || !strings.Contains(err.Error(), "new name") {
		t.Fatalf("a divergent launch lacks a refusal and recovery route: %v", err)
	}
	starts, err := s.laneEvents(testdata.Lane, "lane.started")
	if err != nil || len(starts) != 1 || starts[0]["id"] != events[0]["id"] {
		t.Fatalf("an archive/run-record reader received external lifecycle metadata: %v", err)
	}
	s.authority = false
	displayed, err := s.known(testdata.Lane)
	if err != nil || integer(displayed["run"]) != 2 || displayed["state"] != "abandoned" || displayed["worktree"] != payload["worktree"] {
		t.Fatalf("the display projection lost its external observation: %v", err)
	}
	if _, err := fixture.Store.Verify(); err != nil {
		t.Fatal(err)
	}
}
