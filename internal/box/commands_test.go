package box

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/boxcfg"
	"laneboss.io/laneboss/internal/boxcore"
)

func TestEndProvider(t *testing.T) {
	cases := []struct {
		name, events, want string
	}{
		{"gcp", `{"event":"LAUNCHED","instance_id":"i-demo1","provider":"gcp"}`, "gcp"},
		{"aws", `{"event":"LAUNCHED","instance_id":"i-demo1","provider":"aws"}`, "aws"},
		{"legacy", `{"event":"LAUNCHED","instance_id":"i-demo1"}`, "aws"},
		{"fallback", `{"event":"LAUNCHED","instance_id":"i-other","provider":"aws"}`, "gcp"},
		{"last-launch", `{"event":"LAUNCHED","instance_id":"i-demo1","provider":"aws"}` + "\n" +
			`{"event":"LAUNCHED","instance_id":"i-demo1","provider":"gcp"}` + "\n" +
			`{"event":"ENDED","instance_id":"i-demo1","provider":"aws"}`, "gcp"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newFixture(t)
			h.cfg.Defaults.Provider = "gcp"
			h.ledger.path = writeTemp(t, t.TempDir(), "ledger.jsonl", tc.events+"\n")
			h.svc.end = boxcore.EndResult{Basis: "provider"}
			code := h.call("end", "--instance", "i-demo1", "--address", "demo-host", "--bound-sec", "45")
			want := boxcore.EndOptions{Provider: tc.want, ID: "i-demo1", Address: "demo-host", BoundSec: 45, PollSec: 15}
			if code != 0 || len(h.svc.ends) != 1 || h.svc.ends[0] != want ||
				h.out.String() != "terminated i-demo1 (provider)\n" || h.notes.Len() != 0 {
				t.Fatalf("end: code=%d options=%+v stdout=%q stderr=%q", code, h.svc.ends, h.out.String(), h.notes.String())
			}
		})
	}
}

func TestEndLedgerErrors(t *testing.T) {
	for _, failure := range []string{"open", "read", "malformed", "provider"} {
		t.Run(failure, func(t *testing.T) {
			h := newFixture(t)
			switch failure {
			case "open":
				h.openErr = errors.New("SECRET-NEEDLE")
			case "read":
				h.ledger.eventsErr = errors.New("SECRET-NEEDLE")
			case "malformed":
				h.ledger.path = writeTemp(t, t.TempDir(), "ledger.jsonl", "SECRET-NEEDLE\n")
			case "provider":
				h.ledger.events = []map[string]any{{"event": "LAUNCHED", "instance_id": "i-demo1", "provider": "SECRET-NEEDLE"}}
			}
			code := h.call("end", "--instance", "i-demo1")
			if code != 2 || h.built != 0 || h.out.Len() != 0 ||
				!strings.HasPrefix(h.notes.String(), usage) || strings.Contains(h.notes.String(), "SECRET-NEEDLE") {
				t.Fatalf("ledger failure: code=%d stderr=%q", code, h.notes.String())
			}
		})
	}
}

func TestEndPending(t *testing.T) {
	h := newFixture(t)
	h.svc.end = boxcore.EndResult{State: "stopping", Pending: true, ExitCode: 3}
	code := h.call("end", "--provider", "aws", "--instance", "i-demo1", "--bound-sec", "30")
	want := "i-demo1 is still stopping after 30s; END_PENDING recorded\n"
	if code != 3 || h.out.Len() != 0 || h.notes.String() != want || len(h.svc.ends) != 1 {
		t.Fatalf("pending: code=%d stdout=%q stderr=%q", code, h.out.String(), h.notes.String())
	}
}

func TestBoxJSONShapes(t *testing.T) {
	assertFields := func(t *testing.T, got, want map[string]any) {
		t.Helper()
		for name, wantValue := range want {
			gotValue, ok := got[name]
			if !ok || !reflect.DeepEqual(gotValue, wantValue) {
				t.Errorf("JSON field %q = %v (present %t), want %v", name, gotValue, ok, wantValue)
			}
		}
	}
	decode := func(t *testing.T, output string, value any) {
		t.Helper()
		if err := json.Unmarshal([]byte(output), value); err != nil {
			t.Fatalf("decode JSON: %v", err)
		}
	}

	tests := []struct {
		name   string
		setup  func(*testing.T) *fixture
		args   []string
		verify func(*testing.T, *fixture)
	}{
		{
			name: "end",
			setup: func(t *testing.T) *fixture {
				h := newFixture(t)
				h.svc.end = boxcore.EndResult{
					State: "gone", Basis: "not-found", TerminatedUTC: "1970-01-01T00:01:40Z", BilledSeconds: 45,
				}
				return h
			},
			args: []string{"end", "--provider", "gcp", "--instance", "lb-spot-box", "--format", "json"},
			verify: func(t *testing.T, h *fixture) {
				var got map[string]any
				decode(t, h.out.String(), &got)
				assertFields(t, got, map[string]any{
					"instance_id": "lb-spot-box", "state": "gone", "basis": "not-found",
					"terminated_utc": "1970-01-01T00:01:40Z", "billed_seconds": float64(45),
					"pending": false, "exit_code": float64(0),
				})
			},
		},
		{
			name:  "list",
			setup: listFixture,
			args:  []string{"list", "--format", "json"},
			verify: func(t *testing.T, h *fixture) {
				var got []map[string]any
				decode(t, h.out.String(), &got)
				want := []map[string]any{
					{"id": "i-open", "state": "running", "age_min": float64(30), "ledger": "open", "orphan": false, "type": "demo.large", "zone": "demo-a"},
					{"id": "i-ended", "state": "gone", "age_min": float64(40), "ledger": "ended", "orphan": false, "type": "demo.large", "zone": "demo-b"},
					{"id": "i-orphan", "state": "running", "age_min": float64(50), "ledger": "none", "orphan": true, "type": "demo.small", "zone": "demo-a"},
				}
				if len(got) != len(want) {
					t.Fatalf("list JSON has %d rows, want %d", len(got), len(want))
				}
				for _, wantRow := range want {
					id := wantRow["id"]
					found := false
					for _, gotRow := range got {
						if gotRow["id"] == id {
							assertFields(t, gotRow, wantRow)
							found = true
							break
						}
					}
					if !found {
						t.Errorf("list JSON has no row for id %v", id)
					}
				}

				h.svc.listed = nil
				if code := h.call("list", "--format", "json"); code != 0 || h.out.String() != "[]\n" {
					t.Fatalf("empty list JSON: code=%d stdout=%q stderr=%q", code, h.out.String(), h.notes.String())
				}
			},
		},
		{
			name: "sweep",
			setup: func(t *testing.T) *fixture {
				h := newFixture(t)
				h.svc.sweep = boxcore.SweepResult{
					Examined: 2, Deleted: []string{"i-demo1"}, Refused: []string{"i-demo2 label-gate"},
				}
				return h
			},
			args: []string{"sweep", "--provider", "aws", "--older-than-min", "0", "--format", "json"},
			verify: func(t *testing.T, h *fixture) {
				var got map[string]any
				decode(t, h.out.String(), &got)
				assertFields(t, got, map[string]any{
					"examined": float64(2), "orphans": []any{},
					"deleted": []any{"i-demo1"}, "refused": []any{"i-demo2 label-gate"},
				})
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := tc.setup(t)
			if code := h.call(tc.args...); code != 0 {
				t.Fatalf("command failed: code=%d stderr=%q", code, h.notes.String())
			}
			tc.verify(t, h)
		})
	}
}

func listFixture(t *testing.T) *fixture {
	t.Helper()
	h := newFixture(t)
	h.ledger.events = []map[string]any{{"event": "LAUNCHED", "instance_id": "i-open", "provider": "aws"}}
	h.svc.listed = []boxcore.Listed{
		{Box: boxcore.Box{ID: "i-open", Type: "demo.large", Zone: "demo-a"}, State: boxcore.State{Name: "running"}, AgeMin: 30},
		{Box: boxcore.Box{ID: "i-ended", Type: "demo.large", Zone: "demo-b"}, State: boxcore.State{Name: "gone"}, AgeMin: 40, LedgerEnded: true},
		{Box: boxcore.Box{ID: "i-orphan", Type: "demo.small", Zone: "demo-a"}, State: boxcore.State{Name: "running"}, AgeMin: 50, Orphan: true},
	}
	return h
}

func TestListLines(t *testing.T) {
	h := listFixture(t)
	code := h.call("list", "--provider", "gcp", "--orphans", "--older-than-min", "20")
	want := "i-open\trunning\t30\topen\tno\tdemo.large\tdemo-a\n" +
		"i-ended\tgone\t40\tended\tno\tdemo.large\tdemo-b\n" +
		"i-orphan\trunning\t50\tnone\tyes\tdemo.small\tdemo-a\n"
	wantOptions := []boxcore.ListOptions{{Provider: "gcp", Orphans: true, OlderThanMin: 20}}
	if code != 0 || h.out.String() != want || h.notes.Len() != 0 || !reflect.DeepEqual(h.svc.lists, wantOptions) {
		t.Fatalf("list: code=%d options=%+v stdout=%q stderr=%q", code, h.svc.lists, h.out.String(), h.notes.String())
	}
}

func TestSweepLines(t *testing.T) {
	for _, delete := range []bool{false, true} {
		h := newFixture(t)
		h.svc.sweep = boxcore.SweepResult{
			Examined: 4, Orphans: make([]boxcore.Listed, 2), Deleted: []string{"i-demo1"}, Refused: []string{"i-demo2 label-gate"},
		}
		args := []string{"sweep", "--provider", "gcp", "--older-than-min", "35"}
		if delete {
			args = append(args, "--delete")
		}
		code := h.call(args...)
		want := "examined=4 orphans=2 deleted=1 refused=1\ndeleted i-demo1\nrefused i-demo2 label-gate\n"
		wantOptions := []boxcore.SweepOptions{{Provider: "gcp", OlderThanMin: 35, Delete: delete}}
		if code != 0 || h.out.String() != want || !reflect.DeepEqual(h.svc.sweeps, wantOptions) {
			t.Fatalf("sweep: code=%d options=%+v stdout=%q", code, h.svc.sweeps, h.out.String())
		}
	}
}

func TestListSweepErrors(t *testing.T) {
	for _, command := range []string{"list", "sweep"} {
		h := newFixture(t)
		h.svc.err = errors.New("SECRET-NEEDLE")
		args := []string{command, "--provider", "aws"}
		if command == "sweep" {
			args = append(args, "--older-than-min", "20")
		}
		code := h.call(args...)
		if code != 2 || h.out.Len() != 0 || h.notes.Len() == 0 || strings.Contains(h.notes.String(), "SECRET-NEEDLE") || h.built != 1 {
			t.Fatalf("%s error: code=%d stdout=%q stderr=%q", command, code, h.out.String(), h.notes.String())
		}
	}
}

func TestCheckMissingPrograms(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	h := newFixture(t)
	code := h.call("check")
	want := "ok: config\nok: aws provider\nok: gcp provider\nok: ledger writable\n" +
		"FAIL: git\nFAIL: aws\nFAIL: ssh\nFAIL: curl\nFAIL: gcloud\n"
	if code != 2 || h.out.String() != want || h.notes.Len() != 0 || h.built != 0 || h.ledger.writeCalls != 1 || h.loaded != h.file {
		t.Fatalf("check: code=%d stdout=%q stderr=%q", code, h.out.String(), h.notes.String())
	}
}

func TestCheckLedgerFailure(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	for _, openFailure := range []bool{false, true} {
		h := newFixture(t)
		if openFailure {
			h.openErr = errors.New("SECRET-NEEDLE")
		} else {
			h.ledger.writeErr = errors.New("SECRET-NEEDLE")
		}
		code := h.call("check")
		if code != 2 || !strings.Contains(h.out.String(), "FAIL: ledger writable\n") ||
			strings.Contains(h.out.String()+h.notes.String(), "SECRET-NEEDLE") || h.built != 0 {
			t.Fatalf("ledger check: code=%d stdout=%q stderr=%q", code, h.out.String(), h.notes.String())
		}
	}
}

func TestConfigFailure(t *testing.T) {
	h := newFixture(t)
	h.env.load = func(string, boxcfg.Env) (*boxcore.Config, error) {
		return nil, errors.New("the config cannot be read")
	}
	code := h.call("check")
	if code != 2 || h.out.String() != "FAIL: config\n" ||
		h.notes.String() != "laneboss box: the config cannot be read\n" || h.built != 0 {
		t.Fatalf("config check: code=%d stdout=%q stderr=%q", code, h.out.String(), h.notes.String())
	}
}

func TestCommandUsage(t *testing.T) {
	cases := [][]string{
		{"end", "--provider", "aws"},
		{"end", "--provider", "aws", "--instance", "SECRET-NEEDLE", "--bound-sec", "0"},
		{"list", "--older-than-min", "-1"},
		{"sweep", "--provider", "aws"},
		{"sweep", "--provider", "aws", "--older-than-min", "-1"},
		{"check", "--format", "SECRET-NEEDLE"},
		{"list", "SECRET-NEEDLE"},
	}
	for i, args := range cases {
		h := newFixture(t)
		code := h.call(args...)
		if code != 2 || h.built != 0 || h.out.Len() != 0 ||
			!strings.HasPrefix(h.notes.String(), usage) || strings.Contains(h.notes.String(), "SECRET-NEEDLE") {
			t.Fatalf("case %d: code=%d stderr=%q", i, code, h.notes.String())
		}
	}
}
