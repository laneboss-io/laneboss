package laneturns

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/testdata"
)

func mailFixture(t *testing.T) (*laneSession, *testdata.StoreFixture, object) {
	t.Helper()
	s, f, original := turnFixture(t)
	t.Setenv("LANEBOSS_HOME", f.Config.Home)
	t.Setenv("LANEBOSS_STATE_HOME", f.Config.StateHome)
	t.Setenv("LANEBOSS_CONFIG", f.Config.Name)
	data := []byte("schema_version = 1\nname = \"fixture\"\n" +
		"[runners.fixture]\ncommand = [\"sh\", \"{session}\"]\nresume = [\"sh\", \"{session}\"]\nprompt = \"stdin\"\n" +
		"[runners.oneshot]\ncommand = [\"sh\", \"{session}\"]\nprompt = \"stdin\"\n" +
		"[supervisors.top]\nlevel = 5\nrunner = \"fixture\"\n")
	if err := os.WriteFile(filepath.Join(f.Config.Directory, "config.toml"), data, 0600); err != nil {
		t.Fatal(err)
	}
	c, err := loadConfig(f.Config.Name)
	if err != nil {
		t.Fatal(err)
	}
	s.c, s.state.c = c, c
	return s, f, original
}

func appendMailLife(t *testing.T, f *testdata.StoreFixture, original object, lane, runner, kind string, external bool) {
	t.Helper()
	p := copyObject(original)
	p["runner"], p["session_id"], p["idle_seconds"] = runner, "12345678-1234-4234-8234-123456789abc", nil
	p["mail"] = []any{}
	if kind == "lane.adopted" {
		for _, key := range []string{"run", "how", "launch", "mail"} {
			delete(p, key)
		}
	}
	dir := filepath.Join(f.Config.StatePath, "lanes", lane)
	p["brief"] = object{"sha256": obj(original["brief"])["sha256"], "path": filepath.Join(dir, "rendered", str(obj(original["brief"])["sha256"])+".md")}
	p["log"] = filepath.Join(dir, "output.log")
	p["session"] = object{"socket": f.Config.Socket(f.Config.StatePath), "name": lane}
	e := testdata.Envelope(p)
	e["id"], e["kind"], e["lane"] = "mail-life", kind, lane
	var err error
	if external {
		_, err = f.Store.AppendExternal(e, "supervisor:top")
	} else {
		_, err = f.Store.Append(e)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func assertNoQueuedMail(t *testing.T, s *laneSession, lane string) {
	t.Helper()
	events, err := s.store.events(lane, "lane.mailed")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Error("a refused send recorded a mail event")
	}
	row, err := s.known(lane)
	if err != nil {
		t.Fatal(err)
	}
	if mail := obj(row["mail"]); queued(mail) != 0 || integer(mail["last"]) != 0 {
		t.Error("a refused send changed the mail queue")
	}
	entries, err := os.ReadDir(s.state.lanePath(lane, "mail"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Error("a refused send wrote a mail file")
	}
}

func TestSendExternalLifeWithoutResume(t *testing.T) {
	// Kills the one-line mutant: if runnerErr == nil -> if previous != nil && runnerErr == nil.
	for _, kind := range []string{"lane.adopted", "lane.started"} {
		t.Run(kind, func(t *testing.T) {
			s, f, original := mailFixture(t)
			lane, runner := "observed-mail", "oneshot"
			appendMailLife(t, f, original, lane, runner, kind, true)
			if previous, err := s.latest(lane); err != nil || previous != nil {
				t.Fatalf("the external fixture supplied a launcher-made run: %v", err)
			}
			result, err := sendMessage(s.c, lane, caller.Principal{ID: "human"}, []byte("Review this lane.\n"))
			want := fmt.Sprintf("refused: lane %s cannot take mail: runner %s cannot take turns, because it has no resume template (runners.%s.resume)\n", lane, runner, runner)
			var stderr bytes.Buffer
			if code := reportError(&stderr, err); code != 2 || stderr.String() != want || result != nil {
				t.Errorf("send = %v, exit %d, stderr %q; want exit 2 and %q", result, code, stderr.String(), want)
			}
			assertNoQueuedMail(t, s, lane)
		})
	}
}

func TestSendExternalLifeWithTurns(t *testing.T) {
	// Kills the one-line mutant: if previous == nil -> if previous == nil && runnerErr != nil.
	for _, kind := range []string{"lane.adopted", "lane.started"} {
		t.Run(kind, func(t *testing.T) {
			s, f, original := mailFixture(t)
			lane := "observed-mail"
			appendMailLife(t, f, original, lane, "fixture", kind, true)
			if previous, err := s.latest(lane); err != nil || previous != nil {
				t.Fatalf("the external fixture supplied a launcher-made run: %v", err)
			}
			result, err := sendMessage(s.c, lane, caller.Principal{ID: "human"}, []byte("Continue this lane.\n"))
			want := fmt.Sprintf("refused: lane %s has not run yet, so it takes no mail\nInstead: lane adopt the running session, or lane start --turns\n", lane)
			var stderr bytes.Buffer
			if code := reportError(&stderr, err); code != 2 || stderr.String() != want || result != nil {
				t.Errorf("send = %v, exit %d, stderr %q; want exit 2 and %q", result, code, stderr.String(), want)
			}
			assertNoQueuedMail(t, s, lane)
		})
	}
}

func TestSendLauncherTurnLane(t *testing.T) {
	// Kills the one-line mutant: if previous == nil -> if previous != nil.
	s, f, original := mailFixture(t)
	lane := "recorded-mail"
	appendMailLife(t, f, original, lane, "fixture", "lane.started", false)
	data := []byte("A launcher-made lane still takes mail.\n")
	result, err := sendMessage(s.c, lane, caller.Principal{ID: "human"}, data)
	if err != nil {
		t.Fatal(err)
	}
	if result["lane"] != lane || integer(result["sequence"]) != 1 || integer(result["waiting"]) != 1 {
		t.Fatalf("the launcher-made lane did not queue its message: %v", result)
	}
	kept, err := os.ReadFile(str(result["file"]))
	if err != nil || !bytes.Equal(kept, data) {
		t.Fatalf("the queued file lost the message bytes: %v", err)
	}
	events, err := s.store.events(lane, "lane.mailed")
	if err != nil || len(events) != 1 {
		t.Fatalf("the launcher-made lane did not retain one mail event: %v", err)
	}
	p := obj(events[0]["payload"])
	if p["sha256"] != digest(data) || integer(p["bytes"]) != len(data) || p["sender"] != "human" {
		t.Fatal("the mail event does not describe the actual message")
	}
}
