package caller

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/eventstore"
)

func isolatedConfig(t *testing.T) *config.Configuration {
	t.Helper()
	for _, key := range []string{"LANEBOSS_LANE", "LANEBOSS_ROLE", "LANEBOSS_INSTANCE", "LANEBOSS_CONFIG"} {
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}
	base := t.TempDir()
	base, err := filepath.EvalSymlinks(base)
	if err != nil {
		t.Fatal(err)
	}
	return Configuration("identity", filepath.Join(base, "config"), filepath.Join(base, "state"), filepath.Join(base, "config", "configs", "identity"), filepath.Join(base, "state", "identity"), map[string]any{"supervisors": map[string]any{"super-top": map[string]any{"level": int64(6)}, "mini-a": map[string]any{"level": int64(4)}}})
}

func ticketForTest(t *testing.T, c *config.Configuration, name string) {
	t.Helper()
	table, err := processTable()
	if err != nil {
		t.Fatal(err)
	}
	mine, ok := table[os.Getpid()]
	if !ok {
		t.Fatal("the real test process was not observed")
	}
	p, _, err := Role(c, name)
	if err != nil {
		t.Fatal(err)
	}
	if err = writePrivate(c, "roles/"+name+".json", roleTicket{c.Name, p.ID, mine}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LANEBOSS_ROLE", name)
}

func TestInstanceRoleUsesExplicitOrg(t *testing.T) {
	c := isolatedConfig(t)
	named := filepath.Join(c.Home, "orgs", "named-org")
	explicit := filepath.Join(t.TempDir(), "selected-org")
	for root, level := range map[string]string{named: "6", explicit: "4"} {
		directory := filepath.Join(root, ".laneboss", "instances", "reviewer")
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, ".laneboss", "org.toml"), []byte("schema_version = 1\n"), 0600); err != nil {
			t.Fatal(err)
		}
		body := "name = \"reviewer\"\nlevel = " + level + "\n"
		if err := os.WriteFile(filepath.Join(directory, "instance.toml"), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	c.Data["organisation"] = "named-org"
	c.Data["org_dir"] = explicit
	principal, source, err := Role(c, "reviewer")
	if err != nil || principal.ID != "instance:reviewer" || principal.Level != 4 || source != "instance" {
		t.Fatal("ExplicitOrg: instance identity did not use the configured org_dir")
	}
	delete(c.Data, "org_dir")
	principal, _, err = Role(c, "reviewer")
	if err != nil || principal.Level != 6 {
		t.Fatal("the named-org control no longer resolves its own instance")
	}
	c.Data["org_dir"] = "relative-org"
	if _, _, err := Role(c, "reviewer"); err == nil {
		t.Fatal("an invalid explicit org silently fell back to the named org")
	}
}

func TestLaunchUsesOwnLevel(t *testing.T) {
	c := isolatedConfig(t)
	ticketForTest(t, c, "super-top")
	p, line, err := Launch(c, "")
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "supervisor:super-top" || p.Level != 6 {
		t.Fatalf("ticket did not resolve its recorded role: %+v", p)
	}
	if line.Level != 3 {
		t.Fatalf("protocol lane level = %d, want 3, independent of its L6 starter", line.Level)
	}
	if line.LevelSource != "protocol" || line.Starter != p.ID {
		t.Fatalf("report line did not retain its source and starter: %+v", line)
	}
	_, line, err = Launch(c, "mini-a")
	if err != nil || line.Level != 4 || line.LevelSource != "supervisors" {
		t.Fatalf("selected role level: %+v, %v", line, err)
	}
	if _, _, err = Launch(c, "super-top"); err == nil {
		t.Fatal("a lane at the starter's level was allowed")
	}
	if _, _, err = Launch(c, "missing"); err == nil {
		t.Fatal("an unreadable role was guessed")
	}
}

func TestTicketMustMatchProcessAndSession(t *testing.T) {
	c := isolatedConfig(t)
	ticketForTest(t, c, "mini-a")
	root, err := os.OpenRoot(c.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	var ticket roleTicket
	if err = readJSON(root, "roles/mini-a.json", &ticket); err != nil {
		t.Fatal(err)
	}
	ticket.Process.Start += "9"
	if err = writePrivate(c, "roles/mini-a.json", ticket); err != nil {
		t.Fatal(err)
	}
	p, err := Resolve(c)
	if err != nil {
		t.Fatal(err)
	}
	if p.ID == "supervisor:mini-a" {
		t.Fatal("a ticket with another process start time authenticated the role")
	}
	table := map[int]process{10: {PID: 10, Parent: 1, SID: 10, Start: "100", State: "S"}, 20: {PID: 20, Parent: 10, SID: 10, Start: "200", State: "S"}, 30: {PID: 30, Parent: 20, SID: 30, Start: "300", State: "S"}}
	if !ancestor(table[10], table[30], table) {
		t.Fatal("the fixture did not preserve ancestry across detachment")
	}
	if ticketMatches(roleTicket{Process: table[10]}, table[30], table) {
		t.Fatal("a detached descendant reused a role ticket")
	}
	if !ticketMatches(roleTicket{Process: table[10]}, table[20], table) {
		t.Fatal("the control descendant lost its role ticket")
	}
}

func TestRecordedLaneOverridesLabelsAndUnset(t *testing.T) {
	c := isolatedConfig(t)
	ec := &eventstore.Configuration{Name: c.Name, Home: c.Home, StateHome: c.StateHome, Directory: c.ConfigDir, StatePath: c.StateDir}
	dir, err := ec.OpenDirectory(true)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	store, err := eventstore.Open(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	lane := "worker-a"
	launch := strings.Repeat("a", 32)
	hash := strings.Repeat("b", 64)
	payload := map[string]any{"run": 1, "how": "start", "launch": launch, "runner": "local", "model": "local-model-1", "effort": nil, "account": nil, "chosen_by": map[string]any{"runner": "supervisor", "model": "supervisor", "effort": nil, "account": nil}, "difficulty": nil, "project": nil, "worktree": t.TempDir(), "branch": nil, "base": nil, "repository": nil, "budget_minutes": 10, "quiet_seconds": 900, "brief": map[string]any{"path": filepath.Join(c.StateDir, "lanes", lane, "rendered", hash+".md"), "sha256": hash}, "log": filepath.Join(c.StateDir, "lanes", lane, "output.log"), "session": map[string]any{"socket": ec.Socket(c.StateDir), "name": lane}, "touches": []any{}, "claims": nil, "level": 5, "level_source": "supervisors", "starter": "human"}
	if _, err = store.Append(map[string]any{"kind": "lane.started", "lane": lane, "actor": "human", "protocol_version": "1.3.0", "payload": payload}); err != nil {
		store.Close()
		t.Fatal(err)
	}
	store.Close()
	table, err := processTable()
	if err != nil {
		t.Fatal(err)
	}
	mine := table[os.Getpid()]
	record := map[string]any{"config": c.Name, "lane": lane, "launch": launch, "run": 1, "supervisor": mine, "runner": mine, "processes": []process{mine}}
	if err = writePrivate(c, "lanes/"+lane+"/runs/"+launch+".json", record); err != nil {
		t.Fatal(err)
	}
	ticketForTest(t, c, "super-top")
	for _, label := range []string{"", lane} {
		if label == "" {
			if err = os.Unsetenv("LANEBOSS_LANE"); err != nil {
				t.Fatal(err)
			}
		} else {
			t.Setenv("LANEBOSS_LANE", label)
		}
		p, resolved, err := ResolveWithLane(c)
		if err != nil || p.ID != "lane:"+lane || p.Level != 5 || p.Starter != "human" {
			t.Fatalf("recorded lane did not win: %+v, %v", p, err)
		}
		if resolved == nil || !resolved.Open || resolved.Principal != p || resolved.Payload["worktree"] != payload["worktree"] || resolved.Payload["launch"] != launch {
			t.Fatal("caller resolution lost the authenticated lane's start record")
		}
	}
	t.Setenv("LANEBOSS_LANE", "worker-b")
	if _, err = Resolve(c); err == nil {
		t.Fatal("a lane spoofed another lane through its environment")
	}
}

func TestLifecycleActors(t *testing.T) {
	for _, id := range []string{"human", "supervisor:mini-a", "instance:top", "lane:worker-a"} {
		if got := LifecycleActor(id); got != id {
			t.Fatalf("lifecycle actor = %q, want the actual principal %q", got, id)
		}
	}
	if LifecycleActor("") != "laneboss" {
		t.Fatal("an unrecorded detected step was not attributed to the launcher")
	}
	c := isolatedConfig(t)
	launch := strings.Repeat("c", 32)
	if err := RecordStop(c, "worker-a", launch, Principal{ID: "supervisor:mini-a"}); err != nil {
		t.Fatal(err)
	}
	actor, err := StopActor(c, "worker-a", launch)
	if err != nil || actor != "supervisor:mini-a" {
		t.Fatalf("the worker lost the persisted stop caller: %q, %v", actor, err)
	}
	if err := writePrivate(c, "lanes/worker-a/stop-"+launch+".json", stopRequest{c.Name, "worker-b", launch, "human"}); err != nil {
		t.Fatal(err)
	}
	if _, err = StopActor(c, "worker-a", launch); err == nil {
		t.Fatal("a stop request for another lane was accepted")
	}
}

func TestProcParserUsesRealFields(t *testing.T) {
	// A command name can contain a closing parenthesis; the fields follow the last one.
	data := []byte("42 (worker (test)) S 7 42 42 " + strings.Repeat("0 ", 15) + "98765 0")
	p, err := parseProc(42, data)
	if err != nil || p.Parent != 7 || p.PGID != 42 || p.SID != 42 || p.Start != "98765" {
		t.Fatalf("process stat fields were misread: %+v, %v", p, err)
	}
	if _, err = parseProc(42, []byte("42 (broken) S 7")); err == nil {
		t.Fatal("an incomplete process identity was accepted")
	}
	var stored process
	if err = json.Unmarshal([]byte(`{"pid":42,"start":"98765","pgid":42,"sid":null}`), &stored); err != nil || stored.SID != 0 {
		t.Fatal("portable run records with a null session id were not readable")
	}
}
