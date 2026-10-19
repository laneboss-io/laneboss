package ledger

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"laneboss.io/laneboss/internal/testdata"
)

func TestSelectionExternal(t *testing.T) {
	f := testdata.OpenStore(t)
	t.Setenv("LANEBOSS_CONFIG", f.Config.Name)
	t.Setenv("LANEBOSS_HOME", f.Config.Home)
	t.Setenv("LANEBOSS_STATE_HOME", f.Config.StateHome)
	path := filepath.Join(f.Config.Directory, "config.toml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, []byte("projects = ['scope']\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	projects := filepath.Join(f.Config.Directory, "projects")
	if err := os.MkdirAll(projects, 0700); err != nil {
		t.Fatal(err)
	}
	project := fmt.Sprintf("schema_version = 1\nname = 'scope'\nrepository = %q\nworkers = ['fixture']\nlanding_authority = 'top'\n", t.TempDir())
	if err := os.WriteFile(filepath.Join(projects, "scope.toml"), []byte(project), 0600); err != nil {
		t.Fatal(err)
	}
	events, err := f.Store.Events(0)
	if err != nil {
		t.Fatal(err)
	}
	addRun := func(run int, external bool) {
		t.Helper()
		p := object{}
		for key, value := range obj(events[0]["payload"]) {
			p[key] = value
		}
		p["run"], p["how"], p["project"] = run, "resume", "scope"
		start := testdata.Envelope(p)
		start["id"], start["kind"] = fmt.Sprintf("start-%d", run), "lane.started"
		p = object{}
		for key, value := range obj(events[2]["payload"]) {
			p[key] = value
		}
		p["run"] = run
		end := testdata.Envelope(p)
		end["id"], end["kind"] = fmt.Sprintf("end-%d", run), "lane.ended"
		for _, e := range []object{start, end} {
			if external {
				_, err = f.Store.AppendExternal(e, "supervisor:top")
			} else {
				_, err = f.Store.Append(e)
			}
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	addRun(2, true)
	view, err := Read(f.Config.Name, Selection{Instance: "top"})
	if err != nil {
		t.Fatal(err)
	}
	if len(list(view["tasks"])) != 0 || len(list(view["rows"])) != 0 {
		t.Fatal("an appended project pulled an unrelated real task into the instance ledger")
	}
	addRun(3, false)
	view, err = Read(f.Config.Name, Selection{Instance: "top"})
	if err != nil {
		t.Fatal(err)
	}
	if len(list(view["tasks"])) != 2 {
		t.Fatal("the genuine project association control lost its launcher tasks")
	}
	marked := 0
	for _, value := range list(view["rows"]) {
		if obj(value)["externally_appended"] == true {
			marked++
		}
	}
	if marked != 2 {
		t.Fatal("an independently selected ledger lost its marked observations")
	}
}
