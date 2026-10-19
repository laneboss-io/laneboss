package settingscli

import (
	"bytes"
	"encoding/json"
	"testing"

	"laneboss.io/laneboss/internal/settings"
	"laneboss.io/laneboss/internal/testdata"
)

func TestSettingsExternal(t *testing.T) {
	f := testdata.OpenStore(t)
	t.Setenv("LANEBOSS_CONFIG", f.Config.Name)
	t.Setenv("LANEBOSS_HOME", f.Config.Home)
	t.Setenv("LANEBOSS_STATE_HOME", f.Config.StateHome)
	events, err := f.Store.Events(0)
	if err != nil {
		t.Fatal(err)
	}
	start := func(run int, model string, external bool) {
		t.Helper()
		p := map[string]any{}
		for key, value := range events[0]["payload"].(map[string]any) {
			p[key] = value
		}
		p["run"], p["how"], p["model"] = run, "resume", model
		snapshot := settings.Empty()
		for _, key := range []string{"runner", "model", "budget_minutes"} {
			snapshot.Add(key, settings.Layer{Scope: "default", Value: p[key], Event: "fixture fallback"})
		}
		p["settings"] = snapshot.Map()
		e := testdata.Envelope(p)
		e["id"], e["kind"] = "real-settings", "lane.started"
		if external {
			e["id"] = "external-settings"
			_, err = f.Store.AppendExternal(e, "supervisor:top")
		} else {
			_, err = f.Store.Append(e)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	query := func(args ...string) any {
		t.Helper()
		var out, diagnostic bytes.Buffer
		args = append(args, "--config", f.Config.Name, "--lane", testdata.Lane)
		if code := Run(args, nil, &out, &diagnostic); code != 0 {
			t.Fatalf("settings query failed (%d): %s", code, diagnostic.String())
		}
		var value any
		if err := json.Unmarshal(out.Bytes(), &value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	start(2, "real-model-2", false)
	if value := query("get", "model"); value != "real-model-2" {
		t.Fatal("the genuine settings control changed its scalar output")
	}
	end := testdata.Envelope(map[string]any{"run": 2, "reason": "exit", "exit_code": 0, "signal": nil,
		"duration_seconds": 0, "pattern": nil, "classification": nil, "survivors": 0})
	end["id"], end["kind"] = "real-end", "lane.ended"
	if _, err := f.Store.Append(end); err != nil {
		t.Fatal(err)
	}
	start(3, "external-model-3", true)
	for _, args := range [][]string{{"get", "model"}, {"get", "model", "--explain"}, {"list"}, {"list", "--explain"}} {
		value, ok := query(args...).(map[string]any)
		if !ok || value["externally_appended"] != true {
			t.Fatal("settings displayed an appended snapshot without its origin")
		}
		model := value["value"]
		if args[0] == "list" {
			model = value["model"]
			if explanation, ok := model.(map[string]any); ok {
				model = explanation["value"]
			}
		}
		if model != "external-model-3" {
			t.Fatal("settings lost the observation's actual value")
		}
	}
}
