package report

import (
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/testdata"
)

func TestHumanExternalProjectionTarget(t *testing.T) {
	fixture := testdata.OpenStore(t)
	t.Setenv("LANEBOSS_HOME", fixture.Config.Home)
	t.Setenv("LANEBOSS_STATE_HOME", fixture.Config.StateHome)
	t.Setenv("LANEBOSS_CONFIG", fixture.Config.Name)
	value := testdata.Envelope(map[string]any{"state": "abandoned"})
	value["lane"], value["kind"], value["id"], value["actor"] = "observed", "lane.state", "external-target", "laneboss"
	if _, err := fixture.Store.AppendExternal(value, "supervisor:top"); err != nil {
		t.Fatal(err)
	}
	legacy, err := CheckMessage(fixture.Config.Name, caller.Principal{ID: "human"}, "observed")
	if err != nil || !legacy {
		t.Fatalf("the human must reach an external target with an honest legacy marker: %v", err)
	}
	legacy, err = CheckMessage(fixture.Config.Name, caller.Principal{ID: "supervisor:top", Level: 3}, "observed")
	if err != nil || !legacy {
		t.Fatalf("the target must use the supervisor's configuration-resolved level: %v", err)
	}
	legacy, err = CheckMessage(fixture.Config.Name, caller.Principal{ID: "lane:" + testdata.Lane, Level: 6}, "observed")
	if err == nil || legacy {
		t.Fatal("an external target trusted a supplied lane level instead of its recorded L3")
	}
	legacy, err = CheckMessage(fixture.Config.Name, caller.Principal{ID: "human"}, "absent")
	if err == nil || err.Error() != "lane absent is not known" || legacy {
		t.Fatal("the projection target exception created a missing target")
	}
	config := caller.Configuration(fixture.Config.Name, fixture.Config.Home, fixture.Config.StateHome, fixture.Config.Directory, fixture.Config.StatePath, nil)
	if _, err := caller.Lane(config, "observed"); err == nil {
		t.Fatal("the projection target exception enrolled a caller identity")
	}
	if _, err := caller.Lane(config, testdata.Lane); err != nil {
		t.Fatalf("the real launcher control lost its principal: %v", err)
	}
	events, err := fixture.Store.Events(0)
	if err != nil {
		t.Fatal(err)
	}
	for _, starter := range []string{"supervisor:top", "lane:" + testdata.Lane} {
		name := "claimed-peer"
		if strings.HasPrefix(starter, "lane:") {
			name = "claimed-parent"
		}
		payload := map[string]any{}
		for key, item := range events[0]["payload"].(map[string]any) {
			payload[key] = item
		}
		payload["starter"], payload["level"], payload["level_source"] = starter, 6, "org"
		directory := filepath.Join(fixture.Config.StatePath, "lanes", name)
		payload["log"] = filepath.Join(directory, "output.log")
		payload["session"] = map[string]any{"socket": fixture.Config.Socket(fixture.Config.StatePath), "name": name}
		brief := payload["brief"].(map[string]any)
		payload["brief"] = map[string]any{"path": filepath.Join(directory, "rendered", brief["sha256"].(string)+".md"), "sha256": brief["sha256"]}
		value = testdata.Envelope(payload)
		value["id"], value["kind"], value["lane"] = name, "lane.started", name
		if _, err := fixture.Store.AppendExternal(value, "supervisor:top"); err != nil {
			t.Fatal(err)
		}
		legacy, err = CheckMessage(fixture.Config.Name, caller.Principal{ID: "lane:" + testdata.Lane}, name)
		if err == nil || legacy || !strings.Contains(err.Error(), "may not message") {
			t.Fatalf("a forged starter granted L3 delivery: %v", err)
		}
		legacy, err = CheckMessage(fixture.Config.Name, caller.Principal{ID: "supervisor:top"}, name)
		if err != nil || !legacy {
			t.Fatalf("a forged L6 target blocked the real local supervisor: %v", err)
		}
	}
}
