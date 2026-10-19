package caller

import (
	"testing"

	"laneboss.io/laneboss/internal/eventstore"
)

func TestRunLineIsImmutable(t *testing.T) {
	seq := int64(0)
	start := func(run int, how, launch, parent string) eventstore.Object {
		seq++
		return eventstore.Object{"seq": seq, "kind": "lane.started", "lane": "worker", "payload": map[string]any{"run": run, "how": how, "launch": launch, "level": 3, "level_source": "protocol", "starter": parent}}
	}
	first := start(1, "start", "original", "supervisor:mini-a")
	duplicate := start(1, "start", "replacement", "")
	delete(duplicate["payload"].(map[string]any), "starter")
	ended := eventstore.Object{"kind": "lane.ended", "lane": "worker", "payload": map[string]any{"run": 1}}
	rows, err := lanesFromEvents([]eventstore.Object{first, ended, duplicate})
	if err != nil {
		t.Fatal(err)
	}
	r := rows["worker"]
	if r.Open || r.Payload["launch"] != "original" || r.Principal.Starter != "supervisor:mini-a" {
		t.Fatal("a later event replaced the original run or reopened a closed run")
	}
	resumed := start(2, "resume", "next", "supervisor:mini-b")
	starterless := start(2, "resume", "unparented", "")
	delete(starterless["payload"].(map[string]any), "starter")
	rows, err = lanesFromEvents([]eventstore.Object{first, ended, starterless})
	if err != nil || rows["worker"].Principal.Starter != "supervisor:mini-a" {
		t.Fatal("a starter-less later run made a current life legacy")
	}
	rows, err = lanesFromEvents([]eventstore.Object{first, ended, resumed})
	if err != nil {
		t.Fatal(err)
	}
	if r = rows["worker"]; !r.Open || r.Payload["launch"] != "next" || r.Principal.Starter != "supervisor:mini-a" {
		t.Fatal("a resume changed the original report line")
	}
	if r.Seq != first["seq"] {
		t.Fatal("a resume must keep the start sequence of its life")
	}
	reused := start(3, "reuse", "new-life", "supervisor:mini-b")
	rows, err = lanesFromEvents([]eventstore.Object{first, ended, resumed, reused})
	if err != nil || rows["worker"].Principal.Starter != "supervisor:mini-b" {
		t.Fatal("a new life did not record its actual starter")
	}
	if rows["worker"].Seq != reused["seq"] {
		t.Fatal("a reuse must start a new life with its own start sequence")
	}
	old := start(1, "start", "old", "")
	delete(old["payload"].(map[string]any), "starter")
	rows, err = lanesFromEvents([]eventstore.Object{old, ended, resumed})
	if err != nil || rows["worker"].Principal.Starter != "supervisor:mini-b" {
		t.Fatal("a later recorded starter failed to close the historical fallback")
	}
}

func TestLegacyStarterCannotRaiseLevel(t *testing.T) {
	legacy := Principal{ID: "lane:old"}
	for level := 3; level <= 6; level++ {
		if _, _, err := belowStarter(legacy, Line{Level: level}); err == nil {
			t.Fatalf("an unnumbered lane started an L%d child", level)
		}
	}
	if _, _, err := belowStarter(Principal{ID: "human"}, Line{Level: 6}); err != nil {
		t.Fatal("the terminal human lost its level exception")
	}
}
