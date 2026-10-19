package caller

import (
	"testing"

	"laneboss.io/laneboss/internal/eventstore"
)

func provenanceStart(actor, lane, starter string, seq int64) eventstore.Object {
	return eventstore.Object{"seq": seq, "kind": "lane.started", "lane": lane, "actor": actor,
		"payload": map[string]any{"run": 1, "how": "start", "level": 3, "level_source": "protocol", "starter": starter}}
}

func TestExternalStartNoIdentity(t *testing.T) {
	for _, kind := range []string{"lane.started", "lane.adopted"} {
		event := provenanceStart("event.append:supervisor:top", "observed", "supervisor:top", 1)
		event["kind"] = kind
		lanes, err := lanesFromEvents([]eventstore.Object{event})
		if err != nil || len(lanes) != 0 {
			t.Fatalf("%s enrolled an external observation as a principal: %v", kind, err)
		}
	}
	control := provenanceStart("supervisor:top", "actual", "supervisor:top", 1)
	lanes, err := lanesFromEvents([]eventstore.Object{control})
	if err != nil || lanes["actual"].Principal.ID != "lane:actual" || !lanes["actual"].Open {
		t.Fatalf("the actual launcher control lost identity: %v", err)
	}
}

func TestExternalStartNoAncestry(t *testing.T) {
	actual := provenanceStart("supervisor:top", "actual", "supervisor:top", 1)
	forged := provenanceStart("event.append:supervisor:other", "actual", "lane:other", 2)
	forged["payload"].(map[string]any)["run"] = 2
	forged["payload"].(map[string]any)["how"] = "reuse"
	lanes, err := lanesFromEvents([]eventstore.Object{actual, forged})
	if err != nil || lanes["actual"].Principal.Starter != "supervisor:top" || lanes["actual"].Seq != int64(1) {
		t.Fatalf("external reuse replaced the current life's ancestry: %v", err)
	}
}

func TestExternalStartNoLegacy(t *testing.T) {
	actual := provenanceStart("supervisor:top", "actual", "supervisor:top", 1)
	forged := provenanceStart("event.append:supervisor:other", "actual", "", 2)
	delete(forged["payload"].(map[string]any), "starter")
	forged["payload"].(map[string]any)["run"] = 2
	forged["payload"].(map[string]any)["how"] = "resume"
	closed := eventstore.Object{"kind": "lane.ended", "lane": "actual", "actor": "event.append:supervisor:other", "payload": map[string]any{"run": 1}}
	lanes, err := lanesFromEvents([]eventstore.Object{actual, closed, forged})
	if err != nil || lanes["actual"].Principal.Starter == "" || !lanes["actual"].Open {
		t.Fatalf("an external close or starter-less resume altered the launcher life: %v", err)
	}
}
