package eventstore

import "testing"

func TestRecordedLaneInfoLatestRecord(t *testing.T) {
	events := []Object{
		{"kind": "lane.started", "lane": "worker", "payload": Object{"level": 4, "level_source": "supervisors", "starter": "supervisor:mini-a"}},
		{"kind": "lane.resumed", "lane": "worker", "payload": Object{"level": 6, "starter": "human"}},
	}
	first := RecordedLaneInfo(events)["worker"]
	if first["level"] != 4 || first["level_source"] != "supervisors" || first["starter"] != "supervisor:mini-a" {
		t.Fatal("non-start event changed recorded metadata")
	}
	events = append(events, Object{"kind": "lane.adopted", "lane": "worker", "payload": Object{}})
	last := RecordedLaneInfo(events)["worker"]
	for _, field := range []string{"level", "level_source", "starter"} {
		if last[field] != nil {
			t.Fatalf("old-format latest record inherited %s from an earlier run", field)
		}
	}
	// The old retaining-fields behavior must be distinguishable from null.
	if first["starter"] == last["starter"] {
		t.Fatal("stale-metadata control did not differ from the actual latest record")
	}
	t.Log("negative stale-metadata control differs; latest old-format fields remain null")
}
