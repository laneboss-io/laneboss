package dashboard

import (
	"context"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/testdata"
)

func TestAnalyticsExternal(t *testing.T) {
	f := testdata.OpenStore(t)
	before, err := f.Store.Events(0)
	if err != nil {
		t.Fatal(err)
	}
	p := object{}
	for key, value := range obj(before[0]["payload"]) {
		p[key] = value
	}
	p["run"], p["how"] = 2, "resume"
	start := testdata.Envelope(p)
	start["id"], start["kind"] = "external-start", "lane.started"
	if _, err := f.Store.AppendExternal(start, "supervisor:top"); err != nil {
		t.Fatal(err)
	}
	p = object{}
	for key, value := range obj(before[2]["payload"]) {
		p[key] = value
	}
	p["run"], p["exit_code"], p["duration_seconds"] = 2, 7, 123
	end := testdata.Envelope(p)
	end["id"], end["kind"] = "external-end", "lane.ended"
	if _, err := f.Store.AppendExternal(end, "supervisor:top"); err != nil {
		t.Fatal(err)
	}
	after, err := f.Store.Events(0)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	want, err := analytics(context.Background(), f.Config, nil, before, "24h", 5, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if number(want["event_count"]) != 3 || len(want["lanes"].([]object)) != 1 {
		t.Fatal("the genuine analytics control did not count its real run")
	}
	got, err := analytics(context.Background(), f.Config, nil, after, "24h", 5, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("appended starts/ends changed counts, outcomes, durations or usage")
	}
}
