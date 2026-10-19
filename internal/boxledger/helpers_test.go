package boxledger_test

import (
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/boxledger"
)

// TestLastLaunch detects selecting the first launch or a different instance.
func TestLastLaunch(t *testing.T) {
	first := map[string]any{"event": "LAUNCHED", "instance_id": "i-demo1", "seq": 1}
	last := map[string]any{"event": "LAUNCHED", "instance_id": "i-demo1", "seq": 3}
	other := map[string]any{"event": "LAUNCHED", "instance_id": "i-demo2", "seq": 4}
	for _, row := range []struct {
		name, id string
		events   []map[string]any
		want     map[string]any
	}{
		{"nil", "i-demo1", nil, nil}, {"empty", "i-demo1", []map[string]any{}, nil},
		{"first", "i-demo1", []map[string]any{first}, first},
		{"last", "i-demo1", []map[string]any{first, nil, last, other}, last},
		{"other", "i-demo2", []map[string]any{first, last, other}, other},
		{"missing", "i-demo3", []map[string]any{first, last, other}, nil},
		{"wrong-kind", "i-demo1", []map[string]any{{"event": "DONE_SENT", "instance_id": "i-demo1"}}, nil},
	} {
		t.Run(row.name, func(t *testing.T) {
			if got := boxledger.LastLaunch(row.events, row.id); !reflect.DeepEqual(got, row.want) {
				t.Fatalf("LastLaunch = %v, want %v", got, row.want)
			}
		})
	}
}

// TestEndOf detects selecting pending events or the wrong terminal event.
func TestEndOf(t *testing.T) {
	confirmed := map[string]any{"event": "TERMINATED_CONFIRMED", "instance_id": "i-demo1"}
	unknown := map[string]any{"event": "END_UNKNOWN", "instance_id": "i-demo1"}
	pending := map[string]any{"event": "END_PENDING", "instance_id": "i-demo1"}
	other := map[string]any{"event": "END_UNKNOWN", "instance_id": "i-demo2"}
	for _, row := range []struct {
		name, id string
		events   []map[string]any
		want     string
		ok       bool
	}{
		{"nil", "i-demo1", nil, "", false},
		{"pending", "i-demo1", []map[string]any{pending}, "", false},
		{"confirmed", "i-demo1", []map[string]any{confirmed, pending, other}, "TERMINATED_CONFIRMED", true},
		{"unknown-last", "i-demo1", []map[string]any{confirmed, unknown, other}, "END_UNKNOWN", true},
		{"confirmed-last", "i-demo1", []map[string]any{unknown, nil, confirmed}, "TERMINATED_CONFIRMED", true},
		{"other", "i-demo2", []map[string]any{confirmed, other}, "END_UNKNOWN", true},
		{"absent", "i-demo3", []map[string]any{confirmed, other}, "", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			got, ok := boxledger.EndOf(row.events, row.id)
			if got != row.want || ok != row.ok {
				t.Fatalf("EndOf = %q, %t; want %q, %t", got, ok, row.want, row.ok)
			}
		})
	}
}
