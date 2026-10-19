package wire

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestFixedArrayShape(t *testing.T) {
	type envelope struct {
		Limits [][2]string `json:"limits"`
	}
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	want := envelope{Limits: [][2]string{{"first", string(id)}, {"second", ""}}}
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var got envelope
	if err := Decode(raw, &got); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("acceptance: wire decoder lost the producer's exact fixed array")
	}
	for _, sample := range []struct{ name, input string }{
		{"short", `{"limits":[["a"]]}`}, {"long", `{"limits":[["a","b","c"]]}`},
		{"null", `{"limits":[null]}`}, {"member", `{"limits":[["a",3]]}`},
		{"null-member", `{"limits":[["a",null]]}`},
		{"object", `{"limits":[{"a":"b"}]}`}, {"missing", `{}`},
		{"unknown", `{"limits":[],"other":[]}`}, {"duplicate", `{"limits":[],"limits":[]}`},
	} {
		t.Run(sample.name, func(t *testing.T) {
			var value envelope
			if err := Decode([]byte(sample.input), &value); err == nil {
				t.Fatal("acceptance: wire fixed-array validation admitted an inexact shape")
			}
		})
	}
}
