//go:build linux

package store

import (
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestStoredJSONBounds(t *testing.T) {
	type document struct{ Data string }
	want := document{Data: strings.Repeat("retained state ", api.MaxFrameBytes/8)}
	raw := archJSON(t, want)
	var got document
	if len(raw) <= api.MaxFrameBytes {
		t.Fatal("stored JSON fixture did not cross the RPC frame boundary")
	}
	if err := decodeStored(raw, &got); err != nil || got != want {
		t.Fatal("retained state still used the RPC frame bound", err)
	}
	for _, malformed := range []string{`{"Data":"one","Data":"two"}`, `{"Data":"value","Unknown":true}`, `{"Data":"\ud800"}`} {
		if err := decodeStored([]byte(malformed), &got); err == nil {
			t.Fatal("retained state decoder weakened its closed JSON validation")
		}
	}
}
