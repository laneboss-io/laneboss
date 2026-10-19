package api

import (
	"bytes"
	"strings"
	"testing"
)

func TestObjectJSONBounds(t *testing.T) {
	raw := []byte(`{"data":"` + strings.Repeat("x", MaxFrameBytes) + `"}`)
	canonical, err := CanonicalObjectJSON(raw)
	if err != nil || !bytes.Equal(canonical, raw) || ValidateObjectJSON(raw) != nil {
		t.Fatal("retained JSON still used the RPC frame bound", err)
	}
	if _, err := CanonicalJSON(raw); err == nil {
		t.Fatal("retained object allowance widened RPC canonicalization")
	}
	var body struct {
		Data string `json:"data"`
	}
	if err := DecodeObject(raw, &body); err == nil {
		t.Fatal("retained object allowance widened RPC decoding")
	}
	for _, malformed := range [][]byte{
		[]byte(`{"data":"` + strings.Repeat("x", MaxFrameBytes) + `","data":"duplicate"}`),
		[]byte(`{"data":"\ud800"}`),
		[]byte(`{"data":[]} {}`),
	} {
		if _, err := CanonicalObjectJSON(malformed); err == nil || ValidateObjectJSON(malformed) == nil {
			t.Fatal("retained JSON accepted duplicate, malformed Unicode or trailing data")
		}
	}
	oversized := bytes.Repeat([]byte(" "), MaxObjectBytes+1)
	oversized[0], oversized[len(oversized)-1] = '[', ']'
	_, err = CanonicalObjectJSON(oversized)
	contractCode(t, err, CodeBudget, "oversized retained JSON escaped its object budget")
	contractCode(t, ValidateObjectJSON(oversized), CodeBudget, "oversized stored state escaped its object budget")
}
