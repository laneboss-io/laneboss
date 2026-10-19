package boxgcp

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/boxcore"
	"laneboss.io/laneboss/internal/boxexec"
)

// TestDecodeFailures rejects ignored JSON, absent names and invalid timestamps.
func TestDecodeFailures(t *testing.T) {
	badTime := encodeJSON(t, map[string]string{"name": "lb-box-1", "creationTimestamp": "invalid-time"})
	for _, tc := range []struct {
		name, method string
		data         []byte
	}{
		{"launch-json", "launch", []byte("{")},
		{"launch-empty", "launch", []byte("[]")},
		{"launch-name", "launch", []byte("[{}]")},
		{"launch-time", "launch", arrayJSON(badTime)},
		{"describe-json", "describe", []byte("{")},
		{"describe-name", "describe", []byte("null")},
		{"teardown-json", "teardown", []byte("{")},
		{"list-json", "list", []byte("{")},
		{"list-time", "list", arrayJSON(badTime)},
		{"wait-time", "wait", encodeJSON(t, map[string]string{
			"name": "lb-box-1", "status": "RUNNING", "creationTimestamp": "invalid-time",
		})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := resultFake(boxexec.Result{Stdout: tc.data}, nil)
			p, ctx := New(testConfig(), f, testOptions()), context.Background()
			var err error
			switch tc.method {
			case "launch":
				_, err = p.Launch(ctx, testRequest(), testCandidate(), testGuest())
			case "describe":
				_, err = p.Describe(ctx, testBox())
			case "teardown":
				err = p.Teardown(ctx, testBox())
			case "list":
				_, err = p.List(ctx, boxcore.ListFilter{})
			case "wait":
				_, err = p.WaitRunning(ctx, testBox())
			}
			requireKind(t, err, boxcore.KindOther)
			onlyCall(t, f)
		})
	}
}
