package wire

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/typesafe"
	"laneboss.io/laneboss/internal/v2/api"
)

func TestAssignmentRegionsAreLinear(t *testing.T) {
	text := strings.Repeat("token=redacted ", 18000)
	visited, calls := 0, 0
	if visitAssignmentValues(text, func(value string) bool {
		visited += len(value)
		calls++
		return literalValue(value)
	}) || visited > len(text) || calls != 18000 {
		t.Fatal("assignment scan repeated bytes")
	}
	if secretText(text) {
		t.Fatal("references became credentials")
	}
	if !secretText(text + "token=fake-value-1") {
		t.Fatal("assignment tail was not screened")
	}
	if !secretText(`token="secret=fake-value-1"`) {
		t.Fatal("nested assignment escaped")
	}
}

func TestScreenCapsWithhold(t *testing.T) {
	benign := "ordinary project data"
	s := newScreen("")
	s.left = len(benign) - 1
	if !s.walk(benign, 0) || !s.exhausted {
		t.Fatal("byte cap passed unseen input")
	}
	s = newScreen("")
	s.left = len(benign)
	if s.text(benign) || s.exhausted || !s.text("more data") || !s.exhausted {
		t.Fatal("byte cap boundary failed")
	}
	var deep any = benign
	for range MaxScreenDepth + 1 {
		deep = []any{deep}
	}
	s = newScreen("")
	if !s.walk(deep, 0) || !s.exhausted {
		t.Fatal("depth cap passed unseen input")
	}
	items := make([]any, MaxScreenNodes+1)
	for i := range items {
		items[i] = ""
	}
	s = newScreen("")
	if !s.walk(items, 0) || !s.exhausted {
		t.Fatal("node cap passed unseen input")
	}
	if Sensitive(map[string]any{"task": benign}, "") {
		t.Fatal("benign control was withheld")
	}
	body, err := json.Marshal(map[string]any{"task": strings.Repeat("x", MaxScreenInputBytes)})
	if err != nil {
		t.Fatal(err)
	}
	var typed *api.Error
	if err := screenOutgoing(body, ""); !errors.As(err, &typed) || typed.Code != api.CodeUnscored {
		t.Fatal("raw input cap was not withheld")
	}
}

func TestFragmentWindowBoundaries(t *testing.T) {
	fragment := strings.Repeat("a1", 16)
	// Preserve the original rolling-window boundaries as regression inputs.
	for _, offset := range []int{512 - 5, 1024 - 5, 2048 - 5} {
		value := []any{strings.Repeat("q", offset), "Bear", "er ", fragment}
		if !Sensitive(value, "") {
			t.Fatal("window boundary hid credential")
		}
	}
	key := strings.Repeat("k9", maxScreenKeyBytes/2)
	value := []any{key[:2048], key[2048:4096], key[4096:]}
	if !Sensitive(value, key) || !Sensitive("ordinary", key+"x") {
		t.Fatal("key window or key cap failed")
	}
	s := newScreen("")
	if s.walk([]any{strings.Repeat("q", 4096), "data"}, 0) || s.finish() {
		t.Fatal("clean stream was withheld")
	}
	for i := range s.views {
		if len(s.views[i].buffer) > s.views[i].window || cap(s.views[i].buffer) > s.views[i].window {
			t.Fatal("fragment view exceeded bound")
		}
	}
}

func TestRadixKeysKeepStableOrder(t *testing.T) {
	keys := []string{"bbb", "aa", "b", "", "界", "a", "aab", "aaa"}
	expected := []string{"", "a", "aa", "aaa", "aab", "b", "bbb", "界"}
	s := newScreen("")
	if !s.orderKeys(keys) {
		t.Fatal("key ordering exhausted budget")
	}
	for i := range keys {
		if keys[i] != expected[i] {
			t.Fatal("key ordering changed views")
		}
	}
	s = newScreen("")
	s.left = 1
	if s.orderKeys(keys) || !s.exhausted {
		t.Fatal("sort cap passed unseen keys")
	}
}

func TestScreenCapsBeforeEgress(t *testing.T) {
	for _, mode := range []string{"nodes", "depth", "input"} {
		t.Run(mode, func(t *testing.T) {
			r := request()
			switch mode {
			case "nodes":
				r.Command.Argv = make([]string, MaxScreenNodes+1)
			case "depth":
				r.Task = []byte(strings.Repeat("[", MaxScreenDepth+1) + "0" + strings.Repeat("]", MaxScreenDepth+1))
			case "input":
				r.Command.Command = bytes.Repeat([]byte("x"), MaxScreenInputBytes+1)
				r.Command.RawSHA256 = Digest(r.Command.Command)
			}
			store := &retained{}
			o := options("http://127.0.0.1", r, store)
			var calls int
			o.Client = &http.Client{Transport: trip(func(*http.Request) (*http.Response, error) {
				calls++
				return nil, errors.New("unexpected HTTP")
			})}
			adapter, err := New(o)
			if err != nil {
				t.Fatal(err)
			}
			got, err := adapter.Evaluate(context.Background(), r)
			if err != nil {
				t.Fatal(err)
			}
			unscored(t, got)
			if calls != 0 || len(store.objects) != 0 ||
				got.UnavailableReason != ScreenCapReason {
				t.Fatal("cap leaked input past preflight")
			}
		})
	}
}

func TestConformingRequestNodeBoundary(t *testing.T) {
	// Count the serialized tree independently, including each map key. This
	// fixture has no embedded JSON strings, so every node is visited once in
	// each fixed pass. Empty argv elements add nodes without a byte/work cap.
	var count func(any) int
	count = func(value any) int {
		n := 1
		switch value := value.(type) {
		case map[string]any:
			for _, child := range value {
				n += 1 + count(child)
			}
		case []any:
			for _, child := range value {
				n += count(child)
			}
		}
		return n
	}
	output := screenLedger(t, "request-node-edges")
	for _, edge := range []struct {
		name  string
		delta int
	}{{"below", -1}, {"exact", 0}, {"over", 1}} {
		t.Run(edge.name, func(t *testing.T) {
			r := request()
			base := count(callerRoot(t, r))
			r.Command.Argv = make([]string, MaxScreenNodes-base+edge.delta)
			body, _, err := Payload(r)
			if err != nil || len(body) > api.MaxJudgeBytes || len(body) > MaxScreenInputBytes {
				t.Fatal("node boundary fixture is not a bounded request")
			}
			root, err := typesafe.Decode(body)
			if err != nil || count(root) != MaxScreenNodes+edge.delta {
				t.Fatal("node boundary fixture lost exact node count")
			}
			err = screenOutgoing(body, "")
			if output != nil {
				if err := json.NewEncoder(output).Encode(map[string]any{
					"name": edge.name, "nodes_per_pass": count(root), "body": body, "withheld": err != nil,
				}); err != nil {
					t.Fatal(err)
				}
			}
			if edge.delta <= 0 {
				if err != nil {
					t.Fatal("conforming request lost per-pass node allowance")
				}
			} else {
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != api.CodeUnscored || typed.Message != ScreenCapReason {
					t.Fatal("conforming node exhaustion passed preflight")
				}
			}
		})
	}
}

func TestRequestPassesShareWork(t *testing.T) {
	// Exercise screening's 1 MiB envelope directly, before the separate judge
	// byte/fit gate. Each pass fits alone; their combined work exceeds 8 MiB.
	r := request()
	r.Command.Command = bytes.Repeat([]byte("q"), MaxScreenInputBytes/2)
	r.Command.RawSHA256 = Digest(r.Command.Command)
	body, _, err := Payload(r)
	if err != nil || len(body) > MaxScreenInputBytes {
		t.Fatal("shared work fixture exceeds serialized screen bound")
	}
	root, err := typesafe.Decode(body)
	if err != nil {
		t.Fatal(err)
	}
	for _, execution := range []bool{false, true} {
		s := newScreen("")
		s.execution, s.decodedOnly = execution, execution
		if s.walkAt(root, 0, requestPath) || s.finish() || s.exhausted {
			t.Fatal("shared work control does not fit one pass")
		}
	}
	var typed *api.Error
	if err := screenOutgoing(body, ""); !errors.As(err, &typed) || typed.Code != api.CodeUnscored || typed.Message != ScreenCapReason {
		t.Fatal("request passes reset the shared work budget")
	}
}

func benchmarkScreenBody(b *testing.B, assignments, poisoned bool) []byte {
	b.Helper()
	r := request()
	if !assignments {
		fields := make(map[string]any, 4096)
		for i := range 4096 {
			fields[fmt.Sprintf("f%04d", i)] = "ordinary data"
		}
		var nested any = fields
		for range 24 {
			nested = map[string]any{"layer": nested}
		}
		raw, err := json.Marshal(nested)
		if err != nil {
			b.Fatal(err)
		}
		r.Task = raw
	}
	raw, _, err := Payload(r)
	if err != nil {
		b.Fatal(err)
	}
	n := len(r.Command.Command) + api.MaxJudgeBytes - len(raw)
	if n < 1 {
		b.Fatal("benchmark fixture exceeds bound")
	}
	if assignments {
		unit := "token=redacted "
		r.Command.Command = []byte(strings.Repeat(unit, n/len(unit)) + strings.Repeat(" ", n%len(unit)))
	} else {
		r.Command.Command = bytes.Repeat([]byte("q"), n)
	}
	if poisoned {
		credential := []byte("Bearer " + strings.Repeat("a1", 16))
		if len(credential) > len(r.Command.Command) {
			b.Fatal("benchmark tail does not fit")
		}
		copy(r.Command.Command[len(r.Command.Command)-len(credential):], credential)
	}
	r.Command.RawSHA256 = Digest(r.Command.Command)
	raw, _, err = Payload(r)
	if err != nil || len(raw) != api.MaxJudgeBytes {
		b.Fatal("benchmark byte scope changed")
	}
	return raw
}

// Run without -race on the authorized Ubuntu box. Each observation, including
// strict decode and nested inspection, must fit one quarter of the normal
// two-second command budget. The benchmark does not extend that deadline.
func BenchmarkScreenBudget(b *testing.B) {
	for _, mode := range []string{"many-fields-deep", "assignment-tails"} {
		b.Run(mode, func(b *testing.B) {
			bodies := [][]byte{
				benchmarkScreenBody(b, mode == "assignment-tails", false),
				benchmarkScreenBody(b, mode == "assignment-tails", true),
			}
			b.SetBytes(int64(len(bodies[0]) + len(bodies[1])))
			b.ReportAllocs()
			b.ResetTimer()
			var maximum time.Duration
			for range b.N {
				for i, body := range bodies {
					start := time.Now()
					err := screenOutgoing(body, "")
					elapsed := time.Since(start)
					maximum = max(maximum, elapsed)
					if (err != nil) != (i == 1) {
						b.Fatal("workload detection changed")
					}
					if i == 1 {
						var typed *api.Error
						if !errors.As(err, &typed) || typed.Code != api.CodeUnscored {
							b.Fatal("tail control failed wrong gate")
						}
					}
					if elapsed > 500*time.Millisecond {
						b.Fatalf("%s: %d bytes, #%d, %s > 500ms", mode, len(body), i, elapsed)
					}
				}
			}
			b.ReportMetric(float64(maximum.Nanoseconds())/1e6, "max-ms")
		})
	}
}
