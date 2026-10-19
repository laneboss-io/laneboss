package wire

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func assignmentCanaries() map[string]string {
	padding := strings.Repeat(" \t", 513) // The value starts beyond 1 KiB.
	// The complete literal contains assignment syntax. Its suffix alone looks
	// like a reference/placeholder; cutting there loses the actual value token.
	return map[string]string{
		"unquoted": "password=" + padding + "token=$EXAMPLE_KEY",
		"spaced":   "token = " + padding + "api_key=${EXAMPLE_KEY}",
		"double":   "token=\"" + padding + "password=redacted \"",
		"single":   "token='" + padding + "api_key=redacted '",
	}
}

func assignmentExtensionControls() map[string]string {
	padding := strings.Repeat(" \t", 513)
	return map[string]string{
		"quote-tail":     "token=\"" + padding + "\"fake-value-1",
		"spaced-tail":    "token = " + padding + "''fake-value-1",
		"reference-tail": "token=" + padding + "<EXAMPLE KEY>fake-value-1",
	}
}

func wideFragmentCanaries() map[string]any {
	padding := strings.Repeat("q", 506)
	separator := strings.Repeat(" ", 513) // One byte wider than the old overlap.
	fragment := strings.Repeat("a1", 16)
	return map[string]any{
		"argv": []any{padding, "Bear", "er" + separator, fragment},
		"fields": map[string]any{
			"a": padding, "b": "Bear", "c": "er" + separator, "d": fragment,
		},
		"inside-field":  []any{padding + "Bear", "er" + separator + fragment},
		"authorization": []any{padding, "Author", "ization" + separator + ": Basic " + fragment},
		// With the root key, old blocks start after the complete scheme.
		"url": []any{strings.Repeat("q", 500), "https:", "//" + strings.Repeat("u", 513) + ":", "fake9@"},
		"jwt": []any{padding, "eyJ" + strings.Repeat("a", 513) + ".",
			"eyJ" + strings.Repeat("b", 12) + ".", strings.Repeat("c", 12)},
	}
}

func TestAssignmentValueNotTruncated(t *testing.T) {
	for name, text := range assignmentCanaries() {
		t.Run(name, func(t *testing.T) {
			if credentialText(text) {
				t.Fatal("canary hit a signature")
			}
			if !secretText(text) || !Sensitive(text, "") {
				t.Fatal("assignment value was truncated")
			}
		})
	}
}

func TestPaddedAssignmentControls(t *testing.T) {
	padding := strings.Repeat(" \t", 513)
	for _, quote := range []string{"", "\"", "'", "`"} {
		for _, value := range []string{"fake-value-1", "$EXAMPLE_KEY", "redacted"} {
			text := "token = " + quote + padding + value + quote
			want := value == "fake-value-1"
			if secretText(text) != want || Sensitive(text, "") != want {
				t.Fatal("padded value control changed")
			}
		}
	}
	for _, text := range []string{"token=env.get(\"KEY\")", "token: ordinary prose",
		"token=$EXAMPLE_KEY other data", "token=<EXAMPLE KEY> other data",
		`{"token":"redacted",` + `"secret":"$EXAMPLE_KEY"}`,
		"token='redacted'; build project", "token=<EXAMPLE KEY>, other data"} {
		if secretText(text) || Sensitive(text, "") {
			t.Fatal("benign value token became a credential")
		}
	}
}

func TestWideFragmentCredentials(t *testing.T) {
	for name, value := range wideFragmentCanaries() {
		t.Run(name, func(t *testing.T) {
			body, err := json.Marshal(map[string]any{"state": value})
			if err != nil {
				t.Fatal(err)
			}
			var typed *api.Error
			if err := screenOutgoing(body, ""); !errors.As(err, &typed) ||
				typed.Code != api.CodeUnscored || typed.Message != "credential-shaped input withheld" {
				t.Fatal("wide split credential escaped")
			}
		})
	}
	// A long separator is ordinary input when it does not complete a shape.
	for _, value := range []any{
		[]any{strings.Repeat("q", 511), "Bear", "er" + strings.Repeat(" ", 513), "short"},
		[]any{"https:", "//" + strings.Repeat("u", 513) + ":", "$EXAMPLE_KEY"},
		[]any{"Author", "ization" + strings.Repeat(" ", 513) + ": Basic short"},
		map[string]any{"a": "token=$EXAMPLE_KEY", "b": "data"},
	} {
		body, err := json.Marshal(map[string]any{"state": value})
		if err != nil || screenOutgoing(body, "") != nil {
			t.Fatal("benign split was withheld")
		}
	}
}

func TestAssignmentExtensionControls(t *testing.T) {
	for name, text := range assignmentExtensionControls() {
		t.Run(name, func(t *testing.T) {
			// Explicit non-cap extras: a quote/reference can hide a glued bare
			// suffix from the reference's first-value parser. Preserve its
			// allowed verdict while requiring production to withhold the tail.
			if fix1Sensitive(text, "") || !Sensitive(text, "") {
				t.Fatal("named assignment extra escaped")
			}
			if namedScreenExtra(text) != name {
				t.Fatal("assignment extra lost its name")
			}
			r := request()
			r.Task = []byte(text)
			var calls atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				calls.Add(1)
				http.Error(w, "unexpected HTTP", http.StatusBadRequest)
			}))
			defer server.Close()
			store := &retained{}
			adapter, err := New(options(server.URL, r, store))
			if err != nil {
				t.Fatal(err)
			}
			got, err := adapter.Evaluate(context.Background(), r)
			if err != nil || got.Status != "unavailable" || calls.Load() != 0 ||
				got.UnavailableReason != "credential-shaped input withheld" || len(store.objects) != 0 {
				t.Fatal("named extra reached retention or HTTP")
			}
			unscored(t, got)
		})
	}
}

func TestCompleteFragmentViewCap(t *testing.T) {
	s := newScreen("")
	view := &s.views[0]
	if s.appendBytes(view, strings.Repeat("q", ScreenWindowBytes)) || s.finish() {
		t.Fatal("complete benign view at cap was withheld")
	}
	if len(view.buffer) != ScreenWindowBytes || cap(view.buffer) > ScreenWindowBytes {
		t.Fatal("view size or allocation cap changed")
	}
	if !s.appendBytes(view, "x") || !s.exhausted || !s.finish() {
		t.Fatal("view overflow passed unseen input")
	}
}

func TestAssignmentValueByteCap(t *testing.T) {
	// The entire allowed-size value is screened; the next byte cannot be
	// silently dropped even when the text beyond the cap looks harmless.
	prefix := "token="
	text := prefix + strings.Repeat(" ", MaxScreenInputBytes-len(prefix)-len("redacted")) + "redacted"
	if secretText(text) || !secretText(text+" ") {
		t.Fatal("assignment value cap passed unseen bytes")
	}
}

func TestRegressionBeforeEgress(t *testing.T) {
	cases := map[string]any{}
	for name, text := range assignmentCanaries() {
		cases["assignment-"+name] = text
	}
	for name, value := range wideFragmentCanaries() {
		cases["split-"+name] = value
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			r := request()
			raw, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			r.Task = raw
			if text, ok := value.(string); ok {
				r.Task = []byte(text)
			}
			store := &retained{}
			o := options("http://127.0.0.1", r, store)
			calls := 0
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
			if got.UnavailableReason != "credential-shaped input withheld" ||
				calls != 0 || len(store.objects) != 0 {
				t.Fatal("regression reached retention or HTTP")
			}
		})
	}
}
