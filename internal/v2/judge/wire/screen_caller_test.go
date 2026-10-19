package wire

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"laneboss.io/laneboss/internal/typesafe"
	"laneboss.io/laneboss/internal/v2/api"
)

type callerFixture struct {
	name    string
	request api.JudgeRequest
}

func callerFixtures() []callerFixture {
	token := strings.Repeat("a1", 16)
	var fixtures []callerFixture
	for _, name := range []string{"cwd-command", "command-argv", "argv-paths", "state-strings", "caller-document", "tool-cwd"} {
		r := request()
		switch name {
		case "cwd-command":
			r.Command.CWD, r.Context.CWD = "/srv/Bearer", "/srv/Bearer"
			r.Command.Command = []byte(token)
		case "command-argv":
			r.Command.Command, r.Command.Argv = []byte("Bear"), []string{"er " + token}
		case "argv-paths":
			r.Command.Argv, r.Command.DeclaredPaths = []string{"Bear"}, []string{"er " + token}
		case "state-strings":
			r.Command.CWD, r.Context.CWD = "/srv/Bear", "/srv/Bear"
			r.Task = []byte("er " + token)
		case "caller-document":
			r.Command.CWD, r.Context.CWD = "/srv/Bear", "/srv/Bear"
			r.Task = []byte(`{"part":"er ` + token + `"}`)
		case "tool-cwd":
			r.Command.Tool = "Bearer"
			r.Command.CWD, r.Context.CWD = "/"+token, "/"+token
		}
		r.Command.RawSHA256 = Digest(r.Command.Command)
		fixtures = append(fixtures, callerFixture{name, r})
	}
	for _, name := range []string{"decision-task", "decision-document", "decision-texts"} {
		r := guidanceScreenRequest()
		r.Decisions[0].Text = "Bear"
		switch name {
		case "decision-task":
			r.Task = []byte("er " + token)
		case "decision-document":
			r.Task = []byte(`{"part":"er ` + token + `"}`)
		case "decision-texts":
			second := r.Decisions[0]
			second.ID, second.Text = "decision-b", "er "+token
			r.Decisions = append(r.Decisions, second)
		}
		fixtures = append(fixtures, callerFixture{name, r})
	}
	return fixtures
}

func callerRoot(t *testing.T, r api.JudgeRequest) map[string]any {
	t.Helper()
	body, _, err := Payload(r)
	if err != nil {
		t.Fatal(err)
	}
	root, err := typesafe.Decode(body)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func assertSplitLeaves(t *testing.T, value any) {
	t.Helper()
	switch v := value.(type) {
	case string:
		if fix1SecretText(v) {
			t.Fatal("caller canary is contained in one string")
		}
	case map[string]any:
		for name, child := range v {
			assertSplitLeaves(t, name)
			assertSplitLeaves(t, child)
		}
	case []any:
		for _, child := range v {
			assertSplitLeaves(t, child)
		}
	}
}

func TestCallerJoins(t *testing.T) {
	for _, fixture := range callerFixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			r := fixture.request
			root := callerRoot(t, r)
			assertSplitLeaves(t, root)
			caller, _ := frozenCallerScreen(root, "")
			if !caller {
				t.Fatal("caller canary lost independent coverage")
			}
			var calls atomic.Int64
			body, _, err := Payload(r)
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				calls.Add(1)
				sent, err := io.ReadAll(req.Body)
				if err != nil || !bytes.Equal(sent, body) {
					t.Error("caller HTTP bytes differ")
					return
				}
				writeJSON(t, w, response(sent))
			}))
			defer server.Close()
			store := &retained{}
			o := options(server.URL, r, store)
			adapter, err := New(o)
			if err != nil {
				t.Fatal(err)
			}
			fit, fitErr := adapter.Fit(context.Background(), r)
			got, err := adapter.Evaluate(context.Background(), r)
			if err != nil || got.Status != "unavailable" || got.UnavailableReason != "credential-shaped input withheld" ||
				len(got.Results) != 0 || got.Request != nil || got.Raw != nil || calls.Load() != 0 || len(store.objects) != 0 {
				t.Fatal("caller split reached retention or HTTP")
			}
			var typed *api.Error
			if !errors.As(fitErr, &typed) || typed.Code != api.CodeUnscored ||
				typed.Message != "credential-shaped input withheld" || fit.Proved {
				t.Fatal("caller split escaped fit")
			}
		})
	}
}

func unknownCallerRoots(t *testing.T) []map[string]any {
	t.Helper()
	var roots []map[string]any
	for _, field := range []string{"plain", "metadata", "container"} {
		root := callerRoot(t, request())
		state := root["state"].(map[string]any)
		switch field {
		case "plain":
			state["x"], state["y"] = "Bear", "er "+strings.Repeat("a1", 16)
		case "metadata":
			state["x"] = map[string]any{"id": "Bear", "model": "er " + strings.Repeat("a1", 16)}
		case "container":
			state["context"].(map[string]any)["grant_set_id"] = []any{"Bear", "er " + strings.Repeat("a1", 16)}
		}
		roots = append(roots, root)
	}
	for _, field := range []string{"id", "source", "list-item", "list-object", "levels", "unknown"} {
		root := callerRoot(t, guidanceScreenRequest())
		decision := root["state"].(map[string]any)["decisions"].([]any)[0].(map[string]any)
		parts := []any{"Bear", "er " + strings.Repeat("a1", 16)}
		switch field {
		case "id":
			decision["id"] = parts
		case "source":
			decision["source"].(map[string]any)["path"] = parts
		case "list-item":
			decision["applies_to"].(map[string]any)["roles"] = []any{parts}
		case "list-object":
			decision["applies_to"].(map[string]any)["project_ids"] = map[string]any{"id": parts}
		case "levels":
			decision["applies_to"].(map[string]any)["levels"] = parts
		case "unknown":
			decision["x"], decision["y"] = parts[0], parts[1]
		}
		roots = append(roots, root)
	}
	return roots
}

func TestUnknownCallerJoins(t *testing.T) {
	for _, root := range unknownCallerRoots(t) {
		assertSplitLeaves(t, root)
		caller, _ := frozenCallerScreen(root, "")
		if !caller {
			t.Fatal("caller canary lost independent coverage")
		}
		body, err := json.Marshal(root)
		if err != nil {
			t.Fatal(err)
		}
		var typed *api.Error
		if err := screenOutgoing(body, ""); !errors.As(err, &typed) || typed.Code != api.CodeUnscored ||
			typed.Message != "credential-shaped input withheld" {
			t.Fatal("unknown caller field escaped")
		}
	}
}

func TestOmissionCallerJoins(t *testing.T) {
	roots := unknownCallerRoots(t)
	for _, fixture := range callerFixtures() {
		roots = append(roots, callerRoot(t, fixture.request))
	}
	referenceHits := 0
	for _, root := range roots {
		if fix1Sensitive(root, "") {
			referenceHits++
		}
		if namedScreenOmission(root, "") != "" {
			t.Fatal("caller-only split was excused")
		}
	}
	if referenceHits == 0 {
		t.Fatal("omission control lacks a reference hit")
	}
}

func TestCallerServiceBoundary(t *testing.T) {
	r := benignScreenRequests()[4].request
	root := callerRoot(t, r)
	assertSplitLeaves(t, root)
	caller, excluded := frozenCallerScreen(root, "")
	if !fix1Sensitive(root, "") || caller || len(excluded) == 0 || namedScreenOmission(root, "") != "structured-join" {
		t.Fatal("service join boundary changed")
	}
	joined := r.Command.CWD + string(r.Command.RawSHA256)
	if !fix1CredentialText(joined) {
		t.Fatal("caller/service canary does not complete a shape")
	}
	body, _, err := Payload(r)
	if err != nil || screenOutgoing(body, "") != nil {
		t.Fatal("service bytes were joined to caller input")
	}
	// A complete credential in an excluded field is still withheld. Exclusion
	// removes cross-field joining, never complete-field credential inspection.
	root["model"] = "Bearer " + strings.Repeat("a1", 16)
	body, err = json.Marshal(root)
	if err != nil || screenOutgoing(body, "") == nil {
		t.Fatal("excluded credential was not screened")
	}
}

func TestDecisionServiceBoundary(t *testing.T) {
	r := guidanceScreenRequest()
	root := callerRoot(t, r)
	assertSplitLeaves(t, root)
	caller, excluded := frozenCallerScreen(root, "")
	if !fix1CredentialText(r.Decisions[0].Source.Path+string(r.Decisions[0].Source.SHA256)) ||
		!fix1Sensitive(root, "") || caller || len(excluded) == 0 || namedScreenOmission(root, "") != "structured-join" {
		t.Fatal("decision metadata does not explain the reference hit")
	}
	for _, field := range []struct{ parent, name string }{
		{"", "id"}, {"", "effective_at"},
		{"source", "id"}, {"source", "path"}, {"source", "sha256"}, {"source", "generation"},
		{"authority", "kind"}, {"authority", "receipt_id"}, {"authority", "org_generation"}, {"authority", "source_seq"},
		{"applies_to", "roles"}, {"applies_to", "project_ids"}, {"applies_to", "life_ids"},
	} {
		for _, mode := range []string{"literal", "embedded", "key"} {
			t.Run(field.parent+"/"+field.name+"/"+mode, func(t *testing.T) {
				root := callerRoot(t, r)
				parent := root["state"].(map[string]any)["decisions"].([]any)[0].(map[string]any)
				if field.parent != "" {
					parent = parent[field.parent].(map[string]any)
				}
				text, key := "Bearer "+strings.Repeat("a1", 16), ""
				switch mode {
				case "embedded":
					text = `["Bear","er ` + strings.Repeat("a1", 16) + `"]`
				case "key":
					key = "fixture-known-credential-value-1"
					text = key
				}
				if field.parent == "applies_to" {
					parent[field.name].([]any)[0] = text
				} else {
					parent[field.name] = text
				}
				if caller, _ := frozenCallerScreen(root, key); !caller || namedScreenOmission(root, key) != "" {
					t.Fatal("decision metadata poison lost independent coverage")
				}
				body, err := json.Marshal(root)
				if err != nil {
					t.Fatal(err)
				}
				var typed *api.Error
				if err := screenOutgoing(body, key); !errors.As(err, &typed) || typed.Code != api.CodeUnscored ||
					typed.Message != "credential-shaped input withheld" {
					t.Fatal("decision metadata escaped complete-field screening")
				}
			})
		}
	}
}
