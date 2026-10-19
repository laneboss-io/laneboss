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

type benignScreenFixture struct {
	name      string
	request   api.JudgeRequest
	reference bool
}

func guidanceScreenRequest() api.JudgeRequest {
	r := request()
	r.Purpose, r.Command, r.Rules = "guidance", nil, []api.JudgeRule{}
	r.Task = []byte("Review the build plan.")
	r.Decisions = []api.DecisionCandidate{{
		ID:   "5be17d1f-7204-4f46-a31a-84db825f227c",
		Text: "Keep build artifacts local until review is complete.",
		Source: api.SourceRef{ID: "48d6da52-52ca-444f-8765-bd189812afc1",
			Path: "/decisions/task-7", SHA256: Digest([]byte("approved decision source")), Generation: 1},
		Authority: api.DecisionAuthority{Kind: "human", ReceiptID: "e532d04d-9dd2-474b-94f3-b8ee0f0ee152",
			OrgGeneration: 1, SourceSeq: 1},
		AppliesTo: api.DecisionApplicability{Levels: []int{3}, Roles: []string{"executor"},
			ProjectIDs: []api.ID{"project-a"}, LifeIDs: []api.ID{r.Context.Target.LifeID}},
		EffectiveAt: "2026-01-01T00:00:00Z", Binding: true,
	}}
	return r
}

func benignScreenRequests() []benignScreenFixture {
	var fixtures []benignScreenFixture
	for _, id := range []api.ID{"risk-review", "pa-review", "hf_build", "npm_build"} {
		r := request()
		r.Rules[0].ID = id
		fixtures = append(fixtures, benignScreenFixture{"rule-" + string(id), r, true})
	}
	r := request()
	r.Context.CWD, r.Command.CWD = "/work/task-3", "/work/task-3"
	fixtures = append(fixtures, benignScreenFixture{"cwd-task-3", r, true})
	r = request()
	r.ID = "6ab8c57e-98ef-4503-a9cd-96e9f9d474ee"
	r.Context.LogicalTurnID = "f072f630-4217-4ab0-b618-bd2cfd936e6d"
	r.Context.CWD, r.Command.CWD = "/work/project-3", "/work/project-3"
	r.Command.Argv = []string{"go", "fmt", "./internal/example"}
	r.Command.DeclaredPaths = []string{"/work/src/main.go", "/work/build/report.json"}
	r.Task = []byte("Build the report and preserve its source hashes.")
	fixtures = append(fixtures, benignScreenFixture{"uuid-paths-hashes", r, false})
	fixtures = append(fixtures, benignScreenFixture{"guidance-task-7", guidanceScreenRequest(), true})
	return fixtures
}

// These are complete ordinary requests, including real schema keys and digest
// metadata, rather than isolated short strings chosen to evade a joined view.
func TestBenignStructuredRequestsScore(t *testing.T) {
	for _, fixture := range benignScreenRequests() {
		t.Run(fixture.name, func(t *testing.T) {
			r := fixture.request
			body, _, err := Payload(r)
			if err != nil {
				t.Fatal(err)
			}
			root, err := typesafe.Decode(body)
			if err != nil {
				t.Fatal(err)
			}
			if fix1Sensitive(root, "") != fixture.reference {
				t.Fatal("benign reference verdict changed")
			}
			if fixture.reference && namedScreenOmission(root, "") != "structured-join" {
				t.Fatal("benign fixture contains a genuine credential")
			}
			if caller, _ := frozenCallerScreen(root, ""); caller {
				t.Fatal("benign fixture has a caller credential")
			}
			var calls atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				calls.Add(1)
				sent, err := io.ReadAll(req.Body)
				if err != nil || !bytes.Equal(sent, body) {
					t.Error("benign request bytes changed")
				}
				writeJSON(t, w, response(sent))
			}))
			defer server.Close()
			store := &retained{}
			adapter, err := New(options(server.URL, r, store))
			if err != nil {
				t.Fatal(err)
			}
			got, err := adapter.Evaluate(context.Background(), r)
			if err != nil || got.Status != "scored" || calls.Load() != 1 ||
				got.Request == nil || got.Raw == nil || got.Request.SHA256 != Digest(body) ||
				got.Request.Class != "judge_request" || got.Request.Bytes != int64(len(body)) ||
				len(got.Results) != len(r.Rules)+len(r.Decisions) || len(store.objects["judge_request"]) != 1 ||
				!bytes.Equal(store.objects["judge_request"][0], body) {
				t.Fatal("benign structured input withheld")
			}
			if err := ScoredReply(got, r); err != nil {
				t.Fatal(err)
			}
			for _, answer := range got.Results {
				if answer.Probability == nil || *answer.Probability != value(body, string(answer.QuestionID)) {
					t.Fatal("benign request lost its actual score")
				}
			}
		})
	}
}

func TestOmissionKeepsCredentials(t *testing.T) {
	fragment := strings.Repeat("a1", 16)
	for _, root := range []map[string]any{
		{"state": []any{"Bear", "er ", fragment}},
		generatedScreenRoot(t, "Bearer "+fragment),
		generatedScreenRoot(t, []any{"Bear", "er ", fragment}),
		generatedScreenRoot(t, map[string]any{"a": "Bear", "b": "er " + fragment}),
	} {
		if !fix1Sensitive(root, "") || namedScreenOmission(root, "") != "" {
			t.Fatal("genuine credential classified as a structured omission")
		}
	}
}

func TestStructuredFragmentsStillWithhold(t *testing.T) {
	// Each prefix is benign alone in metadata, but these complete text scopes
	// carry a real signature. Fragment count and length remain unconstrained.
	for _, fixture := range []struct {
		name  string
		parts []string
	}{
		{"bearer", []string{"Bear", "er ", strings.Repeat("a1", 16)}},
		{"risk", []string{"risk-review", strings.Repeat("a1", 16)}},
		{"pa", []string{"pa-review", strings.Repeat("a1", 32)}},
		{"hf", []string{"hf_build", strings.Repeat("a", 40)}},
		{"npm", []string{"npm_build", strings.Repeat("a", 40)}},
	} {
		for _, location := range []string{"argv", "paths", "task-json", "command-json"} {
			t.Run(fixture.name+"/"+location, func(t *testing.T) {
				r := request()
				parts := make([]any, len(fixture.parts))
				for i, text := range fixture.parts {
					parts[i] = text
				}
				if !fix1Sensitive(parts, "") {
					t.Fatal("split canary does not match reference")
				}
				switch location {
				case "argv":
					r.Command.Argv = fixture.parts
				case "paths":
					r.Command.DeclaredPaths = fixture.parts
				default:
					text, err := json.Marshal(parts)
					if err != nil {
						t.Fatal(err)
					}
					if location == "task-json" {
						r.Task = text
					} else {
						r.Command.Command, r.Command.RawSHA256 = text, Digest(text)
					}
				}
				var calls atomic.Int64
				store := &retained{}
				o := options("http://127.0.0.1", r, store)
				o.Client = &http.Client{Transport: trip(func(*http.Request) (*http.Response, error) {
					calls.Add(1)
					return nil, errors.New("unexpected HTTP")
				})}
				adapter, err := New(o)
				if err != nil {
					t.Fatal(err)
				}
				fit, err := adapter.Fit(context.Background(), r)
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != api.CodeUnscored || fit.Proved {
					t.Fatal("withheld fit became a proof")
				}
				got, err := adapter.Evaluate(context.Background(), r)
				if err != nil || got.Status != "unavailable" || got.UnavailableReason != "credential-shaped input withheld" ||
					got.Request != nil || got.Raw != nil || len(got.Results) != 0 ||
					calls.Load() != 0 || len(store.objects) != 0 {
					t.Fatal("structured credential escaped preflight")
				}
				if ScoredReply(got, r) == nil {
					t.Fatal("withheld reply became a valid score")
				}
			})
		}
	}
}

func TestSplitResponseKeyEcho(t *testing.T) {
	key := "fixture-distinct-bearer-value-1"
	for _, echo := range []bool{false, true} {
		r := request()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			body, err := io.ReadAll(req.Body)
			if err != nil {
				t.Error(err)
			}
			root := response(body)
			if echo {
				root["echo_a"], root["echo_b"] = key[:len(key)/2], key[len(key)/2:]
			}
			encoded, err := json.Marshal(root)
			if err != nil {
				t.Error(err)
				return
			}
			if bytes.Contains(encoded, []byte(key)) {
				t.Error("split key control contains whole key")
			}
			if _, err := w.Write(encoded); err != nil {
				t.Error(err)
			}
		}))
		store := &retained{}
		o := options(server.URL, r, store)
		o.CredentialHandle, o.Credential.Bytes = "key-a", []byte(key)
		adapter, err := New(o)
		if err != nil {
			server.Close()
			t.Fatal(err)
		}
		got, err := adapter.Evaluate(context.Background(), r)
		server.Close()
		if err != nil {
			t.Fatal(err)
		}
		if echo {
			if got.Status != "unavailable" || got.UnavailableReason != "judge response withheld" ||
				got.Raw != nil || len(store.objects["judge_raw"]) != 0 {
				t.Fatal("split response key reached retention")
			}
		} else if got.Status != "scored" || got.Raw == nil {
			t.Fatal("response key control did not score")
		}
	}
}
