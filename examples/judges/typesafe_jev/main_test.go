package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sync/atomic"
	"testing"

	"laneboss.io/laneboss/internal/typesafe"
)

func officialFixtures(t *testing.T) (map[string]any, []byte) {
	t.Helper()
	q, err := os.ReadFile("../../../internal/typesafe/testdata/questions.json")
	if err != nil {
		t.Fatal(err)
	}
	questions, err := typesafe.Decode(q)
	if err != nil {
		t.Fatal(err)
	}
	r, err := os.ReadFile("../../../internal/typesafe/testdata/response.json")
	if err != nil {
		t.Fatal(err)
	}
	return questions, r
}

func TestOfficialHTTPContract(t *testing.T) {
	questions, fixture := officialFixtures(t)
	state := map[string]any{"message": "Help! My payouts have been failing for 3 days."}
	secret = "local-stand-in-header-only"
	t.Cleanup(func() { secret = "" })
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		if r.Method != "POST" || r.URL.Path != "/v1/systemone" || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Authorization") != "Bearer "+secret {
			t.Error("official endpoint, method or headers changed")
			w.WriteHeader(422)
			return
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			w.WriteHeader(422)
			return
		}
		body, err := typesafe.Decode(raw)
		if err != nil || len(body) != 3 || body["model"] != "jev-latest" || !reflect.DeepEqual(body["state"], state) || !reflect.DeepEqual(body["questions"], questions) {
			t.Error("one request must carry the complete named state and official questions")
			w.WriteHeader(422)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("x-typesafe-request-id", "fixture-1")
		if _, err := w.Write(fixture); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	bytes, id, err := ask(options{base: server.URL, model: "jev-latest", timeout: 2}, "laneboss.typed", map[string]any{"state": state, "questions": questions})
	if err != nil {
		t.Fatal(err)
	}
	if count.Load() != 1 {
		t.Fatal("independent questions were split across HTTP requests")
	}
	// A legacy launcher shape is not a provider response.
	if _, err := typedAnswer([]byte(`{"probability":0.95,"model":"jev-1.13.0"}`), id, questions); err == nil {
		t.Fatal("legacy provider shape succeeded")
	}
	result, err := typedAnswer(bytes, id, questions)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := typesafe.Response([]byte(result), questions)
	if err != nil {
		t.Fatal(err)
	}
	answers := object(parsed["answers"])
	if object(answers["department"])["probabilities"] == nil || object(answers["frustration"])["legend"] == nil || parsed["request"] != "fixture-1" {
		t.Fatal("adapter dropped official answer fields or the request identifier")
	}
}

func TestOfficialScalarAndRetryRows(t *testing.T) {
	secret = "local-stand-in-header-only"
	t.Cleanup(func() { secret = "" })
	response := []byte(`{"model":"jev-1.13.0","answers":{"answer":{"type":"noul","noul":0.95}},"usage":{"input_tokens":296,"output_tokens":20}}`)
	for _, status := range []int{401, 422, 429, 529} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var count atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				input, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
					w.WriteHeader(422)
					return
				}
				body, err := typesafe.Decode(input)
				wanted := map[string]any{"answer": map[string]any{"type": "noul", "instructions": "Is this urgent?",
					"criteria": map[string]any{"true": "The proposition in instructions is true for the named state.", "false": "The proposition in instructions is false for the named state."}}}
				if err != nil || !reflect.DeepEqual(body["questions"], wanted) {
					t.Error("scalar Noul instructions and criteria differ from the documented wire request")
					w.WriteHeader(422)
					return
				}
				attempt := count.Add(1)
				if attempt == 1 {
					w.WriteHeader(status)
					return
				}
				if _, err := w.Write(response); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			raw, id, err := ask(options{base: server.URL, model: "jev-latest", timeout: 2}, "Is this urgent?", map[string]any{"message": "Please help today"})
			if status == 401 || status == 422 {
				if err == nil || count.Load() != 1 {
					t.Fatal("non-retryable error succeeded or was retried")
				}
				return
			}
			if err != nil || count.Load() != 2 {
				t.Fatal("transient HTTP error was not retried once before success")
			}
			if _, err := answer([]byte(`{"answers":{"answer":{"type":"noul","noul":0.95}}}`), id); err == nil {
				t.Fatal("partial official envelope succeeded")
			}
			out, err := answer(raw, id)
			if err != nil {
				t.Fatal(err)
			}
			var scalar map[string]any
			if err := json.Unmarshal([]byte(out), &scalar); err != nil {
				t.Fatal(err)
			}
			if scalar["probability"] != 0.95 || scalar["model"] != "jev-1.13.0" {
				t.Fatal("official Noul did not translate to the launcher scalar contract")
			}
		})
	}
}
