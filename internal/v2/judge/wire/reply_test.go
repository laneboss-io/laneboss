package wire

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestNormalizedSuccessIsComplete(t *testing.T) {
	r := request()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Error("request read failed")
		}
		writeJSON(t, w, response(body))
	}))
	defer server.Close()
	adapter, err := New(options(server.URL, r, &retained{}))
	if err != nil {
		t.Fatal(err)
	}
	reply, err := adapter.Evaluate(context.Background(), r)
	if err != nil || ScoredReply(reply, r) != nil {
		t.Fatal("complete score was rejected")
	}
	encoded, err := json.Marshal(reply)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"probability", "id", "raw", "tokens", "bytes", "model", "status", "duplicate",
		"request", "request-hash", "request-class", "request-bytes", "batch-id", "batch-duplicate"} {
		t.Run(name, func(t *testing.T) {
			var reply api.JudgeReply
			if err := json.Unmarshal(encoded, &reply); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "probability":
				reply.Results[0].Probability = nil
			case "id":
				reply.Results[0].QuestionID = "other"
			case "raw":
				reply.Raw = nil
			case "request":
				reply.Request = nil
			case "request-hash":
				reply.Request.SHA256 = Digest([]byte("other request"))
			case "request-class":
				reply.Request.Class = "observation"
			case "request-bytes":
				reply.Request.Bytes--
			case "batch-id":
				reply.BatchIDs = []api.ID{""}
			case "batch-duplicate":
				reply.BatchIDs = []api.ID{"batch-a", "batch-a"}
			case "tokens":
				reply.InputTokens = 0
			case "bytes":
				reply.InputBytes--
			case "model":
				reply.ReportedModel = "other-model"
			case "status":
				reply.Status = "unavailable"
			case "duplicate":
				reply.Results = append(reply.Results, reply.Results[0])
			}
			if err := ScoredReply(reply, r); err == nil {
				t.Fatal("incomplete score accepted")
			}
		})
	}
}

func TestTypedDependencyIsPreserved(t *testing.T) {
	r := request()
	o := options("http://127.0.0.1", r, &retained{})
	o.Fit = func(context.Context, []byte) (api.TokenFit, error) {
		return api.TokenFit{}, api.NotImplemented("lb-v2-service", "fixture.fit")
	}
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
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeNotImplemented || calls != 0 {
		t.Fatal("typed dependency was swallowed")
	}
	unscored(t, got)
}
