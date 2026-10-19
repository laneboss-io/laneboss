package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
)

// These are CLI protocol controls. The transport supplies explicit session
// facts; they do not stand in for installed identity or native secret tests.
func TestSessionFlow(t *testing.T) {
	for _, label := range []string{"success", "refused", "request_wait", "proof_wait"} {
		refuse := label == "refused"
		t.Run(label, func(t *testing.T) {
			directory := t.TempDir()
			digest, err := api.RequestDigest(api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion,
				Config: "demo", Method: "human.session", Params: json.RawMessage(`{}`)})
			if err != nil {
				t.Fatal(err)
			}
			proof := api.ProofRef{ID: "session-proof", RequestSHA256: digest,
				ExpiresAt: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))}
			proofFile := integrateFixtureFile(t, directory, "proof.json", proof)
			integrateFixtureFile(t, directory, "read.json", api.Empty{})
			first := map[string]any{"name": "first", "method": "identity.self", "request": "read.json"}
			if label == "request_wait" {
				first["request"] = "pending.json"
			}
			if label == "proof_wait" {
				integrateFixtureFile(t, directory, "import.json", api.SecretImportRequest{
					Name: "flow.canary", Version: "one", SealedUploadID: "stage"})
				first = map[string]any{"name": "first", "method": "secret.import", "request": "import.json",
					"proof": "pending.proof.json", "idempotency_key": strings.Repeat("p", 32)}
			}
			plan := integrateFixtureFile(t, directory, "flow.json", map[string]any{
				"schema": "laneboss.client-flow.v2", "steps": []any{
					first, map[string]any{"name": "second", "method": "identity.self", "request": "read.json"},
				},
			})
			session := api.ID("")
			transport := &integrateFixtureClient{}
			transport.handle = func(request api.Request) (any, error) {
				if request.Method == "human.session" && request.Proof != nil && *request.Proof == proof {
					session = request.RequestID
					return api.HumanSession{ID: session, Config: request.Config}, nil
				}
				if session == "" || request.Method != "identity.self" || request.Proof != nil || transport.closed != 0 {
					return nil, &api.Error{Code: api.CodeUnauthenticated}
				}
				if refuse {
					return nil, &api.Error{Code: api.CodeForbidden, Message: "flow control refusal"}
				}
				return api.Scope{Config: request.Config, Actor: api.Actor{Kind: "human", ID: session}, EndpointGeneration: 1}, nil
			}
			var output bytes.Buffer
			call := Invocation{Path: "human session", Config: "demo", Method: "human.session", ProofFile: proofFile,
				Args: []string{"--flow", plan, "--wait", "0s"}, Stdout: &output, IdempotencyKey: api.ID(strings.Repeat("s", 32)),
				integrateSocket: &integrateSocket{options: client.Options{Config: "demo"}, connection: transport}}
			err = runHumanSession(context.Background(), call)
			if call.integrateSocket.connection != transport || transport.closed != 0 {
				t.Fatal("session flow changed its borrowed connection owner")
			}
			if label == "request_wait" || label == "proof_wait" {
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != api.CodePrerequisite || len(transport.requests) != 1 {
					t.Fatal("missing owner input advanced the public flow", err)
				}
				lines := strings.Split(strings.TrimSpace(output.String()), "\n")
				var wait struct {
					Step      string     `json:"step"`
					Completed bool       `json:"completed"`
					Wait      *api.Error `json:"wait"`
				}
				if len(lines) != 2 || json.Unmarshal([]byte(lines[1]), &wait) != nil || wait.Completed || wait.Wait == nil || wait.Wait.Code != api.CodePrerequisite {
					t.Fatal("missing owner input lost its incomplete typed wait")
				}
				want := "fixture_preparation"
				if label == "proof_wait" {
					want = "human_confirmation"
				}
				if wait.Step != want {
					t.Fatal("owner wait named the wrong prerequisite")
				}
				return
			}
			if refuse {
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != api.CodeForbidden || len(transport.requests) != 2 {
					t.Fatal("flow did not stop at its actual public refusal", err)
				}
				return
			}
			if err != nil {
				t.Fatal("file-backed session flow did not execute", err)
			}
			var records []struct {
				Name     string       `json:"name"`
				Request  api.Request  `json:"request"`
				Response api.Response `json:"response"`
			}
			for _, line := range strings.Split(strings.TrimSpace(output.String()), "\n") {
				var record struct {
					Name     string       `json:"name"`
					Request  api.Request  `json:"request"`
					Response api.Response `json:"response"`
				}
				if err := json.Unmarshal([]byte(line), &record); err != nil {
					t.Fatal(err)
				}
				records = append(records, record)
			}
			if len(records) != 3 || len(transport.requests) != 3 || transport.closed != 0 {
				t.Fatal("flow lost a response or its borrowed connection")
			}
			for i, name := range []string{"human-session", "first", "second"} {
				if records[i].Name != name || records[i].Request.RequestID != transport.requests[i].RequestID ||
					records[i].Response.RequestID != records[i].Request.RequestID {
					t.Fatal("flow changed its actual request or response")
				}
			}
		})
	}
}
