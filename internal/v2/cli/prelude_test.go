package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
)

func TestSpawnPrelude(t *testing.T) {
	for _, rule := range []string{"start", "adopt", "receipt-only", "foreign", "wrong-proof", "ambiguous", "method"} {
		t.Run(rule, func(t *testing.T) {
			digest, err := api.RequestDigest(api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: "demo", Method: "human.session", Params: json.RawMessage(`{}`)})
			if err != nil {
				t.Fatal(err)
			}
			proof := api.ProofRef{ID: "session-proof", RequestSHA256: digest, ExpiresAt: api.Timestamp(time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano))}
			if rule == "wrong-proof" {
				proof.RequestSHA256 = api.Digest(strings.Repeat("0", 64))
			}
			proofFile := integrateFixtureFile(t, t.TempDir(), "session.json", proof)
			// Grant arrays are required wire fields: nil slices encode as null
			// and fail body validation before either prelude request is sent.
			grants := api.GrantRequest{
				Resources: []api.ResourceDelegation{}, Data: []api.DataGrantRequest{},
				Secrets: []api.SecretDelegation{}, Profiles: []api.ProfileDelegation{},
				Network: []api.NetworkDelegation{}, Channels: []api.ChannelDelegation{},
			}
			blob := func(id api.ID, class, content string) api.BlobRef {
				sum := sha256.Sum256([]byte(content))
				return api.BlobRef{ID: id, Class: class, Bytes: int64(len(content)), SHA256: api.Digest(hex.EncodeToString(sum[:]))}
			}
			// Use complete lifecycle inputs so its registered validator cannot
			// hide the proof and connection behavior this fixture exercises.
			start := api.StartRequest{
				Lane: "prelude-root", ProjectID: "project", Level: 3, Role: "executor",
				Task: blob("task", "task", "prelude task\n"), Grants: grants,
				Driver: api.DriverCodex, ProfileGrantID: "profile", Model: "fixture-model", Effort: "high",
				Budget: api.Budget{WallMS: 60000, CPUSeconds: 60, MemoryBytes: 1 << 20,
					Processes: 16, DiskBytes: 1 << 20, SpendMicros: 0, Currency: "USD"},
				RootTicketID: "one-use-ticket", ExpectedPolicyGeneration: 2,
			}
			method := api.Method("lane.start")
			var body any = start
			if rule == "adopt" {
				method, body = "lane.adopt", api.AdoptRequest{
					Lane: start.Lane, Level: start.Level, Role: start.Role, Task: start.Task,
					Grants: start.Grants, Driver: start.Driver, ProfileGrantID: start.ProfileGrantID,
					Model: start.Model, Effort: start.Effort, Budget: start.Budget,
					RootTicketID: start.RootTicketID, ExpectedPolicyGeneration: start.ExpectedPolicyGeneration,
					ImportManifest: blob("manifest", "manifest", "{}"),
				}
			}
			if rule == "method" {
				method, body = "ticket.issue", api.TicketIssueRequest{
					Level: start.Level, Role: start.Role, GrantSetID: "root-grants", ExpiresAt: proof.ExpiresAt,
				}
			}
			original, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			key := api.ID(strings.Repeat("k", 32))
			if _, err := client.PrepareRequest(api.Request{Config: "demo", Method: method, Params: original, IdempotencyKey: key}); err != nil {
				t.Fatalf("fixture check: invalid body would mask the prelude result: %v", err)
			}
			if err := integrateValidateInput(method, original, true); err != nil {
				t.Fatalf("fixture check: registered validator rejected prelude input: %v", err)
			}
			phase, spawns := 0, 0
			transport := &integrateFixtureClient{}
			transport.handle = func(request api.Request) (any, error) {
				if transport.closed != 0 {
					return nil, &api.Error{Code: api.CodeUnavailable}
				}
				switch request.Method {
				case "human.session":
					if phase != 0 || request.Proof == nil || *request.Proof != proof || string(request.Params) != "{}" {
						return nil, &api.Error{Code: api.CodeUnauthenticated}
					}
					phase = 1
					return api.HumanSession{ID: "retained-session", Config: "demo"}, nil
				case "identity.self":
					if phase != 1 || request.Proof != nil || rule == "receipt-only" {
						return nil, &api.Error{Code: api.CodeUnauthenticated}
					}
					phase = 2
					config := "demo"
					if rule == "foreign" {
						config = "foreign"
					}
					return api.Scope{Config: config, Actor: api.Actor{Kind: "human", ID: "principal"}, EndpointGeneration: 1, PolicyGeneration: 2}, nil
				case "lane.start", "lane.adopt":
					spawns++
					if phase != 2 || request.Proof != nil || !bytes.Equal(request.Params, original) {
						return nil, &api.Error{Code: api.CodeUnauthenticated}
					}
					phase = 3
					return api.Operation{ID: "root-operation", Status: "pending"}, nil
				default:
					return nil, &api.Error{Code: api.CodeInvalid}
				}
			}
			var output bytes.Buffer
			call := Invocation{Config: "demo", Method: method, SessionProofFile: proofFile, IdempotencyKey: key, Stdout: &output,
				integrateSocket: &integrateSocket{options: client.Options{Config: "demo"}, connection: transport}}
			if rule == "ambiguous" {
				call.ProofFile = proofFile
			}
			if rule == "ambiguous" || rule == "method" {
				helper, helperErr := call.identitySpawnSession()
				var typed *api.Error
				if !errors.As(helperErr, &typed) || typed.Code != api.CodeInvalid || helper.Method != "" {
					t.Fatal("fixture check: session helper accepted an ambiguous or foreign operation")
				}
			}
			err = call.Invoke(context.Background(), body)
			if rule == "start" || rule == "adopt" {
				if err != nil || phase != 3 || spawns != 1 || len(transport.requests) != 3 || transport.closed != 0 ||
					transport.requests[0].Method != "human.session" || transport.requests[1].Method != "identity.self" || transport.requests[2].Method != method {
					t.Fatalf("fixture check: root spawn did not use its live session prelude: %v", err)
				}
				if transport.requests[0].IdempotencyKey == transport.requests[2].IdempotencyKey ||
					transport.requests[0].RequestID == transport.requests[1].RequestID || !bytes.Contains(output.Bytes(), []byte("root-operation")) {
					t.Fatal("fixture check: prelude changed request correlation or hid the root reply")
				}
				return
			}
			if spawns != 0 {
				t.Fatal("fixture check: refused prelude reached root spawn")
			}
			var typed *api.Error
			want := api.CodeUnauthenticated
			if rule == "wrong-proof" || rule == "ambiguous" || rule == "method" {
				want = api.CodeInvalid
			}
			if !errors.As(err, &typed) || typed.Code != want {
				t.Fatalf("fixture check: prelude want %s, got %v", want, err)
			}
			if rule == "wrong-proof" || rule == "ambiguous" || rule == "method" {
				if len(transport.requests) != 0 {
					t.Fatal("fixture check: invalid session proof option contacted transport")
				}
			} else if len(transport.requests) != 2 || transport.requests[1].Method != "identity.self" {
				t.Fatal("fixture check: session receipt replaced the required public read")
			}
			if output.Len() != 0 || transport.closed != 0 {
				t.Fatal("fixture check: prelude leaked a partial result or closed a borrowed socket")
			}
		})
	}
}

func TestInternalReader(t *testing.T) {
	entry, ok := integrateCommands["internal reader"]
	if !ok || entry.run == nil {
		t.Fatal("installed executable has no persistent public reader entry")
	}
	for _, mode := range []string{"valid", "proof", "foreign", "mutation", "reply"} {
		t.Run(mode, func(t *testing.T) {
			digest, err := api.RequestDigest(api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: "demo", Method: "human.session", Params: json.RawMessage(`{}`)})
			if err != nil {
				t.Fatal(err)
			}
			proof := api.ProofRef{ID: "reader-proof", RequestSHA256: digest, ExpiresAt: "2099-01-01T00:00:00Z", SimulatedPresence: true}
			if mode == "proof" {
				proof.RequestSHA256 = api.Digest(strings.Repeat("0", 64))
			}
			path := integrateFixtureFile(t, t.TempDir(), "reader.json", proof)
			input, output := &bytes.Buffer{}, &bytes.Buffer{}
			request, err := client.PrepareRequest(api.Request{Config: "demo", Method: "identity.self", Params: json.RawMessage(`{}`)})
			if err != nil {
				t.Fatal(err)
			}
			if mode == "foreign" {
				request.Config = "foreign"
			}
			if mode == "mutation" {
				request.Method = "lane.stop"
			}
			if err := json.NewEncoder(input).Encode(request); err != nil {
				t.Fatal(err)
			}
			transport := &integrateFixtureClient{}
			transport.handle = func(q api.Request) (any, error) {
				if q.Method == "human.session" {
					if q.Proof == nil || *q.Proof != proof {
						t.Fatal("reader changed its proof")
					}
					return api.HumanSession{ID: "reader-session", Config: q.Config, ExpiresAt: proof.ExpiresAt, IdleExpiresAt: proof.ExpiresAt, SimulatedPresence: q.Proof.SimulatedPresence}, nil
				}
				if mode == "reply" {
					return "wrong typed reply", nil
				}
				if q.Method != request.Method || q.RequestID != request.RequestID || q.Proof != nil {
					t.Fatal("reader changed the exact read correlation")
				}
				return api.Scope{Config: q.Config, Actor: api.Actor{Kind: "human", ID: "reader-principal"}}, nil
			}
			err = entry.run(context.Background(), Invocation{Config: "demo", ProofFile: path, Stdin: input, Stdout: output,
				integrateSocket: &integrateSocket{options: client.Options{Config: "demo"}, connection: transport}})
			if mode != "valid" {
				if err == nil {
					t.Fatal("reader accepted changed", mode)
				}
				if mode == "proof" && len(transport.requests) != 0 {
					t.Fatal("invalid proof reached the socket")
				}
				if (mode == "foreign" || mode == "mutation") && len(transport.requests) != 1 {
					t.Fatal("foreign input reached a read")
				}
				return
			}
			if err != nil || len(transport.requests) != 2 || transport.closed != 0 {
				t.Fatal("reader did not keep the command's existing connection", err)
			}
			decoder := json.NewDecoder(output)
			for i := 0; i < 2; i++ {
				var response api.Response
				if err := decoder.Decode(&response); err != nil {
					t.Fatal(err)
				}
				if response.RequestID != transport.requests[i].RequestID || response.Error != nil {
					t.Fatal("reader lost the public response")
				}
			}
		})
	}
}

func TestSessionOption(t *testing.T) {
	t.Setenv("LANEBOSS_CONFIG", "demo")
	for _, rule := range []string{"help", "duplicate", "empty", "ambiguous", "method"} {
		t.Run(rule, func(t *testing.T) {
			args := []string{"lane", "start", "--config", "demo"}
			switch rule {
			case "help":
				args = append(args, "--help")
			case "duplicate":
				args = append(args, "--session-proof", "first", "--session-proof=second")
			case "empty":
				args = append(args, "--session-proof=")
			case "ambiguous":
				args = append(args, "--session-proof", "session", "--proof", "operation")
			case "method":
				args = []string{"ticket", "issue", "--config", "demo", "--session-proof", "session"}
			}
			var out, stderr bytes.Buffer
			code := RunContext(context.Background(), args, strings.NewReader(""), &out, &stderr)
			if rule == "help" {
				if code != 0 || !bytes.Contains(out.Bytes(), []byte("--session-proof FILE")) {
					t.Fatal("fixture check: root help omits the session proof route")
				}
				return
			}
			if code != 2 || out.Len() != 0 || stderr.Len() == 0 {
				t.Fatalf("fixture check: invalid session option was not refused before dispatch: %d", code)
			}
		})
	}
}
