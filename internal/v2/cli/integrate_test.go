package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
)

func TestCommandSurface(t *testing.T) {
	// This independent legacy inventory must not shrink to match a dispatcher.
	groups := strings.Fields("init store archive decisions plugin org config event state settings brief lane judge disk doctor start ticket service report dashboard ledger refusal tool box")
	for _, group := range groups {
		found := false
		for path, integrateCommand := range integrateCommands {
			if strings.Split(path, " ")[0] == group && integrateCommand.run != nil {
				found = true
			}
		}
		if !found {
			t.Fatalf("legacy command group missing: %s", group)
		}
	}
	for method := range api.Methods {
		path := strings.ReplaceAll(string(method), ".", " ")
		integrateCommand, exists := integrateCommands[path]
		if !exists || integrateCommand.method != method || integrateCommand.run == nil {
			t.Fatalf("typed CLI route missing: %s", method)
		}
	}
}

type integrateFixtureClient struct {
	requests []api.Request
	closed   int
	handle   func(api.Request) (any, error)
}

func (c *integrateFixtureClient) Call(_ context.Context, request api.Request) (api.Response, error) {
	if _, err := client.PrepareRequest(request); err != nil {
		return api.Response{}, err
	}
	c.requests = append(c.requests, request)
	result, err := c.handle(request)
	if err != nil {
		return api.Response{}, err
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return api.Response{}, err
	}
	return api.Response{Protocol: api.Protocol, Schema: api.SchemaVersion, RequestID: request.RequestID, Result: raw}, nil
}
func (c *integrateFixtureClient) Stream(context.Context, api.Request) (api.EventStream, error) {
	return nil, api.NotImplemented("fixture", "stream")
}
func (c *integrateFixtureClient) Close() error { c.closed++; return nil }

func integrateFixtureFile(t *testing.T, directory, name string, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestInvokeReusesHumanReadConnection(t *testing.T) {
	// Proofs bind the final wire protocol/schema, including client defaults.
	digest, err := api.RequestDigest(api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion,
		Config: "demo", Method: "human.session", Params: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	proof := api.ProofRef{ID: "proof-for-session", RequestSHA256: digest, ExpiresAt: "2026-01-01T00:02:00Z"}
	proofFile := integrateFixtureFile(t, t.TempDir(), "proof.json", proof)
	hasSession := false
	transport := &integrateFixtureClient{}
	transport.handle = func(request api.Request) (any, error) {
		switch request.Method {
		case "human.session":
			if request.Proof == nil || request.Proof.ID != proof.ID {
				return nil, &api.Error{Code: api.CodeForbidden}
			}
			hasSession = true
			return api.HumanSession{ID: "connection-session", Config: request.Config}, nil
		case "store.verify":
			if !hasSession || transport.closed != 0 || request.Proof != nil {
				return nil, &api.Error{Code: api.CodeForbidden}
			}
			return api.Verification{OK: hasSession, Objects: uint64(len(transport.requests)), Problems: []string{}}, nil
		}
		return nil, &api.Error{Code: api.CodeInvalid}
	}
	var output bytes.Buffer
	call := Invocation{Config: "demo", Method: "store.verify", ProofFile: proofFile, Stdout: &output,
		integrateSocket: &integrateSocket{options: client.Options{Config: "demo"}, connection: transport}}
	if err := call.Invoke(context.Background(), api.VerifyRequest{Scope: "store"}); err != nil {
		t.Fatal(err)
	}
	call.ProofFile = "" // The same open connection retains its read authority.
	if err := call.Invoke(context.Background(), api.VerifyRequest{Scope: "store"}); err != nil {
		t.Fatal(err)
	}
	if len(transport.requests) != 3 || transport.requests[0].Method != "human.session" || transport.requests[1].Method != "store.verify" || transport.requests[2].Method != "store.verify" || transport.closed != 0 {
		t.Fatal("calls reopened/closed a connection or failed to establish its read session")
	}
	first, err := integrateSessionRequest("demo", proof)
	if err != nil {
		t.Fatal(err)
	}
	second, err := integrateSessionRequest("demo", proof)
	if err != nil || first.IdempotencyKey != second.IdempotencyKey {
		t.Fatal("session retry changed its key")
	}
	proof.RequestSHA256 = api.Digest(strings.Repeat("0", 64))
	if _, err := integrateSessionRequest("demo", proof); err == nil {
		t.Fatal("unrelated proof established a browsing session")
	}
}

func TestProofBoundContentReference(t *testing.T) {
	directory := t.TempDir()
	ref := api.BlobRef{ID: "committed-input", SHA256: api.Digest(strings.Repeat("1", 64)), Bytes: 21, Class: "record"}
	refFile := integrateFixtureFile(t, directory, "ref.json", ref)
	for _, method := range []api.Method{"records.append", "decisions.mutate"} {
		t.Run(string(method), func(t *testing.T) {
			var params any = api.RecordAppendRequest{Collection: "observations", Content: ref, RelatedIDs: []api.ID{}}
			args := []string{"--collection", "observations", "--content-ref", refFile}
			if method == "decisions.mutate" {
				params = api.DecisionMutateRequest{Action: "add", Content: ref}
				args = []string{"--action", "add", "--content-ref", refFile}
			}
			raw, err := json.Marshal(params)
			if err != nil {
				t.Fatal(err)
			}
			digest, err := api.RequestDigest(api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion,
				Config: "demo", Method: method, Params: raw})
			if err != nil {
				t.Fatal(err)
			}
			proofFile := integrateFixtureFile(t, directory, string(method)+"-proof.json", api.ProofRef{ID: "exact-proof", RequestSHA256: digest})
			transport := &integrateFixtureClient{handle: func(request api.Request) (any, error) {
				if request.Method != method || request.Proof == nil || request.RequestSHA256 != digest {
					return nil, &api.Error{Code: api.CodeIntegrity}
				}
				return api.Record{ID: "retained-record", Content: ref, Collection: "decisions"}, nil
			}}
			call := Invocation{Config: "demo", Method: method, Path: strings.ReplaceAll(string(method), ".", " "), Args: args, ProofFile: proofFile,
				IdempotencyKey: api.ID(strings.Repeat("k", 32)), Stdout: io.Discard,
				integrateSocket: &integrateSocket{options: client.Options{Config: "demo"}, connection: transport}}
			if method == "decisions.mutate" {
				err = integrateRunDecisionsMutate(context.Background(), call)
			} else {
				err = integrateRunRecordsAppend(context.Background(), call)
			}
			if err != nil || len(transport.requests) != 1 {
				t.Fatalf("committed reference required an unknowable upload ID: %v", err)
			}
		})
	}
	call := Invocation{ProofFile: "proof.json"}
	if _, err := integrateRecordContent(context.Background(), &call, "unopened-input", ""); err == nil {
		t.Fatal("inline upload accepted a pre-existing operation proof")
	}
}

func TestContentReadSession(t *testing.T) {
	digest, err := api.RequestDigest(api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: "demo", Method: "human.session", Params: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	proofFile := integrateFixtureFile(t, t.TempDir(), "session.json", api.ProofRef{ID: "read-proof", RequestSHA256: digest})
	session := false
	transport := &integrateFixtureClient{handle: func(request api.Request) (any, error) {
		switch request.Method {
		case "human.session":
			if request.Proof == nil || request.Proof.RequestSHA256 != digest {
				return nil, &api.Error{Code: api.CodeForbidden}
			}
			session = true
			return api.HumanSession{ID: "read-session", Config: request.Config}, nil
		case "records.get":
			if !session || request.Proof != nil {
				return nil, &api.Error{Code: api.CodeForbidden}
			}
			var body api.RecordGetRequest
			if err := api.DecodeObject(request.Params, &body); err != nil {
				return nil, err
			}
			return api.Record{ID: body.RecordID, Collection: "observations"}, nil
		}
		return nil, &api.Error{Code: api.CodeInvalid}
	}}
	var output bytes.Buffer
	call := Invocation{Config: "demo", Method: "records.get", ProofFile: proofFile, Stdout: &output,
		integrateSocket: &integrateSocket{options: client.Options{Config: "demo"}, connection: transport}}
	if err := call.Invoke(context.Background(), api.RecordGetRequest{RecordID: "visible-record"}); err != nil {
		t.Fatalf("content read did not establish its session: %v", err)
	}
	var record api.Record
	if err := api.DecodeObject(output.Bytes(), &record); err != nil || record.ID != "visible-record" || len(transport.requests) != 2 || transport.requests[0].Method != "human.session" || transport.requests[1].Method != "records.get" || transport.closed != 0 {
		t.Fatal("content read lost its connection, request or result")
	}
}

func TestBlobStagingSession(t *testing.T) {
	digest, err := api.RequestDigest(api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: "demo", Method: "human.session", Params: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	proofFile := integrateFixtureFile(t, t.TempDir(), "session.json", api.ProofRef{ID: "staging-session-proof", RequestSHA256: digest})
	session := false
	transport := &integrateFixtureClient{handle: func(request api.Request) (any, error) {
		switch request.Method {
		case "human.session":
			if request.Proof == nil || request.Proof.RequestSHA256 != digest {
				return nil, &api.Error{Code: api.CodeForbidden}
			}
			session = true
			return api.HumanSession{ID: "staging-session", Config: request.Config}, nil
		case "blob.begin":
			if !session || request.Proof != nil {
				return nil, &api.Error{Code: api.CodeForbidden}
			}
			return api.BlobUpload{ObjectID: request.IdempotencyKey, MaxChunkBytes: api.MaxChunkBytes}, nil
		}
		return nil, &api.Error{Code: api.CodeInvalid}
	}}
	call := Invocation{Config: "demo", Method: "blob.begin", ProofFile: proofFile, Stdout: io.Discard, IdempotencyKey: api.ID(strings.Repeat("s", 32)),
		integrateSocket: &integrateSocket{options: client.Options{Config: "demo"}, connection: transport}}
	if err := call.Invoke(context.Background(), api.BlobBeginRequest{Class: "record", Bytes: 4, SHA256: api.Digest(strings.Repeat("1", 64))}); err != nil {
		t.Fatalf("blob staging did not establish its session: %v", err)
	}
	if len(transport.requests) != 2 || transport.requests[0].Method != "human.session" || transport.requests[1].Method != "blob.begin" || transport.closed != 0 {
		t.Fatal("blob staging lost its shared connection or method")
	}
}

func TestUploadRetainsCallerKey(t *testing.T) {
	key := api.ID(strings.Repeat("k", 32))
	first, err := integrateUploadKey(key, "blob.begin")
	if err != nil {
		t.Fatal(err)
	}
	second, err := integrateUploadKey(key, "blob.begin")
	if err != nil || first != second {
		t.Fatal("upload retry changed its durable begin identity")
	}
	chunk, err := integrateUploadKey(key, "blob.chunk")
	if err != nil || chunk == first {
		t.Fatal("different upload effects share an identity")
	}
	changed, err := integrateUploadKey(api.ID(strings.Repeat("j", 32)), "blob.begin")
	if err != nil || changed == first {
		t.Fatal("different caller intents share an upload identity")
	}
	var typed *api.Error
	if _, err := integrateUploadKey("", "blob.begin"); !errors.As(err, &typed) || typed.Code != api.CodeInvalid {
		t.Fatal("upload minted a new mutation key")
	}
}

func TestBindingConflictIsInert(t *testing.T) {
	// Tests run in their own disposable process, never the active lane shell.
	t.Setenv("LANEBOSS_CONFIG", "bound-scope")
	var out, errout bytes.Buffer
	code := Run([]string{"records", "query", "--config", "other-scope", "--collection", "observations"}, nil, &out, &errout)
	var typed api.Error
	if err := json.Unmarshal(errout.Bytes(), &typed); err != nil {
		t.Fatal(err)
	}
	if code != 2 || typed.Code != api.CodeConflict || out.Len() != 0 {
		t.Fatal("conflicting binding reached an operation")
	}
	if strings.Contains(errout.String(), "bound-scope") || strings.Contains(errout.String(), "other-scope") {
		t.Fatal("binding values leaked")
	}
	if os.Getenv("LANEBOSS_CONFIG") != "bound-scope" {
		t.Fatal("client changed its process binding")
	}
}

func TestInvalidRequestStaysLocal(t *testing.T) {
	t.Setenv("LANEBOSS_CONFIG", "demo")
	directory := t.TempDir()
	for name, body := range map[string]string{
		"unknown":   `{"record_id":"one","actor":"human"}`,
		"duplicate": `{"record_id":"one","record_id":"two"}`,
		"null":      `{"record_id":null}`,
		"missing":   `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(directory, name+".json")
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			var out, errout bytes.Buffer
			code := Run([]string{"records", "get", "--config", "demo", "--request", path}, nil, &out, &errout)
			var typed api.Error
			if err := json.Unmarshal(errout.Bytes(), &typed); err != nil {
				t.Fatal(err)
			}
			if code != 2 || typed.Code != api.CodeInvalid || out.Len() != 0 {
				t.Fatal("invalid input reached transport or produced output")
			}
		})
	}
}

func TestFileInputHook(t *testing.T) {
	t.Setenv("LANEBOSS_CONFIG", "demo")
	// This is the common-hook fixture for the guidance adapter, which is a
	// stub in this isolated lane. The combined tree must register and exercise
	// lbV2GuidanceFileRequest itself in TestCLIRejectsMalformedFile as well.
	// A valid request must proceed: the fixture is not an unconditional error.
	integrateInputChecks.Lock()
	previous := integrateInputChecks.methods["guidance.select"]
	previousUnavailable, wasUnavailable := integrateNoFileInput["guidance.select"]
	delete(integrateInputChecks.methods, "guidance.select")
	integrateNoFileInput["guidance.select"] = "lb-v2-guidance"
	integrateInputChecks.Unlock()
	t.Cleanup(func() {
		integrateInputChecks.Lock()
		defer integrateInputChecks.Unlock()
		delete(integrateInputChecks.methods, "guidance.select")
		delete(integrateNoFileInput, "guidance.select")
		if previous != nil {
			integrateInputChecks.methods["guidance.select"] = previous
		}
		if wasUnavailable {
			integrateNoFileInput["guidance.select"] = previousUnavailable
		}
	})
	validator := previous
	if validator == nil {
		validator = func(raw json.RawMessage) error {
			var request api.GuidanceRequest
			if err := api.DecodeObject(raw, &request); err != nil {
				return err
			}
			if request.Target.LifeID == "" || request.Target.Run == 0 || request.LogicalTurnID == "" ||
				request.Task.ID == "" || request.Task.Class != "task" || request.Task.Bytes < 0 || request.Task.Bytes > api.MaxObjectBytes {
				return &api.Error{Code: api.CodeInvalid, Owner: "lb-v2-guidance", Message: "invalid guidance target or task reference"}
			}
			return nil
		}
	}
	directory := t.TempDir()
	key, err := client.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	valid := api.GuidanceRequest{Target: api.LifeRef{LifeID: "life", Run: 1}, LogicalTurnID: "turn",
		Task: api.BlobRef{ID: "task", SHA256: api.Digest(strings.Repeat("1", 64)), Bytes: 3, Class: "task"}}
	t.Run("unregistered", func(t *testing.T) {
		path := integrateFixtureFile(t, directory, "unregistered.json", valid)
		var out, errout bytes.Buffer
		code := Run([]string{"guidance", "select", "--config", "demo", "--request", path,
			"--idempotency-key", string(key), "--binding", filepath.Join(directory, "missing-binding.json")}, nil, &out, &errout)
		var typed api.Error
		if err := json.Unmarshal(errout.Bytes(), &typed); err != nil {
			t.Fatal(err)
		}
		if code != 69 || typed.Code != api.CodeNotImplemented || typed.Owner != "lb-v2-guidance" ||
			typed.Message != api.NotImplemented("lb-v2-guidance", "guidance.select input validator").Message || out.Len() != 0 {
			t.Fatalf("unregistered file input reached transport: exit=%d error=%+v", code, typed)
		}
	})
	if err := RegisterInputValidator("guidance.select", "lb-v2-guidance", validator); err != nil {
		t.Fatal(err)
	}
	t.Run("registration", func(t *testing.T) {
		for _, name := range []string{"nil", "foreign_owner", "duplicate"} {
			t.Run(name, func(t *testing.T) {
				integrateInputChecks.Lock()
				retained := integrateInputChecks.methods["guidance.select"]
				if name != "duplicate" {
					delete(integrateInputChecks.methods, "guidance.select")
				}
				integrateInputChecks.Unlock()
				t.Cleanup(func() {
					integrateInputChecks.Lock()
					defer integrateInputChecks.Unlock()
					integrateInputChecks.methods["guidance.select"] = retained
				})
				owner, check := "lb-v2-guidance", validator
				message := "input validator must belong to its catalog method"
				if name == "nil" {
					check = nil
				}
				if name == "foreign_owner" {
					owner = "lb-v2-integrate"
				}
				if name == "duplicate" {
					message = "duplicate input validator"
				}
				var typed *api.Error
				if err := RegisterInputValidator("guidance.select", owner, check); !errors.As(err, &typed) || typed.Code != api.CodeInvalid || typed.Message != message {
					t.Fatalf("invalid validator registration was accepted: %v", err)
				}
			})
		}
	})
	t.Run("guidance", func(t *testing.T) {
		for name, change := range map[string]func(*api.GuidanceRequest){
			"class":    func(r *api.GuidanceRequest) { r.Task.Class = "policy" },
			"run":      func(r *api.GuidanceRequest) { r.Target.Run = 0 },
			"negative": func(r *api.GuidanceRequest) { r.Task.Bytes = -1 },
			"large":    func(r *api.GuidanceRequest) { r.Task.Bytes = api.MaxObjectBytes + 1 },
		} {
			request := valid
			change(&request)
			path := integrateFixtureFile(t, directory, name+".json", request)
			var out, errout bytes.Buffer
			code := Run([]string{"guidance", "select", "--config", "demo", "--request", path,
				"--idempotency-key", string(key), "--binding", filepath.Join(directory, "missing-binding.json")}, nil, &out, &errout)
			var typed api.Error
			if err := json.Unmarshal(errout.Bytes(), &typed); err != nil {
				t.Fatal(err)
			}
			if code != 2 || typed.Code != api.CodeInvalid || typed.Owner != "lb-v2-guidance" ||
				typed.Message != "invalid guidance target or task reference" || out.Len() != 0 {
				t.Fatalf("owned guidance validation did not precede transport (%s): exit=%d error=%+v", name, code, typed)
			}
		}
	})
	t.Run("records", func(t *testing.T) {
		path := integrateFixtureFile(t, directory, "record.json", api.RecordGetRequest{RecordID: "bad/id"})
		var out, errout bytes.Buffer
		code := Run([]string{"records", "get", "--config", "demo", "--request", path,
			"--binding", filepath.Join(directory, "missing-binding.json")}, nil, &out, &errout)
		var typed api.Error
		if err := json.Unmarshal(errout.Bytes(), &typed); err != nil {
			t.Fatal(err)
		}
		if code != 2 || typed.Code != api.CodeInvalid || typed.Owner != "lb-v2-integrate" || typed.Message != "invalid record ID" || out.Len() != 0 {
			t.Fatalf("owned record validation did not precede transport: exit=%d error=%+v", code, typed)
		}
	})
	transport := &integrateFixtureClient{handle: func(request api.Request) (any, error) {
		var received api.GuidanceRequest
		if err := api.DecodeObject(request.Params, &received); err != nil || received != valid {
			return nil, &api.Error{Code: api.CodeIntegrity, Message: "validated bytes changed"}
		}
		return api.Guidance{Target: received.Target, Task: received.Task, LogicalTurnID: received.LogicalTurnID,
			JudgmentIDs: []api.ID{}, Items: []api.GuidanceItem{}, Status: "unavailable"}, nil
	}}
	call := Invocation{Config: "demo", Method: "guidance.select", IdempotencyKey: key, Stdout: io.Discard,
		integrateSocket: &integrateSocket{options: client.Options{Config: "demo"}, connection: transport}}
	raw, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	if err := call.InvokeRaw(context.Background(), raw); err != nil || len(transport.requests) != 1 {
		t.Fatalf("valid semantic input did not reach the shared socket: %v", err)
	}
	content := valid.Task
	content.ID, content.Class = "record-content", "record"
	appendInput := api.RecordAppendRequest{Collection: "observations", Content: content, RelatedIDs: []api.ID{}}
	t.Run("append", func(t *testing.T) {
		bad := appendInput
		bad.Collection = "unknown"
		path := integrateFixtureFile(t, directory, "bad-append.json", bad)
		var out, errout bytes.Buffer
		code := Run([]string{"records", "append", "--config", "demo", "--request", path,
			"--idempotency-key", string(key), "--binding", filepath.Join(directory, "missing-binding.json")}, nil, &out, &errout)
		var typed api.Error
		if err := json.Unmarshal(errout.Bytes(), &typed); err != nil {
			t.Fatal(err)
		}
		if code != 2 || typed.Code != api.CodeInvalid || typed.Owner != "lb-v2-integrate" || typed.Message != "unknown record collection" || out.Len() != 0 {
			t.Fatalf("owned append validation did not precede transport: exit=%d error=%+v", code, typed)
		}
	})
	t.Run("decision", func(t *testing.T) {
		path := integrateFixtureFile(t, directory, "bad-decision.json", api.DecisionMutateRequest{Action: "annotate", ExpectedGeneration: 1, Content: content})
		var out, errout bytes.Buffer
		code := Run([]string{"decisions", "mutate", "--config", "demo", "--request", path,
			"--idempotency-key", string(key), "--binding", filepath.Join(directory, "missing-binding.json")}, nil, &out, &errout)
		var typed api.Error
		if err := json.Unmarshal(errout.Bytes(), &typed); err != nil {
			t.Fatal(err)
		}
		if code != 2 || typed.Code != api.CodeInvalid || typed.Owner != "lb-v2-integrate" || typed.Message != "decision change requires a canonical decision and base generation" || out.Len() != 0 {
			t.Fatalf("owned decision validation did not precede transport: exit=%d error=%+v", code, typed)
		}
	})
	t.Run("append_forward", func(t *testing.T) {
		path := integrateFixtureFile(t, directory, "append.json", appendInput)
		transport := &integrateFixtureClient{handle: func(request api.Request) (any, error) {
			var received api.RecordAppendRequest
			if err := api.DecodeObject(request.Params, &received); err != nil || request.Method != "records.append" ||
				received.Collection != appendInput.Collection || received.Content != content || len(received.RelatedIDs) != 0 {
				return nil, &api.Error{Code: api.CodeIntegrity, Message: "validated append bytes changed"}
			}
			return api.Record{ID: request.IdempotencyKey, Collection: received.Collection, Content: received.Content}, nil
		}}
		call := Invocation{Config: "demo", Path: "records append", Method: "records.append", IdempotencyKey: key, Stdout: io.Discard,
			integrateSocket: &integrateSocket{options: client.Options{Config: "demo"}, connection: transport}}
		// This is the exact file-reading path used by Run's --request branch.
		if err := call.invokeFile(context.Background(), path); err != nil || len(transport.requests) != 1 {
			t.Fatalf("valid file append did not reach the shared socket: %v", err)
		}
	})
}

func TestAliasCannotChangeIntent(t *testing.T) {
	for _, row := range []struct {
		path   string
		params any
	}{
		{"event append", &api.RecordAppendRequest{Collection: "ledger"}},
		{"decisions search", &api.RecordQuery{Collection: "tools"}},
		{"decisions annotate", &api.DecisionMutateRequest{Action: "add"}},
		{"config path", &api.ConfigReadRequest{View: "plugins"}},
	} {
		if err := integrateValidateAlias(Invocation{Path: row.path}, row.params); err == nil {
			t.Fatalf("conflicting intent accepted for %s", row.path)
		}
	}
}

func TestUnknownFlagDoesNotWrite(t *testing.T) {
	t.Setenv("LANEBOSS_CONFIG", "demo")
	var out, errout bytes.Buffer
	code := Run([]string{"records", "query", "--config", "demo", "--db", "never-open.sqlite"}, nil, &out, &errout)
	var typed api.Error
	if err := json.Unmarshal(errout.Bytes(), &typed); err != nil {
		t.Fatal(err)
	}
	if code != 2 || typed.Code != api.CodeInvalid || out.Len() != 0 {
		t.Fatal("legacy database flag was forwarded")
	}
}

func TestSelectedRunEnd(t *testing.T) {
	request := api.EventTailRequest{LifeID: "child", Run: 2, Since: 10, Until: "lane.ended"}
	event := api.Event{LifeID: "child", Run: 2, Seq: 11, Kind: "lane.ended", Origin: "service"}
	if !integrateSelectedEnd(event, request) {
		t.Fatal("selected authentic end was missed")
	}
	for name, mutate := range map[string]func(*api.Event){
		"old run":      func(e *api.Event) { e.Run = 1 },
		"sibling":      func(e *api.Event) { e.LifeID = "sibling" },
		"old sequence": func(e *api.Event) { e.Seq = 10 },
		"observation":  func(e *api.Event) { e.Origin = "observation" },
		"wrong kind":   func(e *api.Event) { e.Kind = "record.appended" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := event
			mutate(&changed)
			if integrateSelectedEnd(changed, request) {
				t.Fatal("unrelated event ended follow")
			}
		})
	}
}

func TestMalformedResponseIsNotSuccess(t *testing.T) {
	var out bytes.Buffer
	call := Invocation{Method: "records.get", Stdout: &out}
	request := api.Request{RequestID: "request-one"}
	for _, raw := range []string{`null`, `{}`, `{"id":"constant"}`} {
		response := api.Response{Protocol: api.Protocol, Schema: 2, RequestID: request.RequestID, Result: json.RawMessage(raw)}
		if err := call.integrateWriteResponse(request, response); err == nil {
			t.Fatal("incomplete result was accepted")
		}
		if out.Len() != 0 {
			t.Fatal("invalid response was written as success")
		}
	}
}
