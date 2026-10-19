package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
	"laneboss.io/laneboss/internal/v2/migration"
)

func TestCLIMigrationCommands(t *testing.T) {
	tmp := t.TempDir()
	if err := os.Chmod(tmp, 0o700); err != nil {
		t.Fatal(err)
	}

	// 1. Unknown flag and missing input file must return exit 2 (invalid_request).
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"plan-unknown-flag", []string{"migration", "plan", "--config", "demo", "--bad-flag"}},
		{"plan-no-input", []string{"migration", "plan", "--config", "demo"}},
		{"plan-db-disallowed", []string{"migration", "plan", "--config", "demo", "--db", filepath.Join(tmp, "d.db")}},
		{"decisions-db-needs-frozen-inputs", []string{"decisions", "migrate", "--config", "demo", "--db", filepath.Join(tmp, "d.db")}},
		{"apply-unknown-flag", []string{"migration", "apply", "--config", "demo", "--bad-flag"}},
		{"apply-no-input", []string{"migration", "apply", "--config", "demo"}},
		{"apply-bad-id", []string{"migration", "apply", "--config", "demo", "--plan-id", "bad/id"}},
		{"apply-needs-retained-key", []string{"migration", "apply", "--config", "demo", "--plan-id", "migplan-valid"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errBuf bytes.Buffer
			code := Run(tc.args, strings.NewReader(""), &out, &errBuf)
			if code != 2 {
				t.Fatalf("expected exit 2, got %d (stderr=%s)", code, errBuf.String())
			}
			var apiErr api.Error
			if err := json.Unmarshal(errBuf.Bytes(), &apiErr); err != nil || apiErr.Code != api.CodeInvalid {
				t.Fatalf("expected invalid_request error, got %+v (%v)", apiErr, err)
			}
		})
	}

	// 2. Symlink manifest file must be rejected locally (exit 2).
	realReqPath := filepath.Join(tmp, "plan-req.json")
	reqObj := api.MigrationPlanRequest{
		SourceVersion: "0.7.0",
		SourceManifest: api.BlobRef{
			ID:     "blob-man-1",
			SHA256: migration.DigestBytes([]byte("{}")),
			Bytes:  2,
			Class:  "manifest",
		},
	}
	reqBytes, err := migration.CanonicalJCS(reqObj)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(realReqPath, reqBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	symReqPath := filepath.Join(tmp, "sym-req.json")
	if err := os.Symlink(realReqPath, symReqPath); err != nil {
		t.Fatal(err)
	}
	{
		var out, errBuf bytes.Buffer
		code := Run([]string{"migration", "plan", "--config", "demo", "--manifest", symReqPath, "--idempotency-key", "fixture-upload-key-00000001"}, strings.NewReader(""), &out, &errBuf)
		if code != 2 || !strings.Contains(errBuf.String(), "non-symlink") {
			t.Fatalf("expected symlink manifest refusal at the file-open gate, got %d: %s", code, errBuf.String())
		}
	}
	refPath := filepath.Join(tmp, "manifest-ref.json")
	refBytes, err := json.Marshal(reqObj.SourceManifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(refPath, refBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	sessionDigest, err := api.RequestDigest(api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: "demo", Method: "human.session", Params: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	proofPath := filepath.Join(tmp, "session-proof.json")
	proofBytes, err := json.Marshal(api.ProofRef{ID: "session-proof", RequestSHA256: sessionDigest, ExpiresAt: "2026-10-17T00:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(proofPath, proofBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	proofLink := filepath.Join(tmp, "session-proof-link.json")
	if err := os.Symlink(proofPath, proofLink); err != nil {
		t.Fatal(err)
	}
	{
		var out, errBuf bytes.Buffer
		code := Run([]string{"migration", "plan", "--config", "demo", "--content-ref", refPath, "--source-version", "0.7.0", "--proof", proofLink}, strings.NewReader(""), &out, &errBuf)
		if code != 2 || !strings.Contains(errBuf.String(), "non-symlink") {
			t.Fatalf("expected proof symlink refusal before transport, got %d: %s", code, errBuf.String())
		}
	}

	// Valid requests reach an injected connection, independently of installed
	// bindings or any other lane's current stub/host implementation.
	cases := []struct {
		name   string
		path   string
		method api.Method
		args   []string
		file   string
		proof  string
	}{
		{"valid-plan", "migration plan", "migration.plan", nil, realReqPath, ""},
		{"valid-decisions-migrate", "decisions migrate", "migration.plan", []string{"--content-ref", refPath, "--source-version", "0.7.0"}, "", ""},
		{"committed-plan-with-session-proof", "migration plan", "migration.plan", []string{"--content-ref", refPath, "--source-version", "0.7.0"}, "", proofPath},
		{"valid-apply", "migration apply", "migration.apply", []string{"--plan-id", "migplan-1234"}, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, rpcError := range []bool{false, true} {
				name := "transport-error"
				if rpcError {
					name = "rpc-error"
				}
				t.Run(name, func(t *testing.T) {
					failure := &api.Error{Code: api.CodeUnavailable, Message: "controlled migration CLI dependency failure",
						Instead: "Repair the injected CLI dependency.", Retryable: true, OperationID: "fixture-operation", Owner: "lb-v2-migration-fixture"}
					wantFailure := *failure
					dependency := &migrationFixtureRPC{failure: failure, rpcError: rpcError, plan: reqObj,
						apply: api.MigrationApplyRequest{PlanID: "migplan-1234"}}
					if tc.proof != "" {
						dependency.sessionProof = &api.ProofRef{ID: "session-proof", RequestSHA256: sessionDigest, ExpiresAt: "2026-10-17T00:00:00Z"}
					}
					var out, errout bytes.Buffer
					call := Invocation{Path: tc.path, Config: "demo", Method: tc.method, Args: tc.args,
						Stdout: &out, Stderr: &errout, ProofFile: tc.proof, IdempotencyKey: "fixture-apply-key-00000001",
						integrateSocket: &integrateSocket{options: client.Options{Config: "demo"}, connection: dependency}}
					var err error
					if tc.file != "" {
						err = call.invokeFile(context.Background(), tc.file)
					} else if tc.method == "migration.plan" {
						err = runMigrationPlan(context.Background(), call)
					} else {
						err = runMigrationApply(context.Background(), call)
					}
					if err != failure {
						t.Fatalf("migration CLI changed the injected typed error or missed its RPC boundary: got %v, want %+v", err, failure)
					}
					if code := integrateFailure(&errout, err); code != 69 {
						t.Fatalf("typed unavailable error mapped to exit %d", code)
					}
					var encoded api.Error
					if err := api.DecodeObject(errout.Bytes(), &encoded); err != nil || encoded != wantFailure || *failure != wantFailure || out.Len() != 0 {
						t.Fatalf("CLI changed its dependency error fields or printed success: %+v, %v", encoded, err)
					}
					want := []api.Method{tc.method}
					if tc.proof != "" {
						want = []api.Method{"human.session", tc.method}
					}
					var got []api.Method
					for _, request := range dependency.requests {
						got = append(got, request.Method)
					}
					if !reflect.DeepEqual(got, want) || dependency.closed != 0 {
						t.Fatalf("unexpected migration RPC order or connection ownership: %v, closed=%d", got, dependency.closed)
					}
				})
			}
		})
	}
}

type migrationFixtureRPC struct {
	failure      *api.Error
	rpcError     bool
	plan         api.MigrationPlanRequest
	apply        api.MigrationApplyRequest
	sessionProof *api.ProofRef
	sessionOpen  bool
	requests     []api.Request
	closed       int
}

func (fixture *migrationFixtureRPC) Call(_ context.Context, request api.Request) (api.Response, error) {
	if _, err := client.PrepareRequest(request); err != nil {
		return api.Response{}, err
	}
	fixture.requests = append(fixture.requests, request)
	invalid := func() (api.Response, error) {
		return api.Response{}, &api.Error{Code: api.CodeIntegrity, Message: "migration CLI submitted an unexpected fixture request", Owner: "lb-v2-migration-fixture"}
	}
	if request.Config != "demo" || fixture.closed != 0 {
		return invalid()
	}
	response := api.Response{Protocol: api.Protocol, Schema: api.SchemaVersion, RequestID: request.RequestID}
	switch request.Method {
	case "human.session":
		if fixture.sessionProof == nil || request.Proof == nil || *request.Proof != *fixture.sessionProof || string(request.Params) != "{}" || fixture.sessionOpen {
			return invalid()
		}
		fixture.sessionOpen = true
		var err error
		response.Result, err = json.Marshal(api.HumanSession{ID: "fixture-session", Config: request.Config,
			ExpiresAt: fixture.sessionProof.ExpiresAt, IdleExpiresAt: fixture.sessionProof.ExpiresAt})
		return response, err
	case "migration.plan":
		var body api.MigrationPlanRequest
		if err := api.DecodeObject(request.Params, &body); err != nil || body != fixture.plan || request.Proof != nil ||
			fixture.sessionProof != nil && !fixture.sessionOpen {
			return invalid()
		}
	case "migration.apply":
		var body api.MigrationApplyRequest
		if err := api.DecodeObject(request.Params, &body); err != nil || body != fixture.apply || request.IdempotencyKey != "fixture-apply-key-00000001" {
			return invalid()
		}
	default:
		return invalid()
	}
	if fixture.rpcError {
		response.Error = fixture.failure
		return response, nil
	}
	return api.Response{}, fixture.failure
}

func (fixture *migrationFixtureRPC) Stream(context.Context, api.Request) (api.EventStream, error) {
	return nil, &api.Error{Code: api.CodeIntegrity, Message: "migration fixture received an unexpected stream", Owner: "lb-v2-migration-fixture"}
}

func (fixture *migrationFixtureRPC) Close() error {
	fixture.closed++
	return nil
}

func TestCLIMigrationFileInputValidation(t *testing.T) {
	directory := t.TempDir()
	valid := api.MigrationPlanRequest{SourceVersion: "0.7.0", SourceManifest: api.BlobRef{
		ID: "manifest-object", SHA256: migration.DigestBytes([]byte("{}")), Bytes: 2, Class: "manifest"}}
	for _, path := range []string{"migration plan", "decisions migrate"} {
		for _, name := range []string{"version", "id", "digest", "negative-bytes", "large-bytes", "class"} {
			t.Run(path+"/"+name, func(t *testing.T) {
				request := valid
				message := ""
				switch name {
				case "version":
					request.SourceVersion, message = "0.5.0", "unsupported source_version"
				case "id":
					request.SourceManifest.ID, message = "bad/id", "blob reference id is invalid"
				case "digest":
					request.SourceManifest.SHA256, message = "invalid", "blob reference sha256 must be 64 lowercase hex digits"
				case "negative-bytes":
					request.SourceManifest.Bytes, message = -1, "blob reference bytes out of bounds"
				case "large-bytes":
					request.SourceManifest.Bytes, message = api.MaxObjectBytes+1, "blob reference bytes out of bounds"
				case "class":
					request.SourceManifest.Class, message = "task", "blob reference class must be manifest"
				}
				migrationAssertInvalidFile(t, directory, path, request, message)
			})
		}
	}
	for _, id := range []api.ID{"", "bad/id"} {
		t.Run("migration apply/"+string(id), func(t *testing.T) {
			migrationAssertInvalidFile(t, directory, "migration apply", api.MigrationApplyRequest{PlanID: id},
				"plan_id is required and must be a valid ID")
		})
	}
}

func migrationAssertInvalidFile(t *testing.T, directory, path string, request any, message string) {
	t.Helper()
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(directory, "request.json")
	if err := os.WriteFile(file, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errout bytes.Buffer
	args := append(strings.Fields(path), "--config", "demo", "--request", file,
		"--proof", filepath.Join(directory, "missing-proof.json"),
		"--binding", filepath.Join(directory, "missing-binding.json"))
	code := Run(args, nil, &out, &errout)
	var typed api.Error
	if err := api.DecodeObject(errout.Bytes(), &typed); err != nil {
		t.Fatal(err)
	}
	if code != 2 || typed.Code != api.CodeInvalid || typed.Owner != "lb-v2-migration" || typed.Message != message || out.Len() != 0 {
		t.Fatalf("migration file input missed its semantic gate: exit=%d error=%+v", code, typed)
	}
}
