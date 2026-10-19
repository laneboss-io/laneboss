package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
)

func TestAdminDoctorFiles(t *testing.T) {
	t.Setenv("LANEBOSS_CONFIG", "admin-case")
	directory := t.TempDir()
	for name, raw := range map[string]string{
		"field":     `{"path":"ignored"}`,
		"duplicate": `{"path":1,"path":2}`,
		"null":      `null`,
		"array":     `[]`,
		"trailing":  `{} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(directory, name+".json")
			if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
			var expected *api.Error
			if err := admin.ValidateDoctorInput(json.RawMessage(raw)); !errors.As(err, &expected) || expected.Code != api.CodeInvalid {
				t.Fatalf("invalid doctor fixture accepted: %v", err)
			}
			var out, errout bytes.Buffer
			code := Run([]string{"doctor", "--config", "admin-case", "--request", path,
				"--proof", filepath.Join(directory, "missing-proof.json"),
				"--request-id", "invalid/key", "--idempotency-key", "invalid/key",
				"--binding", filepath.Join(directory, "missing-binding.json")}, nil, &out, &errout)
			var typed api.Error
			if err := json.Unmarshal(errout.Bytes(), &typed); err != nil {
				t.Fatal(err)
			}
			if code != 2 || typed.Code != api.CodeInvalid || typed.Owner != expected.Owner ||
				typed.Message != expected.Message || typed.Instead != expected.Instead || out.Len() != 0 {
				t.Fatalf("acceptance: doctor invalid input reached later work: exit=%d error=%+v", code, typed)
			}
		})
	}
	t.Run("valid", func(t *testing.T) {
		// RegisterInputValidator checks the catalog owner, but the registry
		// stores only callbacks. A generic api.Empty callback has the same
		// JSON behavior; it does not prove this adapter registered its hook.
		integrateInputChecks.RLock()
		validate := integrateInputChecks.methods["doctor"]
		integrateInputChecks.RUnlock()
		if validate == nil {
			t.Fatal("acceptance: doctor file did not reach transport: validator registration missing")
		}
		method, exists := api.Methods["doctor"]
		entry := reflect.ValueOf(validate).Pointer()
		symbol := runtime.FuncForPC(entry)
		if symbol == nil {
			t.Fatal("acceptance: doctor file did not reach transport: registered callback has no function identity")
		}
		file, line := symbol.FileLine(entry)
		t.Logf("doctor validator owner=%s callback=%s source=%s:%d", method.Owner, symbol.Name(), filepath.Base(file), line)
		if !exists || method.Owner != "lb-v2-admin" ||
			entry != reflect.ValueOf(admin.ValidateDoctorInput).Pointer() {
			t.Fatal("acceptance: doctor file did not reach transport: admin-owned validator registration missing")
		}
		for _, raw := range []string{`{}`, " \n{ }\t\n", `{"path":"ignored"}`, `{"path":1,"path":2}`, `null`, `[]`, `{} {}`, ``} {
			input := json.RawMessage(raw)
			actualErr := validate(append(json.RawMessage(nil), input...))
			expectedErr := admin.ValidateDoctorInput(input)
			if expectedErr == nil {
				if actualErr != nil {
					t.Fatalf("acceptance: doctor file did not reach transport: registered admin validator rejected valid input: %v", actualErr)
				}
				continue
			}
			var actual, expected *api.Error
			if !errors.As(actualErr, &actual) || !errors.As(expectedErr, &expected) || actual.Code != api.CodeInvalid ||
				actual.Code != expected.Code || actual.Owner != expected.Owner || actual.Message != expected.Message || actual.Instead != expected.Instead {
				t.Fatal("acceptance: doctor file did not reach transport: registered admin validator changed its input guard")
			}
		}
		path := filepath.Join(directory, "valid.json")
		if err := os.WriteFile(path, []byte(" \n{ }\t\n"), 0600); err != nil {
			t.Fatal(err)
		}
		var out, errout bytes.Buffer
		code := Run([]string{"doctor", "--config", "admin-case", "--request", path,
			"--binding", filepath.Join(directory, "missing-binding.json")}, nil, &out, &errout)
		var typed api.Error
		if err := json.Unmarshal(errout.Bytes(), &typed); err != nil {
			t.Fatal(err)
		}
		// The isolated client may be unfinished; the composed client refuses
		// the missing protected binding. No other refusal counts as transport.
		allowed := typed.Code == api.CodeNotImplemented || typed.Code == api.CodePrerequisite
		if code != 69 || !allowed || typed.Owner == "lb-v2-admin" || typed.Code == api.CodeInvalid || out.Len() != 0 {
			t.Fatalf("acceptance: doctor file did not reach transport: exit=%d error=%+v", code, typed)
		}
	})
}

func TestAdminDoctorTransport(t *testing.T) {
	directory := t.TempDir()
	raw := []byte(" \n{ }\t\n")
	path := filepath.Join(directory, "doctor.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	health := api.Health{Protocol: api.Protocol, Schema: api.SchemaVersion,
		ServiceVersion: identity.Version, ArtifactSHA256: api.Digest(strings.Repeat("a", 64)), Ready: true,
		Capabilities: []api.Capability{{Name: "input-fixture", Available: true}}}
	transport := &integrateFixtureClient{handle: func(request api.Request) (any, error) {
		if request.Method != "doctor" || request.Config != "admin-case" {
			t.Fatal("doctor adapter changed the method or configuration")
		}
		var input api.Empty
		if err := api.DecodeObject(request.Params, &input); err != nil {
			t.Fatalf("transport received invalid doctor input: %v", err)
		}
		return health, nil
	}}
	var out bytes.Buffer
	call := Invocation{Config: "admin-case", Method: "doctor", Stdout: &out,
		integrateSocket: &integrateSocket{options: client.Options{Config: "admin-case"}, connection: transport}}
	if err := call.invokeFile(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	if len(transport.requests) != 1 || !bytes.Equal(transport.requests[0].Params, raw) {
		t.Fatal("acceptance: doctor file bytes did not reach shared transport unchanged")
	}
	out.Reset()
	call.Args = []string{"--format", "json"}
	if err := runDoctor(context.Background(), call); err != nil {
		t.Fatal(err)
	}
	parsed, err := admin.ParseDoctorHealth(out.Bytes())
	if err != nil || !parsed.Ready || len(transport.requests) != 2 || transport.closed != 0 {
		t.Fatalf("acceptance: ergonomic doctor did not borrow the validated transport: %v", err)
	}
}
