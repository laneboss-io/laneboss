package service_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	release "laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/cli"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/service"
)

type serviceInputCase struct {
	method  api.Method
	valid   any
	invalid any
	message string
}

func inputID(t *testing.T) api.ID {
	t.Helper()
	id, err := wire.NewID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func serviceInputCases(t *testing.T) []serviceInputCase {
	t.Helper()
	data := []byte(inputID(t))
	sum, other := sha256.Sum256(data), sha256.Sum256(append([]byte("changed"), data...))
	digest, changed := api.Digest(hex.EncodeToString(sum[:])), api.Digest(hex.EncodeToString(other[:]))
	ref := api.BlobRef{ID: inputID(t), Class: "manifest", Bytes: int64(len(data)), SHA256: digest}
	badRef := ref
	badRef.Bytes = api.MaxObjectBytes + 1
	artifact, err := wire.ArtifactDigest()
	if err != nil {
		t.Fatal(err)
	}
	return []serviceInputCase{
		{"health", api.HealthRequest{ClientVersion: release.Version, ArtifactSHA256: artifact}, api.HealthRequest{ArtifactSHA256: artifact}, "health requires a client version"},
		{"operation.get", api.OperationGetRequest{OperationID: inputID(t)}, api.OperationGetRequest{}, "invalid object ID"},
		{"blob.begin", api.BlobBeginRequest{Class: "record", Bytes: int64(len(data)), SHA256: digest}, api.BlobBeginRequest{Class: "invented", Bytes: int64(len(data)), SHA256: digest}, "unknown schema enum"},
		{"blob.chunk", api.BlobChunk{ObjectID: ref.ID, Data: data, SHA256: digest}, api.BlobChunk{ObjectID: ref.ID, Data: data, SHA256: changed}, "chunk digest mismatch"},
		{"blob.commit", api.BlobCommitRequest{ObjectID: ref.ID, SHA256: digest}, api.BlobCommitRequest{SHA256: digest}, "invalid object ID"},
		{"blob.read", api.BlobReadRequest{ObjectID: ref.ID, Limit: 1}, api.BlobReadRequest{ObjectID: ref.ID}, "invalid blob read bounds"},
		{"store.verify", api.VerifyRequest{Scope: "all"}, api.VerifyRequest{}, "verification requires a scope"},
		{"store.rebuild", api.RebuildRequest{FrozenSnapshot: ref}, api.RebuildRequest{FrozenSnapshot: badRef}, "rebuild requires a bounded frozen snapshot manifest or archive"},
	}
}

// This list names accepted binding/transport refusal categories, not another
// lane's stub text. No owning-service refusal or invalid_request is transport.
func serviceInputReachedTransport(err api.Error) bool {
	if err.Owner == "lb-v2-service" || err.Code == api.CodeInvalid {
		return false
	}
	switch err.Code {
	case api.CodePrerequisite:
		return err.Message == "protected binding is missing or unsafe"
	case api.CodeUnavailable, api.CodeUnsupported:
		return true
	case api.CodeNotImplemented:
		return err.Owner == "lb-v2-client"
	}
	return false
}

func TestServiceFileInputs(t *testing.T) {
	config := os.Getenv("LANEBOSS_CONFIG")
	if config == "" {
		config = "service-fixture"
	}
	for _, row := range serviceInputCases(t) {
		t.Run(string(row.method), func(t *testing.T) {
			// Selected mutation runs require an observed node for each named
			// ancestor, so form and validity are separate subtests.
			for _, form := range []string{"--request", "--file"} {
				t.Run(form, func(t *testing.T) {
					for _, valid := range []bool{true, false} {
						t.Run(map[bool]string{true: "valid", false: "invalid"}[valid], func(t *testing.T) {
							directory := t.TempDir()
							body := row.invalid
							if valid {
								body = row.valid
							}
							raw, err := json.Marshal(body)
							if err != nil {
								t.Fatal(err)
							}
							// Prove malformed field types are not supplying the semantic red.
							if !valid {
								shape := reflect.New(api.Methods[row.method].Request).Interface()
								if err := api.DecodeObject(raw, shape); err != nil {
									t.Fatal(err)
								}
							}
							path := filepath.Join(directory, "request.json")
							if err := os.WriteFile(path, raw, 0600); err != nil {
								t.Fatal(err)
							}
							args := strings.Split(strings.ReplaceAll(string(row.method), ".", " "), " ")
							args = append(args, "--config", config, form, path, "--binding", filepath.Join(directory, "missing-binding.json"))
							if valid {
								args = append(args, "--idempotency-key", string(inputID(t)), "--request-id", string(inputID(t)))
							} else {
								// Invalid input must win over missing proof, malformed request
								// metadata and the uninstalled binding, without replacing them.
								args = append(args, "--proof", filepath.Join(directory, "missing-proof.json"), "--idempotency-key", "bad/id", "--request-id", "bad/id")
							}
							var output, diagnostic bytes.Buffer
							code := cli.Run(args, nil, &output, &diagnostic)
							var refusal api.Error
							if err := json.Unmarshal(diagnostic.Bytes(), &refusal); err != nil {
								t.Fatal("CLI did not return a typed refusal", err)
							}
							if valid {
								if code != 69 || output.Len() != 0 || !serviceInputReachedTransport(refusal) {
									t.Fatalf("valid service file did not reach transport: %s exit=%d code=%s owner=%s", row.method, code, refusal.Code, refusal.Owner)
								}
							} else if code != 2 || output.Len() != 0 || refusal.Code != api.CodeInvalid || refusal.Owner != "lb-v2-service" || refusal.Message != row.message {
								t.Fatalf("invalid service file bypassed semantic checks: %s exit=%d code=%s owner=%s message=%s", row.method, code, refusal.Code, refusal.Owner, refusal.Message)
							}
						})
					}
				})
			}
		})
	}
}

type unusedInputStore struct{ api.StateStore }
type unusedInputAuth struct{ api.Authenticator }
type inputClock struct{}

func (inputClock) Now() time.Time { return time.Now() }

func TestServiceHandlerInputs(t *testing.T) {
	core, err := service.New(service.Dependencies{Store: &unusedInputStore{}, Authenticator: &unusedInputAuth{}, Clock: inputClock{}})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range serviceInputCases(t) {
		t.Run(string(row.method), func(t *testing.T) {
			ctx, scope := context.Background(), api.Scope{}
			var err error
			switch request := row.invalid.(type) {
			case api.HealthRequest:
				_, err = core.Health(ctx, scope, request)
			case api.OperationGetRequest:
				_, err = core.OperationGet(ctx, scope, request)
			case api.BlobBeginRequest:
				_, err = core.BlobBegin(ctx, scope, request)
			case api.BlobChunk:
				_, err = core.BlobChunk(ctx, scope, request)
			case api.BlobCommitRequest:
				_, err = core.BlobCommit(ctx, scope, request)
			case api.BlobReadRequest:
				_, err = core.BlobRead(ctx, scope, request)
			case api.VerifyRequest:
				_, err = core.StoreVerify(ctx, scope, request)
			case api.RebuildRequest:
				_, err = core.StoreRebuild(ctx, scope, request)
			default:
				t.Fatal("service input fixture has no typed handler")
			}
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeInvalid || typed.Owner != "lb-v2-service" || typed.Message != row.message {
				t.Fatal("typed service handler bypassed shared input validation", err)
			}
		})
	}
}
