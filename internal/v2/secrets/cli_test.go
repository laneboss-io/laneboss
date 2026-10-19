package secrets_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/cli"
	"laneboss.io/laneboss/internal/v2/client"
	"laneboss.io/laneboss/internal/v2/secrets/testdir"
)

func assertCLIFailure(t *testing.T, args []string, hidden []byte) {
	t.Helper()
	hasKey := false
	for _, arg := range args {
		hasKey = hasKey || arg == "--idempotency-key" || strings.HasPrefix(arg, "--idempotency-key=")
	}
	if !hasKey {
		key, err := client.NewRequestID()
		if err != nil {
			t.Fatal("cannot retain invalid-input control key")
		}
		args = append(append([]string(nil), args...), "--idempotency-key", string(key))
	}
	var stdout, stderr bytes.Buffer
	code := cli.Run(args, bytes.NewReader(nil), &stdout, &stderr)
	var result api.Error
	if err := json.Unmarshal(stderr.Bytes(), &result); code != 2 || stdout.Len() != 0 || err != nil || result.Code != api.CodeInvalid {
		t.Fatal("invalid secret input was not refused before transport")
	}
	if len(hidden) > 0 && bytes.Contains(stderr.Bytes(), hidden) {
		t.Fatal("invalid secret input was echoed into diagnostics")
	}
}

func TestCLIInputRefusals(t *testing.T) {
	var randomness [16]byte
	if _, err := rand.Read(randomness[:]); err != nil {
		t.Fatal("cannot make harmless diagnostic canary")
	}
	canary := hex.EncodeToString(randomness[:])
	for _, args := range [][]string{
		{"secret", "import", "--config", "cli-case"},
		{"secret", "stage", "--config", "cli-case", "--value", canary},
		{"secret", "key", "--config", "cli-case", "--request", "one", "--request", "two"},
		{"secret", "key", "--config", "cli-case", "--unknown=" + canary},
		{"secret", "key", "--config", "cli-case", "positional"},
		{"secret", "list", "--config", "cli-case", "--request="},
	} {
		assertCLIFailure(t, args, []byte(canary))
	}
}

func TestCLIRequestShapes(t *testing.T) {
	for _, content := range []string{
		`{"name":"a","name":"b","version":"one","sealed_upload_id":"s"}`,
		`{"name":"a","version":"one","sealed_upload_id":null}`,
		`{"name":"a","version":"one","sealed_upload_id":"s","value":"untrusted"}`,
		`{"name":"a","version":"one"}`,
	} {
		path := filepath.Join(testdir.New(t), "request.json")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal("cannot retain synthetic request")
		}
		assertCLIFailure(t, []string{"secret", "import", "--config", "cli-case", "--request", path}, nil)
	}
}

func TestCLISemanticRefusal(t *testing.T) {
	key, err := client.NewRequestID()
	if err != nil {
		t.Fatal("cannot retain semantic-control retry key")
	}
	path := filepath.Join(testdir.New(t), "request.json")
	if err := os.WriteFile(path, []byte(`{"name":"*","version":"one","sealed_upload_id":"s"}`), 0600); err != nil {
		t.Fatal("cannot retain synthetic request")
	}
	for _, flag := range []string{"--request", "--input"} {
		assertCLIFailure(t, []string{"secret", "import", "--config", "cli-case", flag, path,
			"--idempotency-key", string(key)}, nil)
	}
}

func TestCLIValidators(t *testing.T) {
	stage := api.SecretStageRequest{KeyID: "key-a", Name: "canary", Version: "one",
		EphemeralPublicKey: make([]byte, 32), Nonce: make([]byte, 12), Ciphertext: make([]byte, 17)}
	badStage := stage
	badStage.Name = "*"
	for _, row := range []struct {
		command        string
		valid, invalid any
	}{
		{"key", api.Empty{}, map[string]any{"extra": 1}},
		{"stage", stage, badStage},
		{"import", api.SecretImportRequest{Name: "canary", Version: "one", SealedUploadID: "stage-a"}, api.SecretImportRequest{Name: "*", Version: "one", SealedUploadID: "stage-a"}},
		{"rotate", api.SecretRotateRequest{Name: "canary", ExpectedVersion: "one", SealedUploadID: "stage-a"}, api.SecretRotateRequest{Name: "*", ExpectedVersion: "one", SealedUploadID: "stage-a"}},
		{"revoke", api.SecretRevokeRequest{Name: "canary", ExpectedVersion: "one"}, api.SecretRevokeRequest{Name: "*", ExpectedVersion: "one"}},
		{"list", api.Empty{}, map[string]any{"extra": 1}},
	} {
		t.Run("secret."+row.command, func(t *testing.T) {
			for _, valid := range []bool{false, true} {
				name := "invalid"
				input := row.invalid
				if valid {
					name, input = "valid", row.valid
				}
				t.Run(name, func(t *testing.T) {
					directory := testdir.New(t)
					path := filepath.Join(directory, "request.json")
					data, err := json.Marshal(input)
					if err != nil {
						t.Fatal("cannot encode semantic CLI input")
					}
					if err := os.WriteFile(path, data, 0600); err != nil {
						t.Fatal("cannot retain semantic CLI input")
					}
					key, err := client.NewRequestID()
					if err != nil {
						t.Fatal("cannot retain semantic CLI retry key")
					}
					args := []string{"secret", row.command, "--config", "cli-case", "--request", path, "--binding", filepath.Join(directory, "missing-binding.json"), "--idempotency-key", string(key)}
					if !valid {
						args = append(args, "--proof", filepath.Join(directory, "missing-proof.json"))
					}
					var out, errOut bytes.Buffer
					code := cli.Run(args, bytes.NewReader(nil), &out, &errOut)
					var failure api.Error
					if err := json.Unmarshal(errOut.Bytes(), &failure); err != nil || out.Len() != 0 {
						t.Fatal("CLI validator did not retain a typed refusal")
					}
					if !valid {
						if code != 2 || failure.Code != api.CodeInvalid {
							t.Fatal("catalog secret input bypassed semantic validation")
						}
						if row.command != "key" && row.command != "list" && failure.Owner != "lb-v2-secrets" {
							t.Fatal("semantic refusal did not come from secrets")
						}
						return
					}
					allowed := map[api.ErrorCode]bool{api.CodeNotImplemented: true, api.CodePrerequisite: true,
						api.CodeUnavailable: true, api.CodeUnauthenticated: true, api.CodeVersion: true}
					if code == 0 || failure.Owner == "lb-v2-secrets" || failure.Code == api.CodeInvalid || !allowed[failure.Code] {
						t.Fatal("valid secret file did not reach the transport or installed binding boundary")
					}
				})
			}
		})
	}
}

func TestCLIProofIntent(t *testing.T) {
	for _, command := range []string{"key", "import"} {
		t.Run(command, func(t *testing.T) {
			directory := testdir.New(t)
			input := []byte(`{}`)
			if command == "import" {
				input = []byte(`{"name":"canary","version":"one","sealed_upload_id":"stage-a"}`)
			}
			path, proofPath := filepath.Join(directory, "request.json"), filepath.Join(directory, "proof.json")
			if err := os.WriteFile(path, input, 0600); err != nil {
				t.Fatal("cannot retain proof-intent input")
			}
			proof := api.ProofRef{ID: "proof-a", RequestSHA256: api.Digest(strings.Repeat("a", 64)),
				ExpiresAt: api.Timestamp(time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano))}
			data, err := json.Marshal(proof)
			if err != nil {
				t.Fatal("cannot encode proof-intent control")
			}
			if err := os.WriteFile(proofPath, data, 0600); err != nil {
				t.Fatal("cannot retain proof-intent control")
			}
			key, err := client.NewRequestID()
			if err != nil {
				t.Fatal("cannot retain proof-intent retry key")
			}
			var out, errOut bytes.Buffer
			code := cli.Run([]string{"secret", command, "--config", "cli-case", "--input", path, "--proof-file", proofPath,
				"--idempotency-key", string(key)}, bytes.NewReader(nil), &out, &errOut)
			var failure api.Error
			if err := json.Unmarshal(errOut.Bytes(), &failure); err != nil || code != 2 || out.Len() != 0 ||
				failure.Code != api.CodeForbidden || failure.Owner != "lb-v2-secrets" {
				t.Fatal("secret CLI accepted a proof for another intent")
			}
		})
	}
}

func TestCLIRejectsFIFO(t *testing.T) {
	path := filepath.Join(testdir.New(t), "input")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal("cannot create harmless FIFO control")
	}
	assertCLIFailure(t, []string{"secret", "key", "--config", "cli-case", "--request", path}, nil)
}
