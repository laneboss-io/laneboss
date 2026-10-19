package approval_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/cli"
)

// These tests exercise public CLI dispatch and local input refusal only. They
// do not claim an installed service, human proof or successful application.
func TestCLIRejectsMissingFiles(t *testing.T) {
	for name, command := range map[string][]string{
		"propose":  {"org", "change", "propose"},
		"get":      {"org", "change", "get"},
		"approve":  {"org", "change", "approve"},
		"apply":    {"org", "change", "apply"},
		"roles":    {"org", "roles", "init"},
		"render":   {"org", "render"},
		"channel":  {"org", "channel", "add"},
		"instance": {"org", "instance", "add"},
	} {
		t.Run(name, func(t *testing.T) {
			args := append(append([]string{}, command...), "--config", approvalTestConfig())
			assertCLIInvalid(t, args)
		})
	}
}

// Preserve an existing test-process binding; never clear or switch a live scope.
func approvalTestConfig() string {
	if bound := os.Getenv("LANEBOSS_CONFIG"); bound != "" {
		return bound
	}
	return "example"
}

func assertCLIInvalid(t *testing.T, args []string) api.Error {
	t.Helper()
	var stdout, stderr bytes.Buffer
	exit := cli.Run(args, strings.NewReader(""), &stdout, &stderr)
	var failure api.Error
	if err := json.Unmarshal(stderr.Bytes(), &failure); err != nil {
		t.Fatalf("CLI refusal was not typed JSON: %v", err)
	}
	if exit != 2 || failure.Code != api.CodeInvalid || failure.Owner != "lb-v2-approval" || stdout.Len() != 0 {
		t.Fatalf("invalid input reached a dependency or printed success: exit=%d code=%s", exit, failure.Code)
	}
	return failure
}

func approvalPrivateDir(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatalf("could not make the test input directory private: %v", err)
	}
	info, err := os.Lstat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("test input directory must be ordinary and private")
	}
	facts, ok := info.Sys().(*syscall.Stat_t)
	if !ok || facts.Uid != uint32(os.Geteuid()) {
		t.Fatal("test input directory must belong to the test identity")
	}
	return directory
}

func TestCLIRefusesMalformedInput(t *testing.T) {
	for name, data := range map[string]string{
		"duplicate":  `{"change_id":"one","change_id":"two"}`,
		"case_alias": `{"change_id":"one","CHANGE_ID":"two"}`,
		"unknown":    `{"change_id":"one","role":"human"}`,
		"null":       `{"change_id":null}`,
		"trailing":   `{"change_id":"one"} true`,
		"missing":    `{}`,
		"oversized":  strings.Repeat("x", api.MaxFrameBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			file := filepath.Join(approvalPrivateDir(t), "request.json")
			if err := os.WriteFile(file, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			assertCLIInvalid(t, []string{"org", "change", "get", "--config", approvalTestConfig(), "--request-file", file})
		})
	}
}

func TestCLIRefusesFileAliases(t *testing.T) {
	directory := approvalPrivateDir(t)
	file := filepath.Join(directory, "request.json")
	if err := os.WriteFile(file, []byte(`{"change_id":"one"}`), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link.json")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{link, directory, filepath.Join(directory, "absent.json")} {
		assertCLIInvalid(t, []string{"org", "change", "get", "--config", approvalTestConfig(), "--request-file", input})
	}
}

func TestCLIRefusesOptions(t *testing.T) {
	for _, args := range [][]string{
		{"--request-file", "one", "--request-file", "two"},
		{"--request-file"},
		{"--request-file=one", "--idempotency-key=short"},
		{"--request-file=one", "--request-id=short"},
		{"--request-file=one", "--accept-uncovered"},
	} {
		command := []string{"org", "change", "get", "--config", approvalTestConfig()}
		assertCLIInvalid(t, append(command, args...))
	}
}

func TestCLIProofInput(t *testing.T) {
	manifest := sha256.Sum256([]byte("staged manifest"))
	request := api.ChangeApproveRequest{ChangeID: "change-one",
		ManifestSHA256: api.Digest(hex.EncodeToString(manifest[:])), BaseGeneration: 7}
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := api.RequestDigest(api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion,
		Config: approvalTestConfig(), Method: "org.change.approve", Params: raw})
	if err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*api.ProofRef){
		"id":   func(p *api.ProofRef) { p.ID = "invalid/proof" },
		"time": func(p *api.ProofRef) { p.ExpiresAt = "not-a-time" },
		"intent": func(p *api.ProofRef) {
			other := sha256.Sum256([]byte("different approval intent"))
			p.RequestSHA256 = api.Digest(hex.EncodeToString(other[:]))
		},
	} {
		t.Run(name, func(t *testing.T) {
			directory := approvalPrivateDir(t)
			requestFile := filepath.Join(directory, "request.json")
			proofFile := filepath.Join(directory, "proof.json")
			proof := api.ProofRef{ID: "proof-one", RequestSHA256: intent, ExpiresAt: "2026-10-15T09:02:00Z"}
			edit(&proof)
			for path, value := range map[string]any{requestFile: request, proofFile: proof} {
				encoded, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, encoded, 0600); err != nil {
					t.Fatal(err)
				}
			}
			assertCLIInvalid(t, []string{"org", "change", "approve", "--config", approvalTestConfig(),
				"--request-file", requestFile, "--proof-file", proofFile,
				"--idempotency-key", strings.Repeat("k", 32)})
		})
	}
}

func TestCLIProhibitsMutationProof(t *testing.T) {
	ref := api.BlobRef{ID: "source", SHA256: api.Digest(strings.Repeat("1", 64)), Bytes: 3, Class: "artifact"}
	sessionIntent, err := api.RequestDigest(api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion,
		Config: approvalTestConfig(), Method: "human.session", Params: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]any{
		"propose": api.ChangeProposeRequest{OrgID: "org-one", BaseGeneration: 7, Reason: ref,
			Files: []api.ResourceDelta{{Path: "notes/demo.md", Action: "add", Mode: 0644, After: &ref}}},
		"apply": api.ChangeApplyRequest{ChangeID: "change-one", ApprovalID: "approval-one", ExpectedGeneration: 7},
	} {
		t.Run(name, func(t *testing.T) {
			directory := approvalPrivateDir(t)
			requestFile, proofFile := filepath.Join(directory, "request.json"), filepath.Join(directory, "proof.json")
			approvalWriteJSON(t, requestFile, body)
			approvalWriteJSON(t, proofFile, api.ProofRef{ID: "proof-one", RequestSHA256: sessionIntent, ExpiresAt: "2026-10-15T09:02:00Z"})
			failure := assertCLIInvalid(t, []string{"org", "change", name, "--config", approvalTestConfig(),
				"--request-file", requestFile, "--proof-file", proofFile, "--idempotency-key", strings.Repeat("k", 32),
				"--binding", filepath.Join(directory, "missing-binding.json")})
			if failure.Message != "pass --request-file PATH; approval requires its proof and a human read may supply a session proof" {
				t.Fatalf("mutation proof did not reach its option prohibition: %s", failure.Message)
			}
		})
	}
}

func TestCLIRawRequestDigest(t *testing.T) {
	directory := approvalPrivateDir(t)
	requestFile := filepath.Join(directory, "request.json")
	raw := `{"org_id":"org-one","base_generation":7,"reason":{"id":"reason","sha256":"` + strings.Repeat("1", 64) + `","bytes":3,"class":"artifact"},"files":[{"path":"notes/demo.md","action":"add","mode":420,"before_sha256":"","after":{"id":"source","sha256":"` + strings.Repeat("2", 64) + `","bytes":3,"class":"artifact"}}]}`
	if err := os.WriteFile(requestFile, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	exit := cli.Run([]string{"org", "change", "propose", "--config", approvalTestConfig(),
		"--request-file", requestFile, "--idempotency-key", strings.Repeat("k", 32),
		"--binding", filepath.Join(directory, "missing-binding.json")}, strings.NewReader(""), &stdout, &stderr)
	var failure api.Error
	if err := json.Unmarshal(stderr.Bytes(), &failure); err != nil {
		t.Fatal(err)
	}
	if exit != 69 || stdout.Len() != 0 || failure.Owner == "lb-v2-approval" ||
		(failure.Code != api.CodePrerequisite && failure.Code != api.CodeNotImplemented) {
		t.Fatalf("valid raw optional member did not reach transport: exit=%d code=%s", exit, failure.Code)
	}
}

func TestCLIReadProof(t *testing.T) {
	intent, err := api.RequestDigest(api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion,
		Config: approvalTestConfig(), Method: "human.session", Params: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"time", "intent"} {
		t.Run(name, func(t *testing.T) {
			directory := approvalPrivateDir(t)
			requestFile, proofFile := filepath.Join(directory, "read.json"), filepath.Join(directory, "proof.json")
			proof := api.ProofRef{ID: "read-proof", RequestSHA256: intent, ExpiresAt: "2026-10-15T09:02:00Z"}
			if name == "time" {
				proof.ExpiresAt = "not-a-time"
			} else {
				proof.RequestSHA256 = api.Digest(hex.EncodeToString(make([]byte, sha256.Size)))
			}
			for path, value := range map[string]any{
				requestFile: api.ChangeGetRequest{ChangeID: "change-one"}, proofFile: proof,
			} {
				encoded, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, encoded, 0600); err != nil {
					t.Fatal(err)
				}
			}
			failure := assertCLIInvalid(t, []string{"org", "change", "get", "--config", approvalTestConfig(),
				"--request-file", requestFile, "--proof-file", proofFile})
			fragment := "covers another exact request"
			if name == "time" {
				fragment = "expiry is not canonical UTC"
			}
			if !strings.Contains(failure.Message, fragment) {
				t.Fatal("read session proof did not reach its specific shape/intent check")
			}
		})
	}
}
