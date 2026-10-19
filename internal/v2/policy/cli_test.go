package policy_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/cli"
	lbV2Policy "laneboss.io/laneboss/internal/v2/policy"
)

func TestCLIRejectsAmbiguousInputs(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(directory, "request.json")
	if err := os.WriteFile(file, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		args []string
		code api.ErrorCode
		exit int
	}{
		{[]string{"policy", "get", "--unknown", "value"}, api.CodeInvalid, 2},
		{[]string{"policy", "get", "--format", "json", "--format", "text"}, api.CodeInvalid, 2},
		{[]string{"policy", "get", "--request", file, "--life-id", "another-life"}, api.CodeInvalid, 2},
		{[]string{"policy", "evaluate", "--request", file, "--command-file", file}, api.CodeInvalid, 2},
		{[]string{"org", "hook", "--request", file, "--format", "text"}, api.CodeUnsupported, 69},
		{[]string{"config", "read", "--request", file, "--view", "policy"}, api.CodeInvalid, 2},
		{[]string{"config", "validate", "--request"}, api.CodeInvalid, 2},
		{[]string{"settings", "--unexpected", "value"}, api.CodeInvalid, 2},
	} {
		args := append(row.args, "--config", "case-policy")
		var stdout, stderr bytes.Buffer
		exit := cli.Run(args, bytes.NewReader(nil), &stdout, &stderr)
		var refusal api.Error
		if err := json.Unmarshal(stderr.Bytes(), &refusal); err != nil || exit != row.exit ||
			refusal.Code != row.code || stdout.Len() != 0 {
			t.Fatalf("input reached transport or produced success: exit=%d, error=%s", exit, stderr.Bytes())
		}
		if row.code == api.CodeUnsupported && (refusal.Owner != "lb-v2-policy" ||
			refusal.Message != "org hook does not support the raw request-file form" ||
			refusal.Instead != "Use org hook's decision-aware adapter without --request; a deny must produce a nonzero exit.") {
			t.Fatal("raw hook ambiguity did not preserve the exact unsupported route")
		}
	}
}

func TestCLIRetainsMutationKey(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(directory, "command.txt")
	if err := os.WriteFile(file, []byte("read a public file\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	exit := cli.Run([]string{"org", "hook", "--config", "case-policy", "--life-id", "life-a", "--run", "1",
		"--turn-id", "turn-a", "--command-file", file, "--cwd", "/work/main"}, bytes.NewReader(nil), &stdout, &stderr)
	var failure api.Error
	if json.Unmarshal(stderr.Bytes(), &failure) != nil || exit != 2 || failure.Code != api.CodeInvalid ||
		!strings.Contains(failure.Message, "retained idempotency key") || stdout.Len() != 0 {
		t.Fatalf("missing retained mutation key reached transport or succeeded: exit=%d, error=%s", exit, stderr.Bytes())
	}
}

func TestCLIRejectsPolicyFiles(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	command := []byte("read public input\n")
	sum := sha256.Sum256(command)
	base := api.PolicyEvaluateRequest{Target: api.LifeRef{LifeID: "life-a", Run: 1}, LogicalTurnID: "turn-a",
		Command: api.CommandData{Tool: "shell", Command: command, Argv: []string{}, DeclaredPaths: []string{},
			CWD: "/work/main", RawSHA256: api.Digest(hex.EncodeToString(sum[:]))}}
	if err := lbV2Policy.ValidateEvaluateInput(base); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name string
		edit func(*api.PolicyEvaluateRequest)
	}{
		{"run", func(r *api.PolicyEvaluateRequest) { r.Target.Run = 0 }},
		{"turn", func(r *api.PolicyEvaluateRequest) { r.LogicalTurnID = "bad.id" }},
		{"cwd", func(r *api.PolicyEvaluateRequest) { r.Command.CWD = "relative" }},
		{"digest", func(r *api.PolicyEvaluateRequest) { r.Command.RawSHA256 = api.Digest(strings.Repeat("0", 64)) }},
	} {
		t.Run(row.name, func(t *testing.T) {
			request := base
			row.edit(&request)
			expected, ok := lbV2Policy.ValidateEvaluateInput(request).(*api.Error)
			if !ok || expected.Code != api.CodeInvalid || expected.Owner != "lb-v2-policy" {
				t.Fatal("invalid policy input was accepted by the shared semantic validator")
			}
			raw, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(directory, row.name+".json")
			if err := os.WriteFile(file, raw, 0600); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			exit := cli.Run([]string{"policy", "evaluate", "--config", "case-policy", "--request", file,
				"--proof", filepath.Join(directory, "absent-proof.json")}, bytes.NewReader(nil), &stdout, &stderr)
			var actual api.Error
			if json.Unmarshal(stderr.Bytes(), &actual) != nil || exit != 2 || stdout.Len() != 0 ||
				actual.Code != expected.Code || actual.Message != expected.Message || actual.Owner != expected.Owner {
				t.Fatalf("policy file semantic error did not precede proof/key/transport: exit=%d, error=%s", exit, stderr.Bytes())
			}
		})
	}
}

func TestCLIReadInvalidFiles(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name     string
		command  []string
		raw      string
		expected error
	}{
		{"policy-get", []string{"policy", "get"}, `{"life_id":"bad.id"}`,
			lbV2Policy.ValidateGetInput(api.PolicyGetRequest{LifeID: "bad.id"})},
		{"config-read", []string{"config", "read"}, `{"view":"unknown"}`,
			lbV2Policy.ValidateConfigReadInput(api.ConfigReadRequest{View: "unknown"})},
		{"config-validate", []string{"config", "validate"}, `{"unexpected":true}`,
			lbV2Policy.ValidateConfigValidateInput([]byte(`{"unexpected":true}`))},
	} {
		t.Run(row.name, func(t *testing.T) {
			expected, ok := row.expected.(*api.Error)
			if !ok || expected.Code != api.CodeInvalid {
				t.Fatal("invalid read input was accepted by the shared validator")
			}
			// Empty has no invalid semantic value after the common shape check.
			// Its extra field is rejected there with the same exact decoder error.
			if row.name != "config-validate" && expected.Owner != "lb-v2-policy" {
				t.Fatal("semantic read error lacks its policy owner")
			}
			file := filepath.Join(directory, row.name+".json")
			if err := os.WriteFile(file, []byte(row.raw), 0600); err != nil {
				t.Fatal(err)
			}
			args := append(append([]string{}, row.command...), "--config", "case-policy", "--request", file,
				"--proof", filepath.Join(directory, "absent-proof.json"), "--request-id", "bad.id",
				"--idempotency-key", "bad.id", "--binding", filepath.Join(directory, "absent-binding.json"))
			var stdout, stderr bytes.Buffer
			exit := cli.Run(args, bytes.NewReader(nil), &stdout, &stderr)
			var actual api.Error
			if json.Unmarshal(stderr.Bytes(), &actual) != nil || exit != 2 || stdout.Len() != 0 ||
				actual.Code != expected.Code || actual.Message != expected.Message || actual.Owner != expected.Owner {
				t.Fatalf("read file error did not precede proof/key/transport: exit=%d, error=%s", exit, stderr.Bytes())
			}
		})
	}
}

func TestCLIReadValidFiles(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name    string
		command []string
		raw     string
	}{
		{"policy-get", []string{"policy", "get"}, `{"life_id":""}`},
		{"config-read", []string{"config", "read"}, `{"view":"path"}`},
		{"config-validate", []string{"config", "validate"}, `{}`},
	} {
		t.Run(row.name, func(t *testing.T) {
			file := filepath.Join(directory, row.name+".json")
			if err := os.WriteFile(file, []byte(row.raw), 0600); err != nil {
				t.Fatal(err)
			}
			args := append(append([]string{}, row.command...), "--config", "case-policy", "--request", file,
				"--binding", filepath.Join(directory, "absent-binding.json"))
			var stdout, stderr bytes.Buffer
			exit := cli.Run(args, bytes.NewReader(nil), &stdout, &stderr)
			var actual api.Error
			// The isolated source has a transport stub; the combined client
			// refuses the explicitly absent protected binding. Neither is a
			// policy validator failure, and neither pins a foreign stub message.
			if json.Unmarshal(stderr.Bytes(), &actual) != nil || exit != 69 || stdout.Len() != 0 ||
				actual.Owner == "lb-v2-policy" || actual.Code == api.CodeInvalid ||
				(actual.Code != api.CodeNotImplemented && actual.Code != api.CodePrerequisite) {
				t.Fatalf("valid read file did not reach transport: exit=%d, error=%s", exit, stderr.Bytes())
			}
		})
	}
}

func TestCLILocalPreflight(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(directory, "command.txt")
	if err := os.WriteFile(file, []byte("read public input"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name    string
		args    []string
		message string
	}{
		{"key", []string{"--cwd", "/work/main"}, "retained idempotency key"},
		{"cwd", []string{"--cwd", "relative", "--idempotency-key", strings.Repeat("k", 32)}, "invalid command data"},
		{"tool", []string{"--tool", strings.Repeat("t", 257), "--idempotency-key", strings.Repeat("k", 32)}, "invalid command data"},
	} {
		t.Run(row.name, func(t *testing.T) {
			args := []string{"org", "hook", "--config", "case-policy", "--command-file", file,
				"--binding", filepath.Join(directory, "absent-binding.json")}
			args = append(args, row.args...)
			var stdout, stderr bytes.Buffer
			exit := cli.Run(args, bytes.NewReader(nil), &stdout, &stderr)
			var refusal api.Error
			if json.Unmarshal(stderr.Bytes(), &refusal) != nil || exit != 2 || refusal.Code != api.CodeInvalid ||
				!strings.Contains(refusal.Message, row.message) || stdout.Len() != 0 {
				t.Fatalf("local preflight reached target lookup: case=%s exit=%d error=%s", row.name, exit, stderr.Bytes())
			}
		})
	}
}

func TestCLIClosedViews(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	for _, view := range []string{"config", "read"} {
		t.Run(view, func(t *testing.T) {
			file := filepath.Join(directory, view+".json")
			if err := os.WriteFile(file, []byte(`{"view":"`+view+`"}`), 0600); err != nil {
				t.Fatal(err)
			}
			for _, options := range [][]string{{"--request", file}, {"--view", view}} {
				args := append([]string{"config", "read", "--config", "case-policy"}, options...)
				var stdout, stderr bytes.Buffer
				exit := cli.Run(args, bytes.NewReader(nil), &stdout, &stderr)
				var refusal api.Error
				if json.Unmarshal(stderr.Bytes(), &refusal) != nil || exit != 2 || refusal.Code != api.CodeInvalid ||
					refusal.Owner != "lb-v2-policy" || refusal.Message != "unknown configuration view" || stdout.Len() != 0 {
					t.Fatalf("noncatalog configuration view reached transport: exit=%d error=%s", exit, stderr.Bytes())
				}
			}
		})
	}
}
