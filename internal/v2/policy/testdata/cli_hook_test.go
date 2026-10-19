package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// This owned test is compiled into package cli through a Go test overlay.
// It borrows the existing CLI test transport seam; no production source or
// transport authentication is replaced and no sampled command is executed.
func TestLBPolicyHookRun(t *testing.T) {
	lbPolicyHookCases(t, false)
}

func TestLBPolicyRawFileHook(t *testing.T) {
	lbPolicyHookCases(t, true)
}

func lbPolicyHookCases(t *testing.T, rawFile bool) {
	t.Helper()
	for _, row := range []struct {
		name        string
		result      string
		exit        int
		scored      bool
		probability float64
	}{
		{"allow", "allow", 0, true, 0},
		{"deny", "refuse", 2, true, 0.9},
		{"warn", "warn", 0, true, 0.6},
		{"unscored", "allow", 0, false, 0},
	} {
		t.Run(row.name, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Chmod(directory, 0700); err != nil {
				t.Fatal(err)
			}
			command := []byte("read a public file\n")
			if !row.scored {
				command = bytes.Repeat([]byte("x"), api.MaxJudgeBytes+1)
			}
			file := filepath.Join(directory, "command.txt")
			if err := os.WriteFile(file, command, 0600); err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256(command)
			expected := api.PolicyEvaluateRequest{Target: api.LifeRef{LifeID: "life-a", Run: 1}, LogicalTurnID: "turn-a",
				Command: api.CommandData{Tool: "shell", Command: command, Argv: []string{}, DeclaredPaths: []string{},
					CWD: "/work/main", RawSHA256: api.Digest(hex.EncodeToString(hash[:]))}}
			rule := api.RuleDecision{RuleID: "responsibility", Result: row.result, Instead: "Submit the reviewed result.",
				Reason: "scored fixture decision", Thresholds: api.Thresholds{Match: 0.85, UncertainLow: 0.4,
					UncertainHigh: 0.6, CalibrationID: "fixture-calibration"}}
			if row.scored {
				probability := row.probability
				rule.Probability = &probability
				rule.JudgmentID = "fixture-judgment"
			} else {
				rule.Reason = "unscored: token_fit_unproved"
			}
			decision := api.PolicyDecision{ID: "decision-a", Result: row.result, Rules: []api.RuleDecision{rule},
				PolicyGeneration: 1, AuditComplete: true,
				Input: api.BlobRef{ID: "input-a", SHA256: api.Digest(hex.EncodeToString(hash[:])), Bytes: 1, Class: "judge_request"}}
			key := strings.Repeat("k", 32)
			transport := &integrateFixtureClient{}
			transport.handle = func(request api.Request) (any, error) {
				var input api.PolicyEvaluateRequest
				if request.Method != "policy.evaluate" || request.IdempotencyKey != api.ID(key) ||
					api.DecodeObject(request.Params, &input) != nil || !reflect.DeepEqual(input, expected) {
					return nil, &api.Error{Code: api.CodeIntegrity, Message: "hook fixture received different retained input"}
				}
				return decision, nil
			}
			if rawFile {
				requestFile := integrateFixtureFile(t, directory, "request.json", expected)
				var stdout, stderr bytes.Buffer
				exit := Run([]string{"org", "hook", "--config", "case-policy", "--request", requestFile,
					"--idempotency-key", key}, bytes.NewReader(nil), &stdout, &stderr)
				var actual api.Error
				want := api.Error{Code: api.CodeUnsupported, Owner: "lb-v2-policy",
					Message: "org hook does not support the raw request-file form",
					Instead: "Use org hook's decision-aware adapter without --request; a deny must produce a nonzero exit."}
				if exit != 69 || stdout.Len() != 0 || api.DecodeObject(stderr.Bytes(), &actual) != nil ||
					!reflect.DeepEqual(actual, want) || len(transport.requests) != 0 || transport.closed != 0 {
					t.Fatalf("hook exit/decision mismatch: raw file did not return exact unsupported refusal: case=%s exit=%d error=%s", row.name, exit, stderr.Bytes())
				}
				return
			}
			original := integrateCommands["org hook"]
			entry := original
			entry.run = func(ctx context.Context, call Invocation) error {
				call.integrateSocket.connection = transport
				return original.run(ctx, call)
			}
			integrateCommands["org hook"] = entry
			defer func() { integrateCommands["org hook"] = original }()
			var stdout, stderr bytes.Buffer
			exit := Run([]string{"org", "hook", "--config", "case-policy", "--command-file", file,
				"--life-id", "life-a", "--run", "1", "--turn-id", "turn-a", "--cwd", "/work/main",
				"--idempotency-key", key}, bytes.NewReader(nil), &stdout, &stderr)
			var actual api.PolicyDecision
			valid := api.DecodeObject(stdout.Bytes(), &actual) == nil && reflect.DeepEqual(actual, decision) &&
				len(transport.requests) == 1 && transport.closed == 1
			if exit != row.exit {
				if row.result == "refuse" && exit == 0 && valid {
					t.Fatal("hook exit/decision mismatch: deny exited zero")
				}
				var refusal api.Error
				if !row.scored && exit == 2 && stdout.Len() == 0 && len(transport.requests) == 0 &&
					api.DecodeObject(stderr.Bytes(), &refusal) == nil && refusal.Code == api.CodeInvalid &&
					refusal.Message == "policy input must be a bounded regular file" {
					t.Fatal("hook exit/decision mismatch: provider overflow refused locally")
				}
				t.Fatalf("CLI hook fixture returned an unexpected failure: case=%s exit=%d error=%s", row.name, exit, stderr.Bytes())
			}
			if !valid {
				t.Fatalf("CLI hook fixture lost typed response/input: case=%s", row.name)
			}
			if row.result == "refuse" {
				var refusal api.Error
				if api.DecodeObject(stderr.Bytes(), &refusal) != nil || refusal.Code != api.CodeForbidden || refusal.Instead != rule.Instead {
					t.Fatalf("hook exit/decision mismatch: case=%s lost typed Instead", row.name)
				}
			} else if stderr.Len() != 0 {
				t.Fatalf("hook exit/decision mismatch: case=%s unexpected stderr", row.name)
			}
		})
	}
}
