package judge_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/cli"
	"laneboss.io/laneboss/internal/v2/judge/wire"
)

func cliPreviewInput() api.JudgeRequest {
	command := []byte("build report")
	return api.JudgeRequest{ID: "preview-a", Purpose: "preview", Rules: []api.JudgeRule{}, Decisions: []api.DecisionCandidate{},
		Task: []byte{}, DeadlineMS: 2000, MaxCostMicros: 100000,
		Command: &api.CommandData{Tool: "shell", Command: command, Argv: []string{}, DeclaredPaths: []string{}, CWD: "/work", RawSHA256: wire.Digest(command)}}
}

func cliRequestFile(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(name, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return name
}

func cliFixtureConfig() string {
	// Reuse any test-process binding without changing it or printing it.
	if bound := os.Getenv("LANEBOSS_CONFIG"); bound != "" {
		return bound
	}
	return "demo"
}

func TestJudgeInputFiles(t *testing.T) {
	for _, method := range []string{"ask", "list"} {
		t.Run(method, func(t *testing.T) {
			valid := any(api.Empty{})
			invalid := any(map[string]any{"extra": true})
			if method == "ask" {
				request := cliPreviewInput()
				valid = request
				request.ID = ""
				invalid = request
			}
			binding := filepath.Join(t.TempDir(), "uninstalled-binding.json")
			for _, accepted := range []bool{false, true} {
				value := invalid
				if accepted {
					value = valid
				}
				args := []string{"judge", method, "--config", cliFixtureConfig(), "--binding", binding, "--request", cliRequestFile(t, value)}
				if accepted {
					args = append(args, "--idempotency-key", strings.Repeat("k", 32))
				} else {
					// Semantic rejection must precede proof I/O and key/socket work.
					args = append(args, "--proof", filepath.Join(t.TempDir(), "unread-proof.json"), "--idempotency-key", "!")
				}
				var out, diagnostic bytes.Buffer
				exit := cli.Run(args, bytes.NewReader(nil), &out, &diagnostic)
				var failure api.Error
				if err := json.Unmarshal(diagnostic.Bytes(), &failure); err != nil || out.Len() != 0 {
					t.Fatal("file form did not return a typed failure")
				}
				if !accepted {
					// Empty has no semantic fields: common shape decoding may
					// reject extras before the registered exact-empty hook.
					owned := failure.Owner == "lb-v2-judge" || method == "list" && failure.Owner == ""
					if method == "list" && failure.Owner == "" {
						// A proof-read failure is also a shared invalid_request.
						// Require this exact input-shape error, not any such code.
						raw, err := json.Marshal(invalid)
						if err != nil {
							t.Fatal(err)
						}
						var empty api.Empty
						var shape *api.Error
						shapeErr := api.DecodeObject(raw, &empty)
						owned = errors.As(shapeErr, &shape) && shape.Code == api.CodeInvalid &&
							failure.Message == shape.Message && failure.Instead == shape.Instead && failure.Owner == shape.Owner
					}
					if exit != 2 || failure.Code != api.CodeInvalid || !owned {
						t.Fatal("judge input validation was bypassed")
					}
					continue
				}
				if failure.Owner == "lb-v2-judge" || failure.Code == api.CodeInvalid {
					t.Fatal("valid judge file missed transport")
				}
				switch failure.Code {
				case api.CodeNotImplemented, api.CodePrerequisite, api.CodeUnavailable:
					if exit != 69 {
						t.Fatal("transport exit differs")
					}
				case api.CodeUnauthenticated, api.CodeVersion:
					if exit != 2 {
						t.Fatal("binding exit differs")
					}
				default:
					t.Fatal("valid judge file hit an unlisted refusal")
				}
			}
		})
	}
}
