package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestHookRawFile(t *testing.T) {
	t.Setenv("LANEBOSS_CONFIG", "demo")
	command := []byte("true")
	hash := sha256.Sum256(command)
	request := api.PolicyEvaluateRequest{Target: api.LifeRef{LifeID: "lane", Run: 1}, LogicalTurnID: "turn",
		Command: api.CommandData{Tool: "shell", Command: command, Argv: []string{"true"}, DeclaredPaths: []string{}, CWD: "/work/main", RawSHA256: api.Digest(hex.EncodeToString(hash[:]))}}
	path := integrateFixtureFile(t, t.TempDir(), "hook-request.json", request)
	var out, errout bytes.Buffer
	code := Run([]string{"org", "hook", "--config", "demo", "--request", path, "--idempotency-key", "hook-key"}, nil, &out, &errout)
	var typed api.Error
	if err := json.Unmarshal(errout.Bytes(), &typed); err != nil {
		t.Fatal(err)
	}
	if code != 69 || typed.Code != api.CodeUnsupported || typed.Owner != "lb-v2-policy" ||
		typed.Message != "org hook does not support the raw request-file form" || out.Len() != 0 {
		t.Fatalf("raw hook file bypassed decision-aware exit handling: exit=%d error=%+v", code, typed)
	}
}
