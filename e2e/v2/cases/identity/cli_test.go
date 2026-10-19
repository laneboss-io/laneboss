package identitycase

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/cli"
)

// These are credential-free parser/error tests. The installed-socket case is
// run.sh and cannot be replaced by these focused client checks.
func identityPrivateDir(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestCLIRejectsLabels(t *testing.T) {
	for _, raw := range []string{`{"actor":"human"}`, `{"level":6}`,
		`{"launch_id":"forged"}`, `{"actor":null}`, "{} {}", "[]",
		`{"actor":"agent","actor":"human"}`} {
		path := filepath.Join(identityPrivateDir(t), "request.json")
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		code := cli.Run([]string{"identity", "self", "--config", "fixture", "--request", path},
			bytes.NewReader(nil), &stdout, &stderr)
		if code != 2 || stdout.Len() != 0 {
			t.Fatalf("forged input reached a successful call: exit=%d", code)
		}
		var failure api.Error
		if err := json.Unmarshal(stderr.Bytes(), &failure); err != nil || failure.Code != api.CodeInvalid {
			t.Fatal("forged input did not produce a typed shape error")
		}
	}
}

func TestCLIRequiredFields(t *testing.T) {
	for _, command := range [][]string{{"human", "challenge"}, {"human", "confirm"}, {"ticket", "issue"}} {
		path := filepath.Join(identityPrivateDir(t), "request.json")
		if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
		args := append(append([]string{}, command...), "--config", "fixture", "--request", path)
		var stdout, stderr bytes.Buffer
		if code := cli.Run(args, bytes.NewReader(nil), &stdout, &stderr); code != 2 || stdout.Len() != 0 {
			t.Fatal("missing identity fields were accepted")
		}
		var failure api.Error
		if err := json.Unmarshal(stderr.Bytes(), &failure); err != nil || failure.Code != api.CodeInvalid {
			t.Fatal("missing identity fields did not produce a typed shape error")
		}
	}
}

func TestCLIRefusesUnknownFlags(t *testing.T) {
	for _, flags := range [][]string{{"--actor", "human"}, {"--level", "6"},
		{"--from", "human"}, {"--request", "one", "--request", "two"},
		{"--request=one", "--request=two"}, {"--format", "text"},
		{"-request", "one", "--request", "two"}, {"--proof="}} {
		args := append([]string{"identity", "self", "--config", "fixture"}, flags...)
		var stdout, stderr bytes.Buffer
		if code := cli.Run(args, bytes.NewReader(nil), &stdout, &stderr); code != 2 || stdout.Len() != 0 {
			t.Fatal("unknown or ambiguous identity flags were accepted")
		}
		var failure api.Error
		if err := json.Unmarshal(stderr.Bytes(), &failure); err != nil || failure.Code != api.CodeInvalid {
			t.Fatal("invalid identity flags did not produce a typed error")
		}
	}
}

func TestCLINonRegularInput(t *testing.T) {
	path := filepath.Join(identityPrivateDir(t), "pipe")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"identity", "self", "--config", "fixture", "--request", path},
		bytes.NewReader(nil), &stdout, &stderr)
	if code != 2 || stdout.Len() != 0 {
		t.Fatal("nonregular input was accepted")
	}
	var failure api.Error
	if err := json.Unmarshal(stderr.Bytes(), &failure); err != nil || failure.Code != api.CodeInvalid {
		t.Fatal("nonregular input did not produce a typed error")
	}
}

func TestCLIRequiresRetainedKey(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"human", "session", "--config", "fixture"}, bytes.NewReader(nil), &stdout, &stderr)
	var failure api.Error
	if code != 2 || stdout.Len() != 0 || json.Unmarshal(stderr.Bytes(), &failure) != nil || failure.Code != api.CodeInvalid ||
		failure.Message != "mutation requires a retained idempotency key" {
		t.Fatal("empty session form did not reach shared retained-key validation")
	}
}
