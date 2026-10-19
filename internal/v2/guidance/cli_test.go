package guidance_test

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
	"laneboss.io/laneboss/internal/v2/client"
)

func cliInvalid(t *testing.T, message, owner string, args ...string) {
	t.Helper()
	t.Setenv("LANEBOSS_CONFIG", "example")
	// Reject malformed input before any installation can be contacted.
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	key, err := client.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	base := []string{"guidance", "select", "--config", "example", "--idempotency-key", string(key),
		"--binding", filepath.Join(directory, "uninstalled.json")}
	var stdout, stderr bytes.Buffer
	exit := cli.Run(append(base, args...),
		strings.NewReader(""), &stdout, &stderr)
	var failure api.Error
	if err := json.Unmarshal(stderr.Bytes(), &failure); err != nil {
		t.Fatalf("missing typed CLI error: %v", err)
	}
	// A retained valid key prevents draft.4's missing-key refusal from
	// concealing a missing input validator. Assert the exact owning diagnostic.
	if exit != 2 || failure.Code != api.CodeInvalid ||
		failure.Owner != owner || failure.Message != message || stdout.Len() != 0 {
		t.Fatalf("invalid request did not fail before transport: %d, %+v", exit, failure)
	}
}

func TestCLIRequiresFile(t *testing.T) {
	for _, row := range []struct {
		name           string
		args           []string
		message, owner string
	}{
		// Guidance owns absent request input and unknown feature arguments.
		{"missing-file", nil, "guidance requires --request FILE", "lb-v2-guidance"},
		{"unknown", []string{"--unknown"}, "unknown guidance argument", "lb-v2-guidance"},
		{"positional", []string{"positional"}, "unknown guidance argument", "lb-v2-guidance"},
		// These invalid common options are rejected before guidance runs.
		// The common parser treats a dash-prefixed value as missing.
		{"missing-value", []string{"--request"}, "common option requires a value", ""},
		{"empty-value", []string{"--request="}, "common option requires a nonempty value", ""},
		{"dash-value", []string{"--request", "-"}, "common option requires a value", ""},
		{"flag-value", []string{"--request", "--other"}, "common option requires a value", ""},
		{"duplicate", []string{"--request", "first.json", "--request", "second.json"}, "duplicate common option", ""},
		{"extra", []string{"--request=first.json", "extra"}, "--request accepts only an exact RPC body and common options", ""},
	} {
		t.Run(row.name, func(t *testing.T) {
			cliInvalid(t, row.message, row.owner, row.args...)
		})
	}
}

func TestCLIRejectsMalformedFile(t *testing.T) {
	request := api.GuidanceRequest{
		Target: api.LifeRef{LifeID: "life-demo", Run: 1}, LogicalTurnID: "turn-a",
		Task: api.BlobRef{ID: "task-a", SHA256: api.Digest(strings.Repeat("e5", 32)), Bytes: 0, Class: "task"},
	}
	valid, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	inputs := map[string][]byte{
		"empty":      []byte(`{}`),
		"null":       []byte(`null`),
		"duplicate":  []byte(strings.Replace(string(valid), `"run":1`, `"run":1,"run":1`, 1)),
		"escaped":    []byte(strings.Replace(string(valid), `"run":1`, `"run":1,"r\u0075n":1`, 1)),
		"missing":    []byte(strings.Replace(string(valid), `"bytes":0,`, ``, 1)),
		"null-field": []byte(strings.Replace(string(valid), `"bytes":0`, `"bytes":null`, 1)),
		"float":      []byte(strings.Replace(string(valid), `"run":1`, `"run":1.5`, 1)),
		"class":      []byte(strings.Replace(string(valid), `"class":"task"`, `"class":"policy"`, 1)),
		"zero-run":   []byte(strings.Replace(string(valid), `"run":1`, `"run":0`, 1)),
		"negative":   []byte(strings.Replace(string(valid), `"bytes":0`, `"bytes":-1`, 1)),
		"large-task": []byte(strings.Replace(string(valid), `"bytes":0`, `"bytes":67108865`, 1)),
		"surrogate":  []byte(strings.Replace(string(valid), `"turn-a"`, `"\ud800"`, 1)),
		"UTF8":       append([]byte{0xff}, valid...),
		"extra":      append(append([]byte{}, valid...), []byte(` {}`)...),
		"oversize":   []byte(strings.Repeat(" ", api.MaxFrameBytes+1)),
	}
	for name, data := range inputs {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Chmod(directory, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "request.json")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			message, owner := "invalid JSON object or field shape", ""
			switch name {
			case "class", "zero-run", "negative", "large-task":
				message, owner = "invalid guidance target or task reference", "lb-v2-guidance"
			case "oversize":
				message = "input must be a bounded regular file"
			default:
				// The shared strict reader deliberately reports a closed schema
				// location/reason. Keep the exact owning diagnostic assertion.
				locations := map[string][2]string{
					"empty":      {"$.target", "missing"},
					"null":       {"$", "type"},
					"duplicate":  {"$.target.run", "duplicate"},
					"escaped":    {"$.target.run", "duplicate"},
					"missing":    {"$.task.bytes", "missing"},
					"null-field": {"$.task.bytes", "null"},
					"float":      {"$.target.run", "range"},
					"surrogate":  {"$", "surrogate"},
					"UTF8":       {"$", "utf8"},
					"extra":      {"$", "trailing"},
				}
				location, known := locations[name]
				if !known {
					t.Fatal("malformed guidance fixture has no exact expected diagnostic", name)
				}
				message += " (frame=object; object=GuidanceRequest; field=" + location[0] + "; reason=" + location[1] + ")"
			}
			cliInvalid(t, message, owner, "--request", path)
		})
	}
}

func TestCLIDiagnosticsAreScreened(t *testing.T) {
	t.Setenv("LANEBOSS_CONFIG", "example")
	var stdout, stderr bytes.Buffer
	marker := "private-input-marker"
	exit := cli.Run([]string{"guidance", "select", "--config", "example", "--" + marker},
		strings.NewReader(""), &stdout, &stderr)
	if exit != 2 || stdout.Len() != 0 || strings.Contains(stderr.String(), marker) {
		t.Fatal("unrecognized private input leaked into CLI diagnostics")
	}
}

func TestCLIValidFileReachesTransport(t *testing.T) {
	t.Setenv("LANEBOSS_CONFIG", "example")
	// This is a file-input boundary fixture. Both supported transport paths
	// must pass semantic validation before refusing the missing installation.
	task := []byte("Review the fixture implementation.\n")
	digest := sha256.Sum256(task)
	request := api.GuidanceRequest{
		Target: api.LifeRef{LifeID: "life-demo", Run: 1}, LogicalTurnID: "turn-a",
		Task: api.BlobRef{ID: "task-a", SHA256: api.Digest(hex.EncodeToString(digest[:])),
			Bytes: int64(len(task)), Class: "task"},
	}
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "request.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	key, err := client.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	exit := cli.Run([]string{"guidance", "select", "--config", "example",
		"--binding", filepath.Join(directory, "uninstalled.json"),
		"--idempotency-key", string(key), "--request", path},
		strings.NewReader(""), &stdout, &stderr)
	var failure api.Error
	if err := json.Unmarshal(stderr.Bytes(), &failure); err != nil {
		t.Fatalf("missing typed transport boundary: %v", err)
	}
	stub := failure.Code == api.CodeNotImplemented && failure.Owner == "lb-v2-service" &&
		failure.Message == "client.Open is not implemented"
	missingBinding := failure.Code == api.CodePrerequisite &&
		failure.Message == "protected binding is missing or unsafe"
	if exit != 69 || stdout.Len() != 0 || failure.Owner == "lb-v2-guidance" ||
		failure.Code == api.CodeInvalid || (!stub && !missingBinding) {
		t.Fatalf("valid guidance file did not reach client.Open: exit=%d error=%+v", exit, failure)
	}
}
