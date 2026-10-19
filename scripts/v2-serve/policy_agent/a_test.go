package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/cli"
)

// Use the installed actor's argv builder and the real CLI parser. An absent
// binding is the expected transport boundary; this grants no lane identity.
func TestPolicyArgs(t *testing.T) {
	const config = "policy-args"
	t.Setenv("LANEBOSS_CONFIG", config)
	for _, prefix := range []string{"a", "_", "-", "--"} {
		t.Run(prefix, func(t *testing.T) {
			directory := t.TempDir()
			stem := filepath.Join(directory, "0003")
			content := []byte("policy task " + filepath.Base(directory))
			request, err := json.Marshal(api.BlobBeginRequest{Class: "task", Bytes: int64(len(content)),
				SHA256: api.Digest(digest(content))})
			if err != nil {
				t.Fatal(err)
			}
			if err := retain(stem+".request.json", append(bytes.Clone(request), '\n')); err != nil {
				t.Fatal(err)
			}
			key := prefix + strings.Repeat("q", 32-len(prefix))
			o := options{Config: config, Client: "laneboss", Binding: filepath.Join(directory, "absent.json")}
			input := job{Kind: "begin", Request: request, Key: key}
			argv, hook, err := jobArgs(o, input, stem)
			if err != nil || hook != nil || len(argv) < 2 {
				t.Fatal("installed actor could not construct its actual upload argv", err)
			}
			last := argv[len(argv)-1]
			if last != key && last != "--idempotency-key="+key {
				t.Fatal("actor changed the retained mutation key")
			}
			var stdout, stderr bytes.Buffer
			exit := cli.Run(argv[1:], strings.NewReader(""), &stdout, &stderr)
			var refusal api.Error
			if err := json.Unmarshal(stderr.Bytes(), &refusal); err != nil {
				t.Fatal("CLI did not retain a typed boundary result", err)
			}
			if exit != 69 || stdout.Len() != 0 || refusal.Code != api.CodePrerequisite ||
				refusal.Message != "protected binding is missing or unsafe" {
				t.Fatalf("installed argv did not reach its binding boundary: exit=%d code=%s message=%s",
					exit, refusal.Code, refusal.Message)
			}
			retained, err := os.ReadFile(stem + ".request.json")
			if err != nil || !bytes.Equal(retained, append(bytes.Clone(request), '\n')) {
				t.Fatal("CLI changed retained request bytes", err)
			}
		})
	}
}
