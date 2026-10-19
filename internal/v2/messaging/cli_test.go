package messaging_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/cli"
	"laneboss.io/laneboss/internal/v2/client"
)

// These are parser controls through the actual CLI entry, not a substituted
// socket implementation. A valid operation still depends on the real client.
func TestCLIRejectsUnsafeInputs(t *testing.T) {
	t.Setenv("LANEBOSS_CONFIG", "parser-case")
	rows := []struct {
		args    []string
		owner   string
		message string
	}{
		{
			args:    []string{"mail", "send", "--from", "human", "--file", "missing", "--life-id", "child"},
			owner:   "lb-v2-messaging",
			message: "unknown messaging flag or positional argument",
		},
		{
			args:    []string{"mail", "send", "--file", "missing", "--life-id", "child", "--channel-grant-id", "grant"},
			owner:   "lb-v2-messaging",
			message: "mail send requires exactly one immutable life or channel grant",
		},
		{
			// Draft.3's common parser rejects body flags with --request
			// before opening the file or invoking the messaging parser.
			args:    []string{"mail", "send", "--request", "missing", "--ask"},
			owner:   "",
			message: "--request accepts only an exact RPC body and common options",
		},
		{
			args:    []string{"mail", "send", "--file", "missing", "--life-id", "child", "--lane", "child"},
			owner:   "lb-v2-messaging",
			message: "duplicate messaging flag",
		},
		{
			args:    []string{"mail", "list", "--limit", "201"},
			owner:   "lb-v2-messaging",
			message: "mail list limit must be from 1 to 200",
		},
		{
			args:    []string{"mail", "list", "--file", "missing"},
			owner:   "lb-v2-messaging",
			message: "mail list does not accept send flags",
		},
		{
			args:    []string{"report", "submit", "--life-id", "parent", "--file", "missing"},
			owner:   "lb-v2-messaging",
			message: "report recipient is derived from the authentic starter",
		},
		{
			args:    []string{"lane", "send", "--file", "missing", "--life-id", "child", "--ask=true"},
			owner:   "lb-v2-messaging",
			message: "--ask is a send/report boolean flag",
		},
	}
	for i, row := range rows {
		var stdout, stderr bytes.Buffer
		args := append(row.args, "--config", "parser-case")
		code := cli.Run(args, nil, &stdout, &stderr)
		var failure api.Error
		if code != 2 || stdout.Len() != 0 || json.Unmarshal(stderr.Bytes(), &failure) != nil || failure.Code != api.CodeInvalid || failure.Owner != row.owner || failure.Message != row.message {
			t.Fatalf("invalid CLI cell %d: exit %d, error %s", i, code, stderr.Bytes())
		}
	}
}

func TestCLIRejectsBadFileBytes(t *testing.T) {
	t.Setenv("LANEBOSS_CONFIG", "parser-case")
	for i, body := range [][]byte{[]byte(" \n\t"), {0xff}, []byte("Bearer " + strings.Repeat("a1", 16))} {
		directory := t.TempDir()
		if err := os.Chmod(directory, 0700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, "message.txt")
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		key, err := client.NewRequestID()
		if err != nil {
			t.Fatal(err)
		}
		code := cli.Run([]string{"lane", "send", "--config", "parser-case", "--life-id", "child", "--file", path, "--idempotency-key", string(key)}, nil, &stdout, &stderr)
		var failure api.Error
		message := "mail must be nonempty UTF-8 text of at most 262144 bytes"
		if i == 2 {
			message = "mail contains a credential-shaped value; nothing was queued"
		}
		if code != 2 || stdout.Len() != 0 || json.Unmarshal(stderr.Bytes(), &failure) != nil || failure.Code != api.CodeInvalid || failure.Owner != "lb-v2-messaging" || failure.Message != message {
			t.Fatalf("invalid file cell %d: exit %d, error %s", i, code, stderr.Bytes())
		}
		if len(body) > 10 && bytes.Contains(stderr.Bytes(), body) {
			t.Fatal("CLI printed rejected credential bytes")
		}
	}
}

func TestCLIProofInputs(t *testing.T) {
	t.Setenv("LANEBOSS_CONFIG", "parser-case")
	key, err := client.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name    string
		flags   []string
		message string
	}{
		{"key", []string{"--file", "missing"}, "messaging mutation requires --idempotency-key ID retained for retries"},
		{"proof", []string{"--file", "missing", "--proof", "missing", "--idempotency-key", string(key)}, "a confirmed message requires --content-ref or --request; upload before confirmation"},
		{"exclusive", []string{"--file", "missing", "--content-ref", "missing", "--idempotency-key", string(key)}, "--file and --content-ref are exclusive"},
	} {
		t.Run(row.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			args := append([]string{"mail", "send", "--config", "parser-case", "--life-id", "child"}, row.flags...)
			code := cli.Run(args, nil, &stdout, &stderr)
			var failure api.Error
			if code != 2 || stdout.Len() != 0 || json.Unmarshal(stderr.Bytes(), &failure) != nil || failure.Code != api.CodeInvalid || failure.Owner != "lb-v2-messaging" || failure.Message != row.message {
				t.Fatalf("wrong CLI refusal: exit %d, error %s", code, stderr.Bytes())
			}
		})
	}
}

func TestCLIContentRef(t *testing.T) {
	t.Setenv("LANEBOSS_CONFIG", "parser-case")
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	key, err := client.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	for i, raw := range []string{
		`{"id":"object","sha256":"` + strings.Repeat("a", 64) + `","bytes":12,"class":"capture"}`,
		`{"id":"object","sha256":"` + strings.Repeat("a", 64) + `","bytes":12,"class":"report","extra":true}`,
		`null`,
	} {
		path := filepath.Join(directory, "content-ref.json")
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		code := cli.Run([]string{"mail", "send", "--config", "parser-case", "--life-id", "child", "--content-ref", path, "--idempotency-key", string(key)}, nil, &stdout, &stderr)
		var failure api.Error
		if code != 2 || stdout.Len() != 0 || json.Unmarshal(stderr.Bytes(), &failure) != nil || failure.Code != api.CodeInvalid || failure.Owner != "lb-v2-messaging" || failure.Message != "content reference must be an exact committed report blob" {
			t.Fatalf("wrong content-reference refusal in cell %d: exit %d, error %s", i, code, stderr.Bytes())
		}
	}
}

func TestCLIFileInputs(t *testing.T) {
	t.Setenv("LANEBOSS_CONFIG", "parser-case")
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	key, err := client.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	ref := api.BlobRef{ID: "committed-object", SHA256: api.Digest(strings.Repeat("a", 64)), Bytes: 12, Class: "report"}
	badArtifact := ref
	badArtifact.Class = "capture"
	for _, row := range []struct {
		method         string
		command        []string
		valid, invalid any
		message        string
	}{
		{"mail.send", []string{"mail", "send"}, api.MailSendRequest{RecipientLifeID: "child", Content: ref}, api.MailSendRequest{Content: ref}, "mail requires exactly one recipient life or human channel grant"},
		{"mail.list", []string{"mail", "list"}, api.ListRequest{Limit: 20}, api.ListRequest{Limit: 0}, "mail list requires a valid life, bounded cursor and limit from 1 to 200"},
		{"report.submit", []string{"report", "submit"}, api.ReportRequest{Content: ref, Artifacts: []api.BlobRef{}}, api.ReportRequest{Content: ref, Artifacts: []api.BlobRef{badArtifact}}, "report artifact reference is invalid"},
	} {
		for _, valid := range []bool{false, true} {
			suffix := "-invalid"
			if valid {
				suffix = "-valid"
			}
			t.Run(row.method+suffix, func(t *testing.T) {
				input := row.invalid
				if valid {
					input = row.valid
				}
				raw, err := json.Marshal(input)
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(directory, row.method+suffix+".json")
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
				args := append(append([]string{}, row.command...), "--config", "parser-case", "--request", path, "--binding", filepath.Join(directory, "uninstalled.json"))
				if valid {
					args = append(args, "--idempotency-key", string(key))
				} else {
					// A missing proof and key must not mask the semantic refusal.
					args = append(args, "--proof", filepath.Join(directory, "missing-proof.json"))
				}
				var stdout, stderr bytes.Buffer
				code := cli.Run(args, nil, &stdout, &stderr)
				var failure api.Error
				if stdout.Len() != 0 || json.Unmarshal(stderr.Bytes(), &failure) != nil {
					t.Fatalf("file form returned invalid output: exit %d", code)
				}
				if !valid {
					if code != 2 || failure.Code != api.CodeInvalid || failure.Owner != "lb-v2-messaging" || failure.Message != row.message {
						t.Fatalf("semantic file refusal was masked: exit %d, error %s", code, stderr.Bytes())
					}
					return
				}
				// Both the stand-in client and the real uninstalled client are
				// permitted boundaries. No other owner's stub message is pinned.
				accepted := failure.Code == api.CodePrerequisite || failure.Code == api.CodeNotImplemented || failure.Code == api.CodeUnavailable || failure.Code == api.CodeUnsupported
				if code != 69 || !accepted || failure.Owner == "lb-v2-messaging" {
					t.Fatalf("valid file did not reach a transport or binding boundary: exit %d, error %s", code, stderr.Bytes())
				}
			})
		}
	}
}
