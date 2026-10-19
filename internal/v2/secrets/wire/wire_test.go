package wire_test

import (
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

func TestStrictRequestDecode(t *testing.T) {
	valid := []byte(`{"name":"canary","version":"one","sealed_upload_id":"stage-a"}`)
	var got api.SecretImportRequest
	if err := wire.Decode(valid, &got, 4096); err != nil || got.Name != "canary" || got.SealedUploadID != "stage-a" {
		t.Fatal("valid request was not decoded")
	}
	bad := []string{
		`{"name":"a","name":"b","version":"one","sealed_upload_id":"s"}`,
		`{"name":"a","version":"one"}`,
		`{"name":"a","version":"one","sealed_upload_id":null}`,
		`{"name":"a","version":"one","sealed_upload_id":"s","extra":1}`,
		`[]`, `null`, `{}`, string(valid) + `{}`, "\xff",
		`{"name":"a","version":"one","sealed_upload_id":[` + strings.Repeat("[", 40) +
			`"s"` + strings.Repeat("]", 40) + `]}`,
	}
	for i, data := range bad {
		if err := wire.Decode([]byte(data), &got, 4096); err == nil {
			t.Fatalf("invalid JSON control %d was accepted", i)
		}
	}
	if err := wire.Decode(valid, &got, len(valid)-1); err == nil {
		t.Fatal("request size limit was ignored")
	}
	var result api.SecretList
	if err := wire.Decode([]byte(`{"secrets":[]}`), &result, 4096); err != nil || result.Secrets == nil {
		t.Fatal("empty result array differs")
	}
	for _, data := range []string{`{"secrets":null}`, `{"secrets":[{"name":"a"}]}`} {
		if err := wire.Decode([]byte(data), &result, 4096); err == nil {
			t.Fatal("incomplete nested result was accepted")
		}
	}
}

func TestTargetBlacklist(t *testing.T) {
	for _, name := range []string{"TASK_TOKEN", "APP_DATA_KEY", "_PRIVATE_DATA", "CUSTOM_2"} {
		if !wire.EnvTarget(name) {
			t.Fatal("ordinary task environment target was refused")
		}
	}
	for _, name := range []string{"HOME", "PATH", "TMPDIR", "CODEX_HOME", "CLAUDE_CONFIG_DIR",
		"LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "LANEBOSS_BINDING", "BASH_ENV", "SSH_AUTH_SOCK",
		"GIT_CONFIG_COUNT", "PYTHONPATH", "NODE_OPTIONS", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
		"SYSTEMD_EXEC_PID", "LISTEN_FDS", "IFS", "GLIBC_TUNABLES", "ZDOTDIR", "FPATH",
		"PROMPT_COMMAND", "TZDIR", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "MALLOC_CHECK_",
		"MALLOC_ARENA_MAX", "bad=name", "bad-name", "", "1_BAD"} {
		if wire.EnvTarget(name) {
			t.Fatal("reserved or invalid environment target was accepted")
		}
	}
	for _, name := range []string{"token", "service/token", "cert.pem", ".token", "_private"} {
		if !wire.FileTarget(name) {
			t.Fatal("ordinary private file target was refused")
		}
	}
	for _, name := range []string{"..", "../escape", "/absolute", "a/../b", "a//b", "a/", ".", "a\\b"} {
		if wire.FileTarget(name) {
			t.Fatal("escaping or ambiguous file target was accepted")
		}
	}
}

func TestExactJSONKeys(t *testing.T) {
	var request api.SecretImportRequest
	for _, data := range []string{
		`{"name":"canary","Name":"other","version":"one","sealed_upload_id":"stage-a"}`,
		`{"name":"canary","version":"one","Version":"two","sealed_upload_id":"stage-a"}`,
	} {
		if err := wire.Decode([]byte(data), &request, 4096); err == nil {
			t.Fatal("case-alias request field was accepted")
		}
	}
	var result api.SecretList
	nested := `{"secrets":[{"name":"canary","version":"one","source_handle":"source-a",` +
		`"key_id":"key-a","revoked":false,"Revoked":true}]}`
	if err := wire.Decode([]byte(nested), &result, 4096); err == nil {
		t.Fatal("nested case-alias field was accepted")
	}
}
