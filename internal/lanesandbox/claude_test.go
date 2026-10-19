package lanesandbox

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestNativeClaude(t *testing.T) {
	home := filepath.Join(t.TempDir(), ".claude")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, "settings.json")
	input := []byte(`{"sandbox":{"enabled":true,"allowUnsandboxedCommands":false}}`)
	if err := os.WriteFile(path, input, 0600); err != nil {
		t.Fatal(err)
	}
	argv := []string{"claude", "--settings", path, "-p"}
	configs := []map[string]any{{"lanes": map[string]any{"sandbox": "off"}}}
	if runtime.GOOS == "linux" {
		configs = append(configs, map[string]any{"lanes": map[string]any{"sandbox": Mode}})
	}
	for _, data := range configs {
		prepared, err := ClaudeOverlay(argv, data)
		if err != nil || !reflect.DeepEqual(argv, prepared) {
			t.Fatal("native invocation changed its settings selector", err)
		}
		actual, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(input, actual) {
			t.Fatal("native invocation changed the org settings", err)
		}
		if _, err := os.Stat(filepath.Join(home, claudeOverlayDir)); !os.IsNotExist(err) {
			t.Fatal("native invocation created an overlay", err)
		}
	}
}
