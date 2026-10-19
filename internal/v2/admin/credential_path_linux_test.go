//go:build linux

package admin

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCredentialPathBounds(t *testing.T) {
	longest := 0
	for size := 1; size <= 32; size++ {
		config := strings.Repeat("a", size)
		b := installation{Config: config}
		paths := []string{
			filepath.Join(b.credentialRuntimePath(), "credential-broker.sock"),
			filepath.Join(b.credentialRuntimePath(), "credential-identity.sock"),
			filepath.Join(b.credentialRuntimePath(), "component.sock"),
			filepath.Join(b.credentialRuntimePath(), "owners", "broker", "credential-broker.sock"),
			filepath.Join(b.credentialRuntimePath(), "owners", "identity", "credential-identity.sock"),
			filepath.Join(b.credentialRuntimePath(), "owners", "identity", "credential-component.sock"),
		}
		for _, path := range paths {
			if len(path) > 90 {
				t.Fatalf("acceptance: credential socket path exceeds its 90-byte budget: config_bytes=%d socket=%s path_bytes=%d", size, filepath.Base(path), len(path))
			}
			longest = max(longest, len(path))
		}
		sum := sha256.Sum256([]byte(config))
		if b.credentialRuntimePath() != filepath.Join("/run/lb-v2-cred", hex.EncodeToString(sum[:16])) {
			t.Fatal("acceptance: credential runtime differs from the fixed 32-hex configuration hash")
		}
	}
	for _, name := range []string{"laneboss-helper", "laneboss-service", "laneboss-credential"} {
		data, err := os.ReadFile(filepath.Join("../../../packaging/v2/linux", name+".service.in"))
		if err != nil {
			t.Fatal(err)
		}
		for _, token := range strings.Fields(string(data)) {
			if strings.Contains(token, "/") && len(token) >= 40 {
				t.Fatalf("acceptance: unit path token exceeds the publication limit: unit=%s token_bytes=%d", name, len(token))
			}
		}
	}
	t.Logf("credential paths: config_max_bytes=32 hash_hex_chars=32 socket_max_bytes=%d socket_limit_bytes=108 unit_path_tokens_under_40=true", longest)
}
