//go:build linux && laneboss_partial && laneboss_e2e_authenticator

package admin

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func TestUsageFixturePinned(t *testing.T) {
	executable := api.Executable{ID: "vendor", SHA256: digestBytes([]byte("actual fixture executable pin")), Version: "component"}
	raw := []byte(`{"schema":"laneboss.serve-agent.v1","config":"usage-case","vendor_stood_in":true,"executable":{"id":"vendor","sha256":"` + string(executable.SHA256) + `","version":"component"}}`)
	path := filepath.Join(t.TempDir(), "fixture.json")
	if err := os.WriteFile(path, raw, 0444); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(path, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), "pinned-fixture")
	defer file.Close()
	manifest := api.RuntimeManifest{Objects: []api.RuntimeObject{{ID: "fixture", Role: "serve-fixture-config", Mode: 0444, Content: api.BlobRef{ID: "fixture-bytes", Class: "artifact", Bytes: int64(len(raw)), SHA256: digestBytes(raw)}}}}
	value, err := usageFixtureRuntime(manifest, []*nativeMount{{file: file, target: "/runtime/fixture"}}, executable, "usage-case")
	if err != nil || !value {
		t.Fatal("usage fixture cannot read its actual pinned O_PATH inode", err)
	}
	manifest.Objects[0].Content.SHA256 = digestBytes(append(raw, 'x'))
	if value, err := usageFixtureRuntime(manifest, []*nativeMount{{file: file, target: "/runtime/fixture"}}, executable, "usage-case"); err == nil || value {
		t.Fatal("usage fixture accepted changed descriptor bytes")
	}
}
