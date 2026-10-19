//go:build linux && laneboss_root_canary

package admin

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestLaneClientAncestors(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("lane client ancestor canary requires disposable Linux root")
	}
	base, err := os.MkdirTemp("/run", "lb-v2-serve2-client-")
	if err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(base, "release")
	if err := os.Mkdir(parent, 0755); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(parent, "client")
	t.Cleanup(func() {
		for _, path := range []string{name, parent, base} {
			if err := os.Remove(path); err != nil {
				t.Error(err)
			}
		}
	})
	data := []byte("ordinary pinned client input\n")
	if err := os.WriteFile(name, data, 0555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(name, 0555); err != nil {
		t.Fatal(err)
	}
	artifact := api.ReleaseArtifact{OS: "linux", Arch: runtime.GOARCH, Bytes: int64(len(data)), SHA256: digestBytes(data)}
	client, err := pinLaneClient(name, artifact)
	if err != nil {
		t.Fatal("protected client control could not retain its actual bytes", err)
	}
	if err := client.file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0777); err != nil {
		t.Fatal(err)
	}
	client, err = pinLaneClient(name, artifact)
	if client != nil {
		client.file.Close()
	}
	if err == nil || client != nil {
		t.Fatal("acceptance: lane client accepted an untrusted ancestor")
	}
}
