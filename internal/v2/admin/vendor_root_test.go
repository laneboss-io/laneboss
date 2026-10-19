//go:build linux && laneboss_root_canary

package admin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestVendorProjection(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("requires the disposable root Linux box")
	}
	if err := os.MkdirAll("/usr/lib/laneboss-v2", 0755); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("/usr/lib/laneboss-v2", "vendor-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	base := filepath.Join(dir, "runtime", "vendor")
	root := filepath.Join(base, "objects")
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "claude")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0555)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Truncate(65 << 20); err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		t.Fatal(err)
	}
	pin := api.Digest(hex.EncodeToString(hash.Sum(nil)))
	artifact := api.Executable{ID: "claude", SHA256: pin, Version: filepath.Base(dir)}
	binding := testBinding()
	binding.Release.Version, binding.Artifact.SHA256, binding.Config = artifact.Version, pin, "vendor"
	object := api.RuntimeObject{ID: "claude", Role: "claude", RootID: "objects", RelativePath: "claude", Mode: 0555,
		Content: api.BlobRef{ID: "claude", Class: "artifact", Bytes: 65 << 20, SHA256: pin}}
	for _, fault := range []string{"valid", "byte", "mode", "oversize", "other"} {
		t.Run(fault, func(t *testing.T) {
			selected := object
			if _, err := f.WriteAt([]byte{0}, 0); err != nil {
				t.Fatal(err)
			}
			if err := f.Truncate(65 << 20); err != nil {
				t.Fatal(err)
			}
			if err := f.Chmod(0555); err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "byte":
				if _, err := f.WriteAt([]byte{1}, 0); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := f.Chmod(0755); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				if err := f.Truncate((512 << 20) + 1); err != nil {
					t.Fatal(err)
				}
				selected.Content.Bytes = (512 << 20) + 1
			case "other":
				selected.Role = "library"
			}
			raw := initialEncode(t, api.RuntimeManifest{Schema: "laneboss.runtime.v2", Generation: 1, Artifact: artifact, Bootstrap: artifact, Objects: []api.RuntimeObject{selected}, Bindings: []api.InstalledBinding{}})
			if err := os.WriteFile(filepath.Join(base, "manifest.json"), raw, 0444); err != nil {
				t.Fatal(err)
			}
			roots := initialEncode(t, []enrolledRoot{{ID: "objects", Path: root}})
			if err := os.WriteFile(filepath.Join(base, "roots.json"), roots, 0444); err != nil {
				t.Fatal(err)
			}
			ref := api.BlobRef{ID: "runtime", Class: "manifest", Bytes: int64(len(raw)), SHA256: digestBytes(raw)}
			_, loadErr := loadInstalledRuntime(context.Background(), binding, ref)
			reader := &Service{binding: binding, deps: Dependencies{Config: binding.Config, RuntimeManifest: ref}}
			retained, readErr := reader.ReadCleanupRuntime(context.Background(), selected.Content)
			manager := &leaseManager{binding: binding}
			record := leaseRecord{Spec: &specRegistration{Handoff: api.PreparedSpecHandoff{Spec: api.LaunchSpec{RuntimeManifest: ref}}}}
			_, mounts, gateErr := manager.gateMounts(context.Background(), record)
			defer func() {
				for _, mount := range mounts {
					mount.file.Close()
				}
			}()
			if fault != "valid" {
				if loadErr == nil || gateErr == nil || readErr == nil {
					t.Fatal("altered or unbounded projection accepted", loadErr, gateErr, readErr)
				}
				return
			}
			if loadErr != nil || gateErr != nil || len(mounts) != 2 || mounts[0].target != "/runtime/claude" || mounts[0].writable {
				t.Fatal("65 MiB vendor projection failed", loadErr, gateErr)
			}
			if readErr != nil || retained.Ref != selected.Content || retained.Role != "runtime" || retained.OwnerLifeID != "" || retained.Identity == "" || retained.RootIdentity == "" {
				t.Fatal("65 MiB installed runtime was unresolved by cleanup", readErr)
			}
			stamp := time.Now().Add(time.Hour)
			if err := os.Chtimes(path, stamp, stamp); err != nil {
				t.Fatal(err)
			}
			touched, err := reader.ReadCleanupRuntime(context.Background(), selected.Content)
			if err != nil || touched != retained {
				t.Fatal("touch wedged the protected runtime identity", err)
			}
			args, _ := nativeGateArgs("vendor", "agent", nil, mounts, true)
			if !strings.Contains(strings.Join(args, " "), "--ro-bind-fd") {
				t.Fatal("vendor projection lost its read-only bind")
			}
		})
	}
}

func TestVendorPython(t *testing.T) {
	cmd := exec.Command("python3", "vendor_test.py")
	cmd.Dir = "../../../scripts/v2-serve"
	output, err := cmd.CombinedOutput()
	for _, line := range strings.Split(string(output), "\n") {
		t.Log(line)
	}
	if err != nil {
		t.Fatal("vendor Python regressions", err)
	}
}
