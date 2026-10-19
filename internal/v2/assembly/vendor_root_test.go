//go:build linux && laneboss_root_canary

package assembly

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestVendorLoad(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("requires the disposable root Linux box")
	}
	if os.Args[len(os.Args)-1] != "vendor-child" {
		dir, err := os.MkdirTemp("/opt", "lb-vendor-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(dir) })
		self, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		in, err := os.Open(self)
		if err != nil {
			t.Fatal(err)
		}
		defer in.Close()
		path := filepath.Join(dir, "canary")
		out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0555)
		if err != nil {
			t.Fatal(err)
		}
		_, copyErr := io.Copy(out, in)
		if err := out.Close(); err != nil || copyErr != nil {
			t.Fatal("copy test executable", err, copyErr)
		}
		output, err := exec.Command(path, "-test.run=^TestVendorLoad$", "-test.v", "--", "vendor-child").CombinedOutput()
		t.Log(string(output))
		if err != nil {
			t.Fatal("vendor load regression", err)
		}
		return
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(filepath.Dir(self), "runtime", "vendor")
	root := filepath.Join(dir, "objects")
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatal(err)
	}
	objects := []api.RuntimeObject{}
	for _, name := range []string{"claudock", "claude"} {
		path := filepath.Join(root, name)
		file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0555)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(65 << 20); err != nil {
			t.Fatal(err)
		}
		hash := sha256.New()
		if _, err := io.Copy(hash, file); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		objects = append(objects, api.RuntimeObject{ID: api.ID(name), Role: name, RootID: "objects", RelativePath: name, Mode: 0555,
			Content: api.BlobRef{ID: api.ID(name), Class: "artifact", Bytes: 65 << 20, SHA256: api.Digest(hex.EncodeToString(hash.Sum(nil)))}})
	}
	artifact := api.Executable{ID: "release", Version: "test", SHA256: runDigest([]byte("release"))}
	roots, err := json.Marshal([]runtimeRoot{{ID: "objects", Path: root}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "roots.json"), roots, 0444); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"valid", "byte", "mode", "oversize", "other", "missing-session", "session-pin"} {
		t.Run(fault, func(t *testing.T) {
			selected := append([]api.RuntimeObject{}, objects...)
			path := filepath.Join(root, "claude")
			file, err := os.OpenFile(path, os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			if _, err := file.WriteAt([]byte{0}, 0); err != nil {
				t.Fatal(err)
			}
			if err := file.Truncate(65 << 20); err != nil {
				t.Fatal(err)
			}
			if err := file.Chmod(0555); err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "byte":
				if _, err := file.WriteAt([]byte{1}, 0); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := file.Chmod(0755); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				if err := file.Truncate((512 << 20) + 1); err != nil {
					t.Fatal(err)
				}
				selected[1].Content.Bytes = (512 << 20) + 1
			case "other":
				selected = append(selected, api.RuntimeObject{ID: "library", Role: "library", RootID: "objects", RelativePath: "claude", Mode: 0555, Content: objects[1].Content})
			}
			raw, err := json.Marshal(api.RuntimeManifest{Schema: "laneboss.runtime.v2", Generation: 1, Artifact: artifact, Objects: selected, Bindings: []api.InstalledBinding{}})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0444); err != nil {
				t.Fatal(err)
			}
			installed := Installation{Config: "vendor", ArtifactSHA256: artifact.SHA256,
				RuntimeManifest: api.BlobRef{ID: "runtime", Class: "manifest", Bytes: int64(len(raw)), SHA256: runDigest(raw)}}
			wrapper := api.Executable{ID: "claudock", SHA256: objects[0].Content.SHA256, Version: "enrolled-wrapper-release"}
			vendor := api.Executable{ID: "claude", SHA256: objects[1].Content.SHA256, Version: "enrolled-history-release"}
			if fault == "session-pin" {
				vendor.SHA256 = runDigest([]byte("different vendor"))
			}
			writeRealSessionEnrollment(t, dir, &installed, wrapper, vendor)
			if fault == "missing-session" {
				installed.LaunchEnrollment = nil
			}
			actual, err := loadRealRuntime(installed)
			if fault == "valid" {
				if err != nil || actual == nil || actual.Claude != vendor || actual.Wrapper != wrapper {
					t.Fatal("65 MiB vendor load lost its pins", err)
				}
			} else if err == nil {
				t.Fatal("runtime accepted altered or unbounded bytes", fault)
			}
		})
	}
}
