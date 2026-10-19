//go:build linux && !laneboss_root_canary

package policycase

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// This runs the actual canceled vendor startup at its installed home/work
// namespace paths, using the real policy boot and assembler's project,
// task and baseline Codex selection with all five extra profiles present.
// It measures real Git dirt; it is not an installed helper/Clean E2E claim.
func TestPolicyStartDirt(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Fatal("startup controls require the nonroot Linux phase")
	}
	source, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(t.TempDir(), "policy-input.json")
	probe := exec.Command("python3", "-I", "-B", filepath.Join(source, "e2e", "v2", "cases", "policy", "l_probe.py"), "--output", input)
	if out, err := probe.CombinedOutput(); err != nil {
		t.Fatalf("actual policy boot: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	var in startInput
	if err := json.Unmarshal(raw, &in); err != nil {
		t.Fatal(err)
	}
	var start api.StartRequest
	for _, row := range in.Launches {
		if row.Driver == api.DriverCodex {
			start = row
		}
	}
	selected, extra := false, map[api.ID]bool{}
	for _, row := range in.Ceiling.Profiles {
		if row.ID == start.ProfileGrantID {
			selected = row.ProfileID == "serve-profile-codex"
		}
		if strings.HasPrefix(string(row.ProfileID), "policy-profile-") {
			extra[row.ProfileID] = true
		}
	}
	if !selected || len(extra) != 5 || start.Level != 5 || start.Role != "supervisor" {
		t.Fatal("baseline Codex or independent policy profile selection changed")
	}
	binary := filepath.Join(t.TempDir(), "policy-prefix")
	build := exec.Command("go", "test", "-c", "-o", binary, "./scripts/v2-serve/policy_agent")
	build.Dir = source
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("actual prefix build: %v\n%s", err, out)
	}
	prompt := in.blob(t, start.Task)
	for _, own := range []bool{false, true} {
		name := "baseline"
		if own {
			name = "real-work"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			work, home := filepath.Join(root, "work"), filepath.Join(root, "home")
			for _, path := range []string{work, home} {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			var tree api.ObjectManifest
			if err := json.Unmarshal(in.blob(t, in.Project), &tree); err != nil || len(tree.Entries) == 0 {
				t.Fatal("actual policy project is absent", err)
			}
			for _, entry := range tree.Entries {
				if entry.Kind != "file" || !filepath.IsLocal(entry.Path) || entry.Content == nil {
					t.Fatal("startup fixture needs the actual bounded policy file tree")
				}
				if err := os.WriteFile(filepath.Join(work, entry.Path), in.blob(t, *entry.Content), os.FileMode(entry.Mode)); err != nil {
					t.Fatal(err)
				}
			}
			startGit(t, work, "init", "--quiet")
			startGit(t, work, "add", "--all")
			startGit(t, work, "-c", "user.name=fixture", "-c", "user.email=fixture", "commit", "--quiet", "-m", "initial")
			owned := append([]byte("uncommitted lane work\n"), prompt...)
			if own {
				if err := os.WriteFile(filepath.Join(work, "owned.txt"), owned, 0600); err != nil {
					t.Fatal(err)
				}
			}
			cancelStartup(t, binary, work, home, prompt)
			status := startGit(t, work, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignored=matching", "--ignore-submodules=all")
			if !own && len(status) != 0 {
				t.Fatalf("startup dirt: Git status=%q", status)
			}
			if own {
				kept, err := os.ReadFile(filepath.Join(work, "owned.txt"))
				if err != nil || !bytes.Equal(kept, owned) || len(status) == 0 {
					t.Fatal("startup changed or concealed real uncommitted work", err)
				}
			}
			retained, err := os.ReadFile(filepath.Join(home, "policy-start", "prompt.input"))
			if err != nil || !bytes.Equal(retained, prompt) {
				t.Fatal("startup lost its actual retained input", err)
			}
		})
	}
}

type startInput struct {
	Ceiling   api.GrantSet       `json:"ceiling"`
	Launches  []api.StartRequest `json:"launches"`
	Project   api.BlobRef        `json:"project"`
	Documents []struct {
		Ref  api.BlobRef `json:"ref"`
		Data []byte      `json:"data"`
	} `json:"documents"`
}

func (in startInput) blob(t *testing.T, ref api.BlobRef) []byte {
	t.Helper()
	for _, row := range in.Documents {
		if row.Ref == ref {
			sum := sha256.Sum256(row.Data)
			if int64(len(row.Data)) != ref.Bytes || api.Digest(hex.EncodeToString(sum[:])) != ref.SHA256 {
				t.Fatal("policy bytes changed")
			}
			return row.Data
		}
	}
	t.Fatal("policy input blob absent")
	return nil
}

func startGit(t *testing.T, work string, args ...string) []byte {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", work}, args...)...)
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "LC_ALL=C"}
	out, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("prefix Git: %v\n%s", err, out)
	}
	return out
}

func cancelStartup(t *testing.T, binary, work, home string, prompt []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "bwrap", "--unshare-user", "--unshare-net", "--die-with-parent", "--new-session",
		"--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
		"--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--bind", home, "/home/lane", "--bind", work, "/work/main",
		"--chdir", "/work/main", "--ro-bind", binary, "/run/laneboss/client", "--ro-bind", binary, "/prefix-test",
		"--", "/prefix-test", "--", "policy-start-child")
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=/home/lane", "GOMAXPROCS=1"}
	command.Stdin = bytes.NewReader(prompt)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("actual canceled startup prefix failed: %v\n%s", err, output)
	}
}
