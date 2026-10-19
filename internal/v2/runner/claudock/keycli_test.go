//go:build linux && laneboss_vendor

package claudock

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// The dependencies supply synthetic authority, but both executables are the
// public pinned vendors. Only a generated fake key reaches the network.
func TestKeyVendor(t *testing.T) {
	wrapper, vendor := keyVendors(t)
	for _, mismatch := range []bool{false, true} {
		name := "key"
		if mismatch {
			name = "wrong-kind"
		}
		t.Run(name, func(t *testing.T) {
			f := runnerReady(t, nil)
			f.request.Slot.Mode = "claude-api-key"
			f.service.deps.ExecutablePath = wrapper
			f.service.deps.ClaudePath = vendor
			f.service.deps.Executable.SHA256 = contentDigest(get(t, wrapper))
			f.service.deps.Claude.SHA256 = contentDigest(get(t, vendor))
			f.request.Executable = f.service.deps.Executable
			f.service.deps.RuntimePath = "/runtime/claudock"
			f.service.deps.VerifyMode = func(_ context.Context, w, v api.Executable, mode string) error {
				if w != f.service.deps.Executable || v != f.service.deps.Claude || mode != "claude-api-key" {
					t.Fatal("vendor identity or slot mode changed")
				}
				return nil
			}
			f.sourceLaunch(t, "start")
			plan, err := f.service.Start(context.Background(), f.request)
			if err != nil {
				t.Fatal(err)
			}
			key := flagKey(t)
			defer clear(key)
			store, err := EncodeKeyStore(key)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(store)
			if mismatch {
				path := filepath.Join(f.home.path, ".config/claudock/profiles.json")
				var registry registryProjection
				if err := json.Unmarshal(get(t, path), &registry); err != nil {
					t.Fatal(err)
				}
				selected := "claude-" + plan.Argv[2]
				if plan.Argv[2] == "claude" {
					selected = "claude"
				}
				found := false
				for i := range registry.Profiles {
					if registry.Profiles[i].Command == selected {
						registry.Profiles[i].AuthKind = "subscription"
						found = true
					}
				}
				if !found {
					t.Fatal("wrong-kind twin never selected a profile")
				}
				data, err := json.Marshal(registry)
				if err != nil || os.Chmod(path, 0600) != nil {
					t.Fatal("cannot prepare mismatched profile")
				}
				put(t, path, data)
				if err := os.Chmod(path, 0400); err != nil {
					t.Fatal(err)
				}
				if err := f.home.checkProjection("claude-api-key"); err == nil || !strings.Contains(err.Error(), "private API key profile differs") {
					t.Fatal("V2 did not refuse the actual profile-kind mismatch")
				}
			}
			put(t, filepath.Join(f.home.path, KeyStorePath), store)
			args := []string{"--unshare-user", "--unshare-pid", "--die-with-parent", "--tmpfs", "/",
				"--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib",
				"--symlink", "usr/lib64", "/lib64", "--ro-bind", "/etc/ssl", "/etc/ssl",
				"--ro-bind", "/etc/resolv.conf", "/etc/resolv.conf", "--ro-bind", "/etc/hosts", "/etc/hosts",
				"--ro-bind", "/etc/nsswitch.conf", "/etc/nsswitch.conf", "--ro-bind", "/etc/passwd", "/etc/passwd",
				"--tmpfs", "/home", "--dir", "/home/lane", "--bind", f.home.path, "/home/lane",
				"--tmpfs", "/runtime", "--ro-bind", wrapper, "/runtime/claudock", "--ro-bind", vendor, "/runtime/claude",
				"--tmpfs", "/work", "--dir", "/work/main", "--tmpfs", "/tmp", "--proc", "/proc", "--dev", "/dev",
				"--chdir", plan.CWD}
			args = append(args, plan.Argv...)
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "bwrap", args...)
			cmd.Env = []string{"HOME=/home/lane", "PATH=/usr/bin:/bin:/runtime", "TMPDIR=/tmp",
				"CLAUDE_CONFIG_DIR=/home/lane/.claude", "CLAUDOCK_REGISTRY_DIR=/home/lane/.config/claudock",
				"CLAUDOCK_CREDENTIAL_STORE=file:/home/lane/" + KeyStorePath, "ANTHROPIC_API_KEY=" + string(key),
				"DISABLE_AUTOUPDATER=1", "CLAUDE_CODE_DISABLE_" + "NONESSENTIAL_TRAFFIC=1"}
			cmd.Stdin = strings.NewReader("Reply with OK.\n")
			output, runErr := cmd.CombinedOutput()
			if bytes.Contains(output, key) || len(key) >= 8 && bytes.Contains(output, key[len(key)-8:]) {
				t.Fatal("vendor capture exposed the fake credential")
			}
			result, noKey, unauthorized := false, false, false
			for _, line := range bytes.Split(output, []byte{'\n'}) {
				var event struct {
					Type      string `json:"type"`
					IsError   bool   `json:"is_error"`
					KeySource string `json:"apiKeySource"`
					Status    int    `json:"api_error_status"`
				}
				if json.Unmarshal(line, &event) == nil && event.Type == "system" && event.KeySource == "none" {
					noKey = true
				}
				if json.Unmarshal(line, &event) == nil && event.Type == "result" && event.IsError {
					result = true
					unauthorized = event.Status == 401
					t.Log("Claude capture:", string(line))
				}
			}
			if mismatch {
				if runErr == nil || !result || !noKey || !bytes.Contains(output, []byte("Not logged in")) {
					t.Fatalf("wrong-kind profile did not fail without the API key: %s", output)
				}
				t.Log("wrong-kind profile actually selected; V2 refused its shape and vendor observed no API key")
			} else if !result || !unauthorized || runErr == nil || !bytes.Contains(bytes.ToLower(output), []byte("api key")) {
				t.Fatalf("fake key did not reach Claude auth result: %s", output)
			}
		})
	}
}

// Use the actual --canary-api-key entry, rather than a separately shaped key.
// Descriptor 3 is a private test pipe; no key enters command output or argv.
func flagKey(t *testing.T) []byte {
	t.Helper()
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", "-I", "-B", "../../../../scripts/v2-serve/key_route.py")
	cmd.ExtraFiles, cmd.Stdout, cmd.Stderr = []*os.File{write}, io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		write.Close()
		t.Fatal("cannot start the fake flag source")
	}
	if err := write.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(io.LimitReader(read, MaxAPIKeyBytes+5))
	defer clear(raw)
	if waitErr := cmd.Wait(); err != nil || waitErr != nil || len(raw) < 5 ||
		int(binary.BigEndian.Uint32(raw[:4])) != len(raw)-4 {
		t.Fatal("fake flag source did not deliver one bounded private key")
	}
	return bytes.Clone(raw[4:])
}

func keyVendors(t *testing.T) (string, string) {
	t.Helper()
	root := temporary(t)
	command := func(program string, args ...string) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, program, args...)
		cmd.Env = []string{"HOME=" + root, "PATH=/usr/bin:/bin", "LANG=C"}
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("vendor setup %s failed: %s", filepath.Base(program), output)
		}
		return output
	}
	base := "https://github.com/laneboss-io/" + "claudock-cli/releases/download/v0.1.0/"
	asset := "claudock_0.1.0_linux_" + runtime.GOARCH + ".tar.gz"
	archive := filepath.Join(root, asset)
	command("curl", "-fsSL", "--output", archive, base+asset)
	sums := command("curl", "-fsSL", base+"SHA256SUMS")
	sum := sha256.Sum256(get(t, archive))
	if !bytes.Contains(sums, []byte(hex.EncodeToString(sum[:])+"  "+asset)) {
		t.Fatal("vendor archive checksum differs")
	}
	command("tar", "-xzf", archive, "-C", root)
	wrapper := filepath.Join(root, "claudock")
	version := command(wrapper, "version")
	if strings.TrimSpace(string(version)) != "Claudock 0.1.0" {
		t.Fatalf("pinned wrapper version differs: %s", version)
	}
	t.Logf("actual released wrapper version: %s", bytes.TrimSpace(version))
	installer := filepath.Join(root, "install.sh")
	command("curl", "-fsSL", "--output", installer, "https://claude.ai/install.sh")
	command("bash", installer, "2.1.296")
	vendor, err := filepath.EvalSymlinks(filepath.Join(root, ".local/bin/claude"))
	if err != nil || !strings.HasPrefix(vendor, root+"/") {
		t.Fatal("vendor installer escaped its private home")
	}
	if !bytes.HasPrefix(command(vendor, "--version"), []byte("2.1.296")) {
		t.Fatal("Claude version differs")
	}
	for _, path := range []string{wrapper, vendor} {
		if err := os.Chmod(path, 0555); err != nil {
			t.Fatal("cannot pin vendor executable permissions")
		}
	}
	return wrapper, vendor
}
