//go:build linux && laneboss_root_canary && laneboss_isolation_recovery

package secretscase_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// This opt-in queue adapter follows cases/linux/test-box.md: install the real
// test executable as root, then run those exact bytes as the source owner.
// It retains the child output and never changes a kernel or product guard.
func TestInstalledIsolationRecovery(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("isolation recovery requires the authorized root queue process")
	}
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	source, err := filepath.Abs(filepath.Join(directory, "../../../.."))
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(source)
	if err != nil {
		t.Fatal(err)
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid == 0 || owner.Gid == 0 {
		t.Fatal("isolation recovery requires its original nonroot source owner")
	}
	root, err := os.MkdirTemp("/opt", "lb-v2-case-secrets-isolation-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "home")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(home, int(owner.Uid), int(owner.Gid)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	staged := filepath.Join(root, "built.test")
	build := exec.CommandContext(ctx, "go", "test", "-mod=readonly", "-c", "-o", staged, "./internal/v2/isolation/linux")
	build.Dir = source
	output, err := build.CombinedOutput()
	if saveErr := os.WriteFile(filepath.Join(root, "build.log"), output, 0600); saveErr != nil {
		t.Fatal(saveErr)
	}
	if err != nil {
		t.Fatal("isolation recovery build failed; retained build.log", err)
	}
	binary := filepath.Join(root, "linux.test")
	install := exec.CommandContext(ctx, "install", "-o", "root", "-g", "root", "-m", "0755", staged, binary)
	if output, err := install.CombinedOutput(); err != nil {
		if saveErr := os.WriteFile(filepath.Join(root, "install.log"), output, 0600); saveErr != nil {
			t.Fatal(saveErr)
		}
		t.Fatal("isolation recovery install failed", err)
	}
	data, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "binary.sha256"), []byte(fmt.Sprintf("%x\n", sha256.Sum256(data))), 0600); err != nil {
		t.Fatal(err)
	}
	child := exec.CommandContext(ctx, binary, "-test.v", "-test.timeout=10m")
	child.Dir = root
	child.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "HOME=" + home}
	child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: owner.Uid, Gid: owner.Gid}}
	output, runErr := child.CombinedOutput()
	if err := os.WriteFile(filepath.Join(root, "tests.log"), output, 0600); err != nil {
		t.Fatal(err)
	}
	code := 0
	if runErr != nil {
		code = 1
		if exit, ok := runErr.(*exec.ExitError); ok {
			code = exit.ExitCode()
		}
	}
	if err := os.WriteFile(filepath.Join(root, "exit.txt"), []byte(fmt.Sprintf("%d\n", code)), 0600); err != nil {
		t.Fatal(err)
	}
	passed, failed, skipped := 0, 0, 0
	for _, line := range strings.Split(string(output), "\n") {
		switch {
		case strings.HasPrefix(line, "--- PASS:"):
			passed++
		case strings.HasPrefix(line, "--- FAIL:"):
			failed++
			t.Log(line)
		case strings.HasPrefix(line, "--- SKIP:"):
			skipped++
			t.Log(line)
		case strings.Contains(line, "install the test binary"):
			t.Log(line)
		case strings.Contains(line, "prerequisite") || strings.Contains(line, "probe did") || strings.Contains(line, "pinned binary behavior failed") || strings.Contains(line, "HOME"):
			t.Log(line)
		}
	}
	t.Logf("retained isolation recovery evidence: %s; passed=%d failed=%d skipped=%d", root, passed, failed, skipped)
	if runErr != nil || passed == 0 || failed != 0 || skipped != 0 {
		t.Fatal("installed nonroot isolation checks did not pass", runErr)
	}
}
