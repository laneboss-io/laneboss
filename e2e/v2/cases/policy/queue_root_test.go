//go:build linux && laneboss_root_canary

package policycase

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPolicyQueueOwnership(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("queue UID canary requires the authorized root Linux box")
	}
	root, err := os.MkdirTemp("/tmp", "lb-policy-queue-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	})
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	queue := filepath.Join(root, "queue")
	if err := os.Mkdir(queue, 0700); err != nil {
		t.Fatal(err)
	}
	const uid, gid = 65534, 65534
	if err := os.Chown(queue, uid, gid); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("python3", "-I", "queue_probe.py", "--queue", queue)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("coordinator write failed: %v\n%s", err, output)
	}
	path := filepath.Join(queue, "0000.job.json")
	expected, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	reader := exec.Command("/bin/cat", path)
	reader.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid}}
	actual, err := reader.CombinedOutput()
	if err != nil || !bytes.Equal(actual, expected) {
		t.Fatalf("actual queue UID cannot read its private coordinator job: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 || info.Sys().(*syscall.Stat_t).Uid != uid {
		t.Fatalf("job lost private queue ownership: %v", err)
	}
}

// Shared vendor-input checks deliberately create protected root fixtures in
// /opt. Keep them in the explicitly authorized root phase, beside the UID
// canary; the generic e2e/v2 controller remains a separate non-root phase.
func TestSharedServeControls(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("shared protected-input checks require the authorized root Linux box")
	}
	shared := filepath.Join("..", "..", "..", "..", "scripts", "v2-serve")
	command := exec.Command("python3", "-I", "-m", "unittest", "discover", "-s", shared, "-p", "*_test.py", "-v")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("shared serve regression controls: %v\n%s", err, output)
	}
	t.Log(string(output))
}
