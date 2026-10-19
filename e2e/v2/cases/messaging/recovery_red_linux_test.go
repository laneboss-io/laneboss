//go:build linux

package messagingcase

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Run only on the disposable Linux box. The reached named assertion must fail
// with the retained-receipt branch removed, then pass on the actual candidate.
// No mutant vet or project execution occurs on a development host.
func TestItem3RecoveryRedGreen(t *testing.T) {
	item3RedGreen(t, "internal/v2/messaging/reconcile.go",
		"\tif mail.Status == \"delivered\" || mail.Status == \"returned\" {\n\t\treturn s.reconcileRetainedDelivery(ctx, scope, record, mail)\n\t}\n", "",
		"./internal/v2/messaging", "TestItem3LogicalDeliveryRecovery", "lost reply after a later turn did not recover the original receipt once")
}

func TestItem3PublicEventRedGreen(t *testing.T) {
	item3RedGreen(t, "internal/v2/store/transaction.go",
		"if input.Scope.Actor.Kind == \"lane\" && !natural && !laneAuthored {",
		"if input.Scope.Actor.Kind == \"lane\" && !natural && (!laneAuthored || laneAuthored) {",
		"./internal/v2/store", "TestItem3LaneControlCommit", "authentic parent control did not commit through the real store forbidden: lane event cannot claim authoritative or foreign-life facts")
}

func item3RedGreen(t *testing.T, relative, beforeText, afterText, pkg, name, diagnostic string) {
	t.Helper()
	root, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, relative)
	raw, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	before := []byte(beforeText)
	if bytes.Count(raw, before) != 1 {
		t.Fatal("control lost its exact owning branch", name)
	}
	directory := t.TempDir()
	mutant := filepath.Join(directory, filepath.Base(relative))
	if err := os.WriteFile(mutant, bytes.Replace(raw, before, []byte(afterText), 1), 0600); err != nil {
		t.Fatal(err)
	}
	overlay := filepath.Join(directory, "overlay.json")
	input, err := json.Marshal(map[string]any{"Replace": map[string]string{source: mutant}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(overlay, input, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "test", "-vet=off", "-count=1", "-json", "-overlay", overlay,
		"-run", "^"+name+"$", pkg)
	command.Dir = root
	output, failure := command.CombinedOutput()
	t.Logf("%s RED output:\n%s", name, output)
	failing := `"Action":"fail","Package":"laneboss.io/laneboss/` + strings.TrimPrefix(pkg, "./") + `","Test":"` + name + `"`
	if failure == nil || !bytes.Contains(output, []byte(diagnostic)) || !bytes.Contains(output, []byte(failing)) {
		t.Fatalf("mutation did not reach and fail its intended assertion: %v\n%s", failure, output)
	}
	baseline := exec.CommandContext(ctx, "go", "test", "-vet=off", "-count=1", "-run", "^"+name+"$", pkg)
	baseline.Dir = root
	output, err = baseline.CombinedOutput()
	t.Logf("candidate GREEN output:\n%s", output)
	if err != nil {
		t.Fatalf("candidate did not restore its intended behavior: %v\n%s", err, output)
	}
}
