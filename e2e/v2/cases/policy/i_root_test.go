//go:build linux && laneboss_root_canary

package policycase

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
)

// The real root-only installer reads protected actual boot/assembler bytes.
// It starts no service, worker, owner request or model request.
func TestPolicyBootInitial(t *testing.T) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		t.Fatal("initial validation requires the authorized root Linux observer")
	}
	stage, err := os.MkdirTemp("/opt", "lb-v2-case-policy-initial-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(stage); err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	probe := exec.CommandContext(ctx, "python3", "-I", "i_probe.py", "--output", stage)
	if output, err := probe.CombinedOutput(); err != nil {
		t.Fatalf("actual boot/assembler export: %v\n%s", err, output)
	}
	read := func(name string) []byte {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(stage, name))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	var initial admin.InitialManifest
	if err := api.DecodeObject(read("initial.json"), &initial); err != nil {
		t.Fatal(err)
	}
	var request admin.InitialRequest
	if err := api.DecodeObject(read("initial-ref.json"), &request); err != nil {
		t.Fatal(err)
	}
	var extraTasks []api.ID
	for _, ref := range initial.Objects {
		if ref.Class == "task" && ref != initial.Task {
			extraTasks = append(extraTasks, ref.ID)
		}
	}
	var receipt bytes.Buffer
	if err := admin.RunInitialValidation(ctx, initial.Config,
		[]string{"--validate-initial", filepath.Join(stage, "initial.json"), "--initial-ref", filepath.Join(stage, "initial-ref.json")}, &receipt); err != nil {
		t.Fatalf("installer initial validation; standalone tasks=%v: %v", extraTasks, err)
	}
	var result struct {
		Valid    bool        `json:"valid"`
		Manifest api.BlobRef `json:"manifest"`
		ID       api.ID      `json:"id"`
	}
	if err := api.DecodeObject(receipt.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Valid || result.Manifest != request.Manifest || result.ID != initial.ID {
		t.Fatal("installer did not confirm the exact boot publication")
	}
	write := func(name string, raw []byte) {
		t.Helper()
		path := filepath.Join(stage, name)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0444); err != nil {
			t.Fatal(err)
		}
	}
	pin := func(id api.ID, class string, raw []byte) api.BlobRef {
		sum := sha256.Sum256(raw)
		return api.BlobRef{ID: id, Class: class, SHA256: api.Digest(hex.EncodeToString(sum[:])), Bytes: int64(len(raw))}
	}
	// Restore the original orphan with real role-task bytes and correct hashes.
	// Only reachability is wrong: no malformed input or missing file masks it.
	orphan := pin("policy-role-task", "task", read("role-task.input"))
	for _, ref := range initial.Objects {
		if ref.ID == orphan.ID {
			t.Fatal("role task is still published before its authenticated upload")
		}
	}
	write(filepath.Join("initial-objects", string(orphan.ID)), read("role-task.input"))
	initial.Objects = append(initial.Objects, orphan)
	raw, err := json.Marshal(initial)
	if err != nil {
		t.Fatal(err)
	}
	write("orphan.json", raw)
	request.Manifest = pin(request.Manifest.ID, "manifest", raw)
	raw, err = json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	write("orphan-ref.json", raw)
	receipt.Reset()
	err = admin.RunInitialValidation(ctx, initial.Config,
		[]string{"--validate-initial", filepath.Join(stage, "orphan.json"), "--initial-ref", filepath.Join(stage, "orphan-ref.json")}, &receipt)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeInvalid || typed.Message != "initial publication contains an unselected object" || receipt.Len() != 0 {
		t.Fatalf("orphan did not reach the unchanged closure validator: %v", err)
	}
	t.Log("GREEN: actual boot passed installer validation; correctly pinned orphan reached initialClosure")
}
