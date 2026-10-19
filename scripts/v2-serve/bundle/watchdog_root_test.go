//go:build linux && laneboss_root_canary

package main

import (
	"bytes"
	"context"
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

// The runtime bytes are declared inert inputs. The Python case boot, bundle
// executable, exact JSON decoder and root-only initial validator are real.
// This starts no service, agent, model request or publication operation.
func TestWatchdogBootBundle(t *testing.T) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		t.Fatal("watchdog bundle validation requires the disposable Linux root step")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	stage, err := os.MkdirTemp("/opt", "lb-v2-case-watchdog-initial-")
	if err != nil {
		t.Fatal(err)
	}
	// Keep exact inputs and the tested executable for the queue owner's
	// evidence collection. Subprocess calls share the test's fixed deadline.
	t.Log("root bundle evidence:", stage)
	write := func(name string, raw []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(stage, name), raw, 0444); err != nil {
			t.Fatal(err)
		}
	}
	in := bundleInput(t)
	base, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	write("base-input.json", base)
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	producer := exec.CommandContext(ctx, "python3", "-B", filepath.Join(root, "e2e/v2/cases/watchdog/boot_bundle_input.py"), stage)
	raw, err := producer.Output()
	if err != nil {
		if failed, ok := err.(*exec.ExitError); ok {
			t.Log(string(failed.Stderr))
		}
		t.Fatal("actual watchdog boot input failed:", err)
	}
	retained, err := os.ReadFile(filepath.Join(stage, "bundle-input.json"))
	if err != nil || !bytes.Equal(raw, retained) {
		t.Fatal("watchdog boot input changed before the bundle decoder", err)
	}
	binary := filepath.Join(stage, "bundle")
	build := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("real bundle build failed: %v\n%s", err, output)
	}
	built, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("bundle executable sha256=%s bytes=%d", digest(built), len(built))
	command := exec.CommandContext(ctx, binary, "--input", filepath.Join(stage, "bundle-input.json"))
	assembled, err := command.Output()
	if err != nil {
		if failed, ok := err.(*exec.ExitError); ok {
			t.Log(string(failed.Stderr))
		}
		t.Fatal("actual watchdog bundle assembler failed:", err)
	}
	write("bundle-output.json", assembled)
	var out output
	if err := json.Unmarshal(assembled, &out); err != nil || out.Schema != "laneboss.serve-initial-bundle.v1" {
		t.Fatal("actual bundle output is invalid", err)
	}
	objects := map[api.ID][]byte{"tool-bytes": []byte("declared tool bytes"), "agent-bytes": []byte("declared agent bytes")}
	for _, doc := range out.Documents {
		if _, exists := objects[doc.Ref.ID]; exists || doc.Ref != ref(doc.Ref.ID, doc.Ref.Class, doc.Data) {
			t.Fatal("bundle document repeated an identity or changed its exact bytes")
		}
		objects[doc.Ref.ID] = doc.Data
	}
	if err := os.Mkdir(filepath.Join(stage, "initial-objects"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, selected := range out.Initial.Objects {
		raw, found := objects[selected.ID]
		if !found || selected != ref(selected.ID, selected.Class, raw) {
			t.Fatal("initial object differs from the actual assembled bytes", selected.ID)
		}
		write(filepath.Join("initial-objects", string(selected.ID)), raw)
	}
	write("initial.json", out.Raw)
	request, err := json.Marshal(admin.InitialRequest{Manifest: out.Ref})
	if err != nil {
		t.Fatal(err)
	}
	write("initial-ref.json", request)
	var receipt bytes.Buffer
	err = admin.RunInitialValidation(ctx, out.Initial.Config, []string{"--validate-initial", filepath.Join(stage, "initial.json"), "--initial-ref", filepath.Join(stage, "initial-ref.json")}, &receipt)
	if err != nil {
		t.Fatal("actual watchdog initial closure failed:", err)
	}
	var validated struct {
		Valid    bool        `json:"valid"`
		Manifest api.BlobRef `json:"manifest"`
		ID       api.ID      `json:"id"`
	}
	if err := api.DecodeObject(receipt.Bytes(), &validated); err != nil || !validated.Valid || validated.Manifest != out.Ref || validated.ID != out.Initial.ID {
		t.Fatal("initial validator did not confirm this exact watchdog bundle", err)
	}
	// A later child still needs its exact task bytes; they may not disappear
	// merely to satisfy publication inventory closure.
	task, err := os.ReadFile(filepath.Join(stage, "evidence", "wd-wd-child-task.input"))
	if err != nil || len(bytes.TrimSpace(task)) == 0 {
		t.Fatal("watchdog lost the retained later child task", err)
	}
	// Reintroducing that exact orphan must still stop the real validator.
	// Successful boot selection confers no permission to widen its closure.
	orphan := ref("wd-child-task", "task", task)
	negative := out.Initial
	negative.Objects = append(append([]api.BlobRef{}, negative.Objects...), orphan)
	negativeRaw, err := json.Marshal(negative)
	if err != nil {
		t.Fatal(err)
	}
	write("negative.json", negativeRaw)
	write(filepath.Join("initial-objects", string(orphan.ID)), task)
	negativeRef := ref(out.Ref.ID, out.Ref.Class, negativeRaw)
	negativeRequest, err := json.Marshal(admin.InitialRequest{Manifest: negativeRef})
	if err != nil {
		t.Fatal(err)
	}
	write("negative-ref.json", negativeRequest)
	var refused bytes.Buffer
	err = admin.RunInitialValidation(ctx, out.Initial.Config, []string{"--validate-initial", filepath.Join(stage, "negative.json"), "--initial-ref", filepath.Join(stage, "negative-ref.json")}, &refused)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeInvalid || typed.Message != "initial publication contains an unselected object" || refused.Len() != 0 {
		t.Fatal("initial closure did not reject the reintroduced child task", err)
	}
	t.Logf("watchdog boot input sha256=%s initial_sha256=%s child_task_sha256=%s objects=%d", digest(raw), out.Ref.SHA256, digest(task), len(out.Initial.Objects))
}
