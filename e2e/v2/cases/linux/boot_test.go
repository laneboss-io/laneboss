//go:build laneboss_root_canary

package linuxcase

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
)

// Exercise actual boot bytes, the shared exporter and Go bundle assembler,
// then the installer's root-only file reader and full initialClosure check.
// No installed service or worker executes the inert runtime fixture.
func TestLinuxBootBundle(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		t.Fatal("boot validation requires the authorized root Linux box")
	}
	root, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	stage, err := os.MkdirTemp("/opt", "lb-v2-case-linux-boot-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(stage); err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	var verdicts []string
	// Keep exact ephemeral inputs in one compressed JSON record; repeated
	// canary/template bytes otherwise hide deciding errors in bounded logs.
	t.Cleanup(func() {
		command := exec.CommandContext(ctx, "python3", "-I", "-B",
			filepath.Join(root, "e2e/v2/cases/linux/boot_bundle.py"), "--pack", stage)
		output, err := command.CombinedOutput()
		if err != nil || len(output) > 18000 {
			t.Errorf("retain complete boot inputs in bounded log: %v; bytes=%d", err, len(output))
		} else {
			t.Log(string(output))
		}
		for _, verdict := range verdicts {
			t.Log(verdict)
		}
	})
	tool := filepath.Join(stage, "bundle")
	build := exec.CommandContext(ctx, "go", "build", "-o", tool, "./scripts/v2-serve/bundle")
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build actual bundle assembler: %v\n%s", err, output)
	}
	for _, kind := range []string{"no-plan", "empty-plan", "selected-plan", "orphan-plan"} {
		t.Run(kind, func(t *testing.T) {
			dir := filepath.Join(stage, kind)
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			command := exec.CommandContext(ctx, "python3", "-I", "-B",
				filepath.Join(root, "e2e/v2/cases/linux/boot_bundle.py"),
				"--root", dir, "--tool", tool, "--kind", kind)
			command.Dir = root
			var stderr bytes.Buffer
			command.Stderr = &stderr
			raw, err := command.Output()
			if err != nil {
				t.Fatalf("actual Linux boot/export/assembly failed: %v\n%s", err, stderr.Bytes())
			}
			var fixture struct {
				Config   string      `json:"config"`
				Manifest api.BlobRef `json:"manifest"`
				Initial  string      `json:"initial"`
				Request  string      `json:"request"`
				Records  []struct {
					Name   string     `json:"name"`
					SHA256 api.Digest `json:"sha256"`
					Bytes  int64      `json:"bytes"`
					Data   []byte     `json:"data"`
				} `json:"records"`
			}
			if err := api.DecodeObject(raw, &fixture); err != nil {
				t.Fatal("boot fixture output:", err)
			}
			for _, record := range fixture.Records {
				sum := sha256.Sum256(record.Data)
				if int64(len(record.Data)) != record.Bytes || api.Digest(hex.EncodeToString(sum[:])) != record.SHA256 {
					t.Fatal("retained input bytes differ:", record.Name)
				}
			}
			var receipt bytes.Buffer
			err = admin.RunInitialValidation(ctx, fixture.Config,
				[]string{"--validate-initial", fixture.Initial, "--initial-ref", fixture.Request}, &receipt)
			verdicts = append(verdicts, kind+": "+string(receipt.Bytes()))
			if err != nil {
				verdicts[len(verdicts)-1] = kind + ": " + err.Error()
			}
			if kind == "orphan-plan" {
				var refused *api.Error
				if !errors.As(err, &refused) || refused.Code != api.CodeInvalid || refused.Owner != "lb-v2-admin" || refused.Message != "initial publication contains an unselected object" || receipt.Len() != 0 {
					t.Fatalf("orphan plan did not reach the closure refusal: %v; receipt=%s", err, receipt.Bytes())
				}
				t.Logf("RED control: actual %s refused by initialClosure: %s", kind, refused.Message)
				return
			}
			if err != nil {
				t.Fatal("admin initial validation:", err)
			}
			var result struct {
				Valid    bool        `json:"valid"`
				Manifest api.BlobRef `json:"manifest"`
				ID       api.ID      `json:"id"`
			}
			if err := api.DecodeObject(receipt.Bytes(), &result); err != nil {
				t.Fatal("initial validation receipt:", err)
			}
			initialRaw, err := os.ReadFile(fixture.Initial)
			if err != nil {
				t.Fatal(err)
			}
			var initial admin.InitialManifest
			if err := api.DecodeObject(initialRaw, &initial); err != nil {
				t.Fatal(err)
			}
			if !result.Valid || result.Manifest != fixture.Manifest || result.ID != initial.ID {
				t.Fatal("installer did not confirm the exact boot publication")
			}
			t.Logf("GREEN: actual %s boot passed installer initial validation; manifest=%s receipt=%s", kind, result.Manifest.SHA256, receipt.Bytes())
		})
	}
}
