//go:build linux && laneboss_live_spend

package store

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/runner/claudock"
)

// This opt-in input producer runs only on the disposable Linux box. No login,
// existing HOME, credential file or inherited authentication is used.
func spendFakeKeyCapture(t *testing.T, p *api.LaunchPlanRecord) (api.CaptureRecord, []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	home := t.TempDir()
	if err := os.Chmod(home, 0700); err != nil {
		t.Fatal(err)
	}
	environment := []string{"HOME=" + home, "PATH=/usr/bin:/bin", "LANG=C", "DISABLE_TELEMETRY=1", "DISABLE_ERROR_REPORTING=1", "CLAUDE_CODE_DISABLE_" + "NONESSENTIAL_TRAFFIC=1"}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://claude.ai/install.sh", nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 90 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("pinned vendor installer download failed")
	}
	installer, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || response.StatusCode != http.StatusOK || len(installer) == 0 || len(installer) >= 1<<20 {
		t.Fatal("pinned vendor installer response is incomplete")
	}
	script := filepath.Join(home, "install-vendor.sh")
	if err := os.WriteFile(script, installer, 0700); err != nil {
		t.Fatal(err)
	}
	install := exec.CommandContext(ctx, "/bin/bash", script, claudock.ClaudeVersion)
	install.Env = environment
	install.Dir = home
	var diagnostics bytes.Buffer
	install.Stdout, install.Stderr = &diagnostics, &diagnostics
	if err := install.Run(); err != nil {
		t.Fatal("pinned vendor installation failed")
	}
	vendor, err := filepath.EvalSymlinks(filepath.Join(home, ".local/bin/claude"))
	if err != nil {
		t.Fatal("installed vendor executable is missing")
	}
	rel, err := filepath.Rel(home, vendor)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		t.Fatal("vendor installer escaped its isolated home")
	}
	file, err := os.Open(vendor)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	size, hashErr := io.Copy(hash, io.LimitReader(file, 512<<20))
	closeErr = file.Close()
	if hashErr != nil || closeErr != nil || size <= 0 || size >= 512<<20 {
		t.Fatal("installed vendor bytes could not be pinned")
	}
	version := exec.CommandContext(ctx, vendor, "--version")
	version.Env = environment
	version.Dir = home
	versionBytes, err := version.Output()
	if err != nil || !strings.HasPrefix(string(versionBytes), claudock.ClaudeVersion+" ") {
		t.Fatal("installed vendor version differs from the adapter pin")
	}
	var identity [16]byte
	if _, err := rand.Read(identity[:]); err != nil {
		t.Fatal(err)
	}
	identity[6] = identity[6]&15 | 64
	identity[8] = identity[8]&63 | 128
	session := fmt.Sprintf("%x-%x-%x-%x-%x", identity[:4], identity[4:6], identity[6:8], identity[8:10], identity[10:])
	p.Plan.Runner.Session.VendorID = session
	const fakeKey = "sk-ant-invalid-spend-canary"
	run := exec.CommandContext(ctx, vendor, "-p", "--verbose", "--output-format", "stream-json", "--session-id", session,
		"--model", "claude-sonnet-5-5", "--max-turns", "1", "--setting-sources", "", "Reply with x.")
	run.Env = append(append([]string{}, environment...), "ANTHROPIC_API_KEY="+fakeKey)
	run.Dir = home
	var stdout, stderr bytes.Buffer
	run.Stdout, run.Stderr = &stdout, &stderr
	err = run.Run()
	var exited *exec.ExitError
	if err == nil || !asSpendExit(err, &exited) || ctx.Err() != nil {
		t.Fatal("fake credential did not produce a terminal vendor refusal")
	}
	raw := bytes.Clone(stdout.Bytes())
	if bytes.Contains(raw, []byte(fakeKey)) || bytes.Contains(stderr.Bytes(), []byte(fakeKey)) {
		t.Fatal("vendor output disclosed the fake credential marker")
	}
	refused, results := false, 0
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		var event struct {
			Type    string       `json:"type"`
			Session string       `json:"session_id"`
			IsError bool         `json:"is_error"`
			Cost    *json.Number `json:"total_cost_usd"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatal("vendor stdout is not stream-json")
		}
		text := strings.ToLower(string(scanner.Bytes()))
		refused = refused || strings.Contains(text, "invalid api key") || strings.Contains(text, "authentication_error") || strings.Contains(text, "invalid x-api-key")
		if event.Type == "result" {
			results++
			if !event.IsError || event.Session != session || event.Cost == nil || string(*event.Cost) != "0" {
				t.Fatal("fake credential result does not report a vendor zero-cost error")
			}
		}
	}
	if scanner.Err() != nil || !refused || results != 1 {
		t.Fatal("vendor fake-key output has no single authentication-refused result")
	}
	installerSum := sha256.Sum256(installer)
	t.Logf("vendor_version=%s vendor_bytes=%d vendor_sha256=%s installer_sha256=%s", claudock.ClaudeVersion, size, hex.EncodeToString(hash.Sum(nil)), hex.EncodeToString(installerSum[:]))
	t.Logf("fake_key_stream_base64=%s", base64.StdEncoding.EncodeToString(raw))
	return api.CaptureRecord{ID: testID(t), BindingID: p.Plan.Capture.ID, Target: p.Reservation.Target, Stream: "stdout", Primary: true, Coverage: "partial",
		Data: api.BlobRef{ID: testID(t), Class: "capture", Bytes: int64(len(raw)), SHA256: testDigest(raw)}}, raw
}

func asSpendExit(err error, target **exec.ExitError) bool {
	value, ok := err.(*exec.ExitError)
	if ok {
		*target = value
	}
	return ok
}
