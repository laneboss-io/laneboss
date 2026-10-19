//go:build linux && laneboss_installed

package assembly

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

var startupInstallation = flag.String("service-installation", "", "protected installed service input")
var startupEvidence = flag.String("startup-evidence", "", "new private startup evidence directory")

type startupProbe struct {
	t         *testing.T
	directory string
	index     int
}

func (p *startupProbe) keep(name string, data []byte) {
	p.t.Helper()
	file, err := os.OpenFile(filepath.Join(p.directory, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		p.t.Fatal("startup evidence cannot be retained")
	}
	_, writeErr := file.Write(data)
	if errors.Join(writeErr, file.Sync(), file.Close()) != nil {
		p.t.Fatal("startup evidence write failed")
	}
}

func (p *startupProbe) command(ctx context.Context, label string, argv ...string) ([]byte, error) {
	p.t.Helper()
	p.index++
	stem := fmt.Sprintf("%03d-%s", p.index, label)
	encoded, err := json.Marshal(argv)
	if err != nil {
		p.t.Fatal("startup argv cannot be retained")
	}
	p.keep(stem+".argv.json", encoded)
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	command := exec.CommandContext(bounded, argv[0], argv[1:]...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err = command.Run()
	code := -1
	if command.ProcessState != nil {
		code = command.ProcessState.ExitCode()
	}
	result, encodeErr := json.Marshal(struct {
		ExitCode int  `json:"exit_code"`
		TimedOut bool `json:"timed_out"`
	}{code, bounded.Err() != nil})
	if encodeErr != nil {
		p.t.Fatal("startup command result cannot be retained")
	}
	p.keep(stem+".stdout", stdout.Bytes())
	p.keep(stem+".stderr", stderr.Bytes())
	p.keep(stem+".exit.json", result)
	return stdout.Bytes(), errors.Join(err, bounded.Err())
}

func (p *startupProbe) must(ctx context.Context, label string, argv ...string) []byte {
	p.t.Helper()
	output, err := p.command(ctx, label, argv...)
	if err != nil {
		p.t.Fatalf("startup command failed: %s; inspect retained output", label)
	}
	return output
}

func (p *startupProbe) journal(ctx context.Context, unit string) {
	p.t.Helper()
	invocation, err := p.command(ctx, "invocation", "systemctl", "show", "--value", "-p", "InvocationID", unit)
	if err != nil || !regexp.MustCompile(`^[a-f0-9]{32}$`).Match(bytes.TrimSpace(invocation)) {
		p.t.Error("startup invocation journal selector is unavailable")
		return
	}
	output, err := p.command(ctx, "journal", "journalctl", "--no-pager", "--output", "cat",
		"_SYSTEMD_INVOCATION_ID="+string(bytes.TrimSpace(invocation)))
	if err != nil {
		p.t.Error("startup journal could not be retained")
		return
	}
	lines := bufio.NewScanner(bytes.NewReader(output))
	lines.Buffer(make([]byte, 4096), api.MaxFrameBytes)
	for lines.Scan() {
		line := bytes.TrimSpace(lines.Bytes())
		if !bytes.HasPrefix(line, []byte("{")) {
			continue
		}
		var problem struct {
			Code  api.ErrorCode `json:"code"`
			Owner string        `json:"owner"`
		}
		if json.Unmarshal(line, &problem) != nil {
			p.t.Error("startup journal contains malformed JSON")
			continue
		}
		if problem.Code != "" {
			p.t.Errorf("production startup refused: owner=%s code=%s", problem.Owner, problem.Code)
		}
	}
	if lines.Err() != nil {
		p.t.Error("startup journal exceeded its read bound")
	}
}

// This runs the actual installed Serve/Build constructor graph in its dedicated
// unit, not a second Go graph filled with mem stores, fake peers or fixture
// runners. A missing installation is a failure when this integration tag runs.
func TestProductionStartup(t *testing.T) {
	if os.Geteuid() != 0 || *startupInstallation == "" || *startupEvidence == "" {
		t.Fatal("production startup requires Linux root and explicit protected inputs/evidence")
	}
	if !filepath.IsAbs(*startupEvidence) || filepath.Clean(*startupEvidence) != *startupEvidence ||
		!strings.HasPrefix(*startupEvidence, "/opt/lb-v2-serve-") {
		t.Fatal("startup evidence must be a fresh protected lane directory")
	}
	if err := protectedParents(filepath.Dir(*startupEvidence), 0); err != nil {
		t.Fatal("startup evidence parent is not protected")
	}
	if err := os.Mkdir(*startupEvidence, 0700); err != nil {
		t.Fatal("preserve existing startup evidence")
	}
	probe := &startupProbe{t: t, directory: *startupEvidence}
	raw, err := readProtected(*startupInstallation, api.MaxFrameBytes)
	if err != nil {
		t.Fatal("protected installed startup input cannot be read")
	}
	probe.keep("installation.input.json", raw)
	var installed Installation
	if api.DecodeObject(raw, &installed) != nil || validateInstallation(installed, Options{Config: installed.Config}) != nil {
		t.Fatal("production startup installation is invalid")
	}
	// The binding supplies the actual release version, not a test executable.
	bindingBytes, err := readProtected(installed.BindingFile, api.MaxFrameBytes)
	if err != nil || api.DecodeObject(bindingBytes, &installed.Binding) != nil {
		t.Fatal("production startup binding cannot be read")
	}
	if err := api.ValidateBinding(installed.Binding, installed.Config, installed.Binding.ServiceVersion); err != nil {
		t.Fatal("production startup binding is invalid")
	}
	if installed.Binding.Class != "human" || installed.Binding.Backend != "linux-bwrap-landlock" ||
		installed.Binding.Socket != installed.Socket || installed.Binding.ServiceUID != installed.ServiceUID ||
		installed.Binding.ArtifactSHA256 != installed.ArtifactSHA256 {
		t.Fatal("production startup binding differs from its installed Linux host")
	}
	probe.keep("binding.input.json", bindingBytes)
	binary := filepath.Join("/usr/lib/laneboss-v2", installed.Binding.ServiceVersion, "laneboss")
	artifact, err := readProtected(binary, 256<<20)
	if err != nil {
		t.Fatal("production startup artifact cannot be read")
	}
	sum := sha256.Sum256(artifact)
	if api.Digest(hex.EncodeToString(sum[:])) != installed.ArtifactSHA256 {
		t.Fatal("production startup artifact pin differs")
	}
	probe.keep("laneboss.input", artifact)
	info, err := buildinfo.ReadFile(binary)
	if err != nil || info.Path != "laneboss.io/laneboss/cmd/laneboss" {
		t.Fatal("production startup build information is unavailable")
	}
	for _, setting := range info.Settings {
		if setting.Key == "-tags" && setting.Value != "" {
			t.Fatal("production startup requires the untagged production artifact")
		}
	}
	manifest, err := readProtected(filepath.Join(filepath.Dir(binary), "runtime", installed.Config, "manifest.json"), api.MaxFrameBytes)
	if err != nil {
		t.Fatal("production runtime manifest cannot be read")
	}
	sum = sha256.Sum256(manifest)
	if installed.RuntimeManifest.SHA256 != api.Digest(hex.EncodeToString(sum[:])) || installed.RuntimeManifest.Bytes != int64(len(manifest)) {
		t.Fatal("production runtime manifest pin differs")
	}
	var runtime api.RuntimeManifest
	if api.DecodeObject(manifest, &runtime) != nil {
		t.Fatal("production runtime manifest is invalid")
	}
	probe.keep("runtime.input.json", manifest)
	for _, object := range runtime.Objects {
		if strings.HasPrefix(object.Role, "serve-fixture") {
			t.Fatal("production startup cannot use the serve fixture enrollment")
		}
	}
	if _, err := os.Lstat(installed.Socket); !os.IsNotExist(err) {
		t.Fatal("production startup socket is not fresh")
	}
	if _, err := os.Lstat(filepath.Join(installed.StateDirectory, "state.sqlite")); !os.IsNotExist(err) {
		t.Fatal("production startup requires the fresh installed state directory")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	for _, role := range []string{"helper", "service"} {
		unit := "laneboss-" + role + "@" + installed.Config + ".service"
		before := probe.must(ctx, "before-pid", "systemctl", "show", "--value", "-p", "MainPID", unit)
		if string(bytes.TrimSpace(before)) != "0" {
			t.Fatal("production startup unit is already running")
		}
		t.Cleanup(func() {
			cleanup, stop := context.WithTimeout(context.Background(), 45*time.Second)
			defer stop()
			probe.journal(cleanup, unit)
			if _, err := probe.command(cleanup, "stop-unit", "systemctl", "stop", unit); err != nil {
				t.Error("production startup unit stop failed; no alternate stop route")
				return
			}
			pid, err := probe.command(cleanup, "after-pid", "systemctl", "show", "--value", "-p", "MainPID", unit)
			if err != nil || string(bytes.TrimSpace(pid)) != "0" {
				t.Error("production startup unit retained its process")
			}
			if role == "service" {
				status, err := probe.command(cleanup, "stop-status", "systemctl", "show", "--value", "-p", "ExecMainStatus", unit)
				if err != nil || string(bytes.TrimSpace(status)) != "0" {
					t.Error("requested production service stop did not exit zero")
				}
			}
		})
		probe.must(ctx, "start-unit", "systemctl", "start", unit)
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(30 * time.Second)
	defer deadline.Stop()
wait:
	for {
		if stat, err := os.Lstat(installed.Socket); err == nil {
			if stat.Mode()&os.ModeSocket == 0 {
				t.Fatal("production startup did not publish a socket")
			}
			break wait
		} else if !os.IsNotExist(err) {
			t.Fatal("production startup socket observation failed")
		}
		select {
		case <-ctx.Done():
			t.Fatal("production startup context expired")
		case <-deadline.C:
			t.Fatal("production startup socket deadline; inspect the retained unit journals")
		case <-ticker.C:
		}
	}
	serviceUnit := "laneboss-service@" + installed.Config + ".service"
	pidBytes := probe.must(ctx, "service-pid", "systemctl", "show", "--value", "-p", "MainPID", serviceUnit)
	pid, err := strconv.Atoi(string(bytes.TrimSpace(pidBytes)))
	if err != nil || pid <= 1 {
		t.Fatal("production startup service has no actual process")
	}
	processArtifact, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil {
		t.Fatal("production startup process artifact cannot be read")
	}
	sum = sha256.Sum256(processArtifact)
	if api.Digest(hex.EncodeToString(sum[:])) != installed.ArtifactSHA256 {
		t.Fatal("production startup unit executed different bytes")
	}
	// No identity, enrollment, lane or other RPC may precede public health.
	healthBytes := probe.must(ctx, "health", binary, "health", "--config", installed.Config, "--binding", installed.BindingFile)
	var health api.Health
	if api.DecodeObject(healthBytes, &health) != nil || health.Protocol != api.Protocol ||
		health.Schema != api.SchemaVersion || health.ArtifactSHA256 != installed.ArtifactSHA256 ||
		health.ServiceVersion != installed.Binding.ServiceVersion {
		t.Fatal("production startup health identity differs")
	}
	capabilities := make(map[string]bool)
	for _, capability := range health.Capabilities {
		capabilities[capability.Name] = capability.Available
	}
	for _, required := range []string{"installed-transport", "registered-methods", "state-snapshot", "native-peer"} {
		if !capabilities[required] {
			t.Fatalf("production startup lacks observed capability: %s", required)
		}
	}
}
