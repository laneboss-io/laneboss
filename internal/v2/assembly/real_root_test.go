//go:build linux && laneboss_root_canary

package assembly

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/runner/claudock"
)

// Exercise the installed adapter with protected runtime objects beside the
// running artifact. The wrapper is an unexecuted pin; the public exact-version
// Claude Code binary supplies actual version and credential-selection output.
func TestRealBindings(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("requires the authorized root canary box")
	}
	if os.Args[len(os.Args)-1] != "real-bindings-child" {
		dir, err := os.MkdirTemp("/opt", "lb-v2-realrun-")
		if err != nil {
			t.Fatal(err)
		}
		self, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(self)
		if err != nil {
			t.Fatal(err)
		}
		binary := filepath.Join(dir, "canary")
		if err := os.WriteFile(binary, data, 0555); err != nil {
			t.Fatal(err)
		}
		output, err := exec.Command(binary, "-test.run=^TestRealBindings$", "-test.v", "--", "real-bindings-child").CombinedOutput()
		t.Log(string(output))
		if err != nil {
			t.Fatal("installed adapter canary failed", err)
		}
		return
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(filepath.Dir(self), "runtime", "realrun")
	root := filepath.Join(dir, "objects")
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatal(err)
	}
	objects := []api.RuntimeObject{}
	for _, name := range []string{"claudock", "claude"} {
		data := []byte("unexecuted runtime pin: " + name)
		if name == "claude" {
			data = installCompatibilityVendor(t, filepath.Join(root, name))
		} else if err := os.WriteFile(filepath.Join(root, name), data, 0555); err != nil {
			t.Fatal(err)
		}
		objects = append(objects, api.RuntimeObject{ID: api.ID(name), RootID: "objects", RelativePath: name,
			Role: name, Mode: 0555, Content: api.BlobRef{ID: api.ID(name), Class: "artifact", Bytes: int64(len(data)), SHA256: runDigest(data)}})
	}
	artifact := api.Executable{ID: "release", Version: "test", SHA256: runDigest([]byte("release"))}
	manifest, err := json.Marshal(api.RuntimeManifest{Schema: "laneboss.runtime.v2", Generation: 1, Artifact: artifact, Objects: objects, Bindings: []api.InstalledBinding{}})
	if err != nil {
		t.Fatal(err)
	}
	roots, err := json.Marshal([]runtimeRoot{{ID: "objects", Path: root}})
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"manifest.json": manifest, "roots.json": roots} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0444); err != nil {
			t.Fatal(err)
		}
	}
	installed := Installation{Config: "realrun", ArtifactSHA256: artifact.SHA256,
		StateDirectory:  filepath.Join(filepath.Dir(self), "state"),
		RuntimeManifest: api.BlobRef{ID: "runtime", Class: "manifest", Bytes: int64(len(manifest)), SHA256: runDigest(manifest)}}
	writeRealSessionEnrollment(t, dir, &installed,
		api.Executable{ID: "claudock", SHA256: objects[0].Content.SHA256, Version: "0.1.0"},
		api.Executable{ID: "claude", SHA256: objects[1].Content.SHA256, Version: "2.1.296"})
	if err := os.Mkdir(installed.StateDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	ports := runnerDependencies{Store: &struct{ api.StateStore }{}, Clock: wallClock{},
		Sources: &struct{ api.LaunchSourceResolver }{}, Storage: &struct{ api.LaunchStorageResolver }{},
		Grants: &struct{ api.GrantResolver }{}, Credentials: &struct{ api.CredentialBroker }{},
		UsageWindows: &struct{ api.UsageWindowSource }{}, Capture: &struct{ api.CaptureControl }{},
		Materialization: &struct{ api.MaterializationControl }{}}
	runner, _, err := realRunners(installed, ports)
	if err != nil {
		t.Fatal(err)
	}
	_, err = runner.Start(context.Background(), api.RunnerRequest{})
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeInvalid || typed.Owner != "lb-v2-claudock" {
		t.Fatal("enrolled pins did not reach request validation", err)
	}
	boundRuntime, err := loadRealRuntime(installed)
	if err != nil || boundRuntime == nil {
		t.Fatal("installed session provenance lost its enrolled runtime", err)
	}
	for _, mode := range []string{"claude-api-key", "claudock-headless"} {
		request := api.RunnerRequest{Target: api.LifeRef{LifeID: "life", Run: 1}, LogicalTurnID: "turn",
			Session: api.Session{ID: "session", Driver: api.DriverClaudock, HomeID: "home", HistoryID: "history", LogicalCWD: "/work/main"},
			Home:    api.PrivateHome{ID: "home", WorkspaceID: "workspace", HistoryID: "history", VendorDirectory: ".claude"},
			Slot: api.CredentialSlot{ID: "slot", ProfileGrantID: "grant", ProfileID: "profile", LeaseID: "slot-lease", Mode: mode,
				ExpiresAt: api.Timestamp(time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano))},
			Executable: boundRuntime.Wrapper, Prompt: api.BlobRef{ID: "prompt", Class: "prompt", Bytes: 1, SHA256: installed.RuntimeManifest.SHA256},
			Model: "claude-sonnet-4-6", Effort: "high", Budget: api.Budget{WallMS: 60000, MemoryBytes: 1 << 28, Processes: 32, DiskBytes: 1 << 20, Currency: "USD"}}
		_, absentErr := runner.Start(context.Background(), request)
		if !errors.As(absentErr, &typed) || typed.Code != api.CodeInvalid || typed.Owner != "lb-v2-claudock" {
			t.Fatal("real installed binding accepted absent vendor session fields", absentErr)
		}
		// These public synthetic fields isolate the request-shape boundary.
		// The actual protected planning claim must still refuse this caller.
		request.Session.VendorID = "00000000-0000-4000-8000-000000000000"
		request.Session.VendorVersion = boundRuntime.Claude.Version
		_, explicitErr := runner.Start(context.Background(), request)
		if !errors.As(explicitErr, &typed) || typed.Code != api.CodeForbidden {
			t.Fatal("real installed binding did not advance to its planning-claim guard", explicitErr)
		}
		t.Logf("realBindings session provenance: mode=%s absent_fields=invalid_request explicit_fields=forbidden", mode)
	}
	// The enrolled CLI must supply its own version and credential selection.
	bindings, err := realBindings(installed, ports, claudock.Dependencies{})
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"claude-api-key", "claudock-headless"} {
		err := bindings.VerifyMode(context.Background(), boundRuntime.Wrapper, boundRuntime.Claude, mode)
		if err != nil {
			t.Fatal("installed runner rejected measured enrolled vendor compatibility", err)
		}
		t.Logf("realBindings compatibility: mode=%s measured=true vendor_version=%s vendor_sha256=%s", mode, boundRuntime.Claude.Version, boundRuntime.Claude.SHA256)
		for _, field := range []string{"vendor-version", "vendor-digest", "wrapper-digest", "mode"} {
			wrapper, vendor, selectedMode := boundRuntime.Wrapper, boundRuntime.Claude, mode
			switch field {
			case "vendor-version":
				vendor.Version += ".changed"
			case "vendor-digest":
				vendor.SHA256 = runDigest([]byte("different vendor"))
			case "wrapper-digest":
				wrapper.SHA256 = runDigest([]byte("different wrapper"))
			case "mode":
				selectedMode = "unmeasured-mode"
			}
			if err := bindings.VerifyMode(context.Background(), wrapper, vendor, selectedMode); err == nil {
				t.Fatal("installed compatibility accepted a mismatched measurement", field)
			}
		}
	}
	measurements, err := os.ReadDir(filepath.Join(installed.StateDirectory, "claudock-compatibility"))
	if err != nil || len(measurements) != 2 {
		t.Fatal("installed compatibility did not retain both actual vendor measurements", err)
	}
	seenModes := map[string]bool{}
	for _, entry := range measurements {
		raw, err := os.ReadFile(filepath.Join(installed.StateDirectory, "claudock-compatibility", entry.Name()))
		var measured struct {
			Schema           string         `json:"schema"`
			Wrapper          api.Executable `json:"wrapper"`
			Vendor           api.Executable `json:"vendor"`
			Mode             string         `json:"mode"`
			Adapter          string         `json:"adapter"`
			VersionOutput    string         `json:"version_output"`
			CredentialStatus []byte         `json:"credential_status"`
		}
		if err != nil || json.Unmarshal(raw, &measured) != nil || measured.Schema != "laneboss.claudock-compatibility.v1" || measured.Vendor != boundRuntime.Claude ||
			measured.Wrapper != boundRuntime.Wrapper || measured.Adapter != claudock.AdapterVersion || !strings.HasPrefix(measured.VersionOutput, measured.Vendor.Version) || api.ValidateObjectJSON(measured.CredentialStatus) != nil {
			t.Fatal("installed compatibility retained fabricated or incomplete measurement bytes", err)
		}
		var selected struct {
			Method string `json:"authMethod"`
		}
		if json.Unmarshal(measured.CredentialStatus, &selected) != nil || seenModes[measured.Mode] ||
			measured.Mode != "claude-api-key" && measured.Mode != "claudock-headless" ||
			measured.Mode == "claude-api-key" && selected.Method != "api_key" || measured.Mode == "claudock-headless" && selected.Method != "oauth_token" {
			t.Fatal("installed compatibility receipt replaced its measured credential mode")
		}
		seenModes[measured.Mode] = true
		t.Logf("realBindings compatibility receipt: mode=%s sha256=%s", measured.Mode, runDigest(raw))
	}
	if err := bindings.Records.Close(); err != nil {
		t.Fatal(err)
	}
	// A changed pin must still fail before any request or credential processing.
	if err := os.Chmod(filepath.Join(root, "claude"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "claude"), []byte("changed"), 0555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "claude"), 0555); err != nil {
		t.Fatal(err)
	}
	_, err = runner.Start(context.Background(), api.RunnerRequest{})
	if !errors.As(err, &typed) || typed.Code == api.CodeInvalid {
		t.Fatal("changed runtime bytes reached request validation", err)
	}
}

// Download only the public installer and exact CLI version into this root
// canary's disposable home. No login, prompt or model command is invoked.
func installCompatibilityVendor(t *testing.T, destination string) []byte {
	t.Helper()
	home := t.TempDir()
	installer := filepath.Join(home, "install.sh")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	for _, argv := range [][]string{
		{"/usr/bin/curl", "--fail", "--silent", "--show-error", "--location", "--output", installer, "https://claude.ai/install.sh"},
		{"/usr/bin/bash", installer, claudock.ClaudeVersion},
	} {
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
		cmd.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin", "LANG=C"}
		if err := cmd.Run(); err != nil {
			t.Fatal("public exact-version vendor installation failed", err)
		}
	}
	path, err := filepath.EvalSymlinks(filepath.Join(home, ".local/bin/claude"))
	if err != nil || !strings.HasPrefix(path, home+string(filepath.Separator)) {
		t.Fatal("vendor installer did not retain its executable in the disposable home", err)
	}
	source, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0555)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(file, io.LimitReader(source, api.MaxVendorBytes+1)); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(source.Close(), file.Close()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(destination)
	if err != nil || len(data) == 0 || int64(len(data)) > api.MaxVendorBytes {
		t.Fatal("installed vendor byte inventory differs", err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(destination), "claude-measured.input"), data, 0444); err != nil {
		t.Fatal(err)
	}
	installerBytes, err := os.ReadFile(installer)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(destination), "claude-installer.input"), installerBytes, 0444); err != nil {
		t.Fatal(err)
	}
	tester, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("compatibility inputs: installer_sha256=%s tester_sha256=%s", runDigest(installerBytes), runDigest(tester))
	return data
}

func writeRealSessionEnrollment(t *testing.T, dir string, installed *Installation, wrapper, vendor api.Executable) {
	t.Helper()
	enrollment := api.LaunchEnrollment{Schema: "laneboss.launch-enrollment.v2", Config: installed.Config, Generation: 1,
		Projects: []api.ProjectEnrollment{{ID: "project-enrollment", ProjectID: "project", Generation: 1,
			Object: api.BlobRef{ID: "project", Class: "manifest", Bytes: 1, SHA256: installed.ArtifactSHA256},
			Base:   string(installed.ArtifactSHA256), HistoryScope: "tree"}},
		Runtimes: []api.LaunchRuntime{{EnrollmentID: "real-runtime", Generation: 1, Backend: "linux-bwrap-landlock",
			Driver: api.DriverClaudock, Executable: wrapper, SessionExecutable: vendor, Manifest: installed.RuntimeManifest}}}
	raw, err := json.Marshal(enrollment)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "launch-enrollment.json"), raw, 0444); err != nil {
		t.Fatal(err)
	}
	installed.LaunchEnrollment = &api.BlobRef{ID: "launch-enrollment", Class: "manifest", Bytes: int64(len(raw)), SHA256: runDigest(raw)}
}
