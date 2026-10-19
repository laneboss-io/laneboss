//go:build linux

package linux

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

const profileRegistryPath = "/sys/kernel/security/" + "apparmor/profiles"

// These are decision fixtures, not successful kernel/process attestations.
// Kernel acceptance still runs the actual fixed commands and pinned FD probe.
type appArmorDecisionFixture struct {
	probe   appArmorProbe
	files   map[string]string
	reads   []string
	calls   int
	results []namespaceCommandResult
}

func deniedNamespaceFixture() namespaceCommandResult {
	return namespaceCommandResult{exitCode: 1, err: errors.New("fixture exit status 1"),
		stderr: "unshare: unshare failed: Operation not permitted\n"}
}

func newAppArmorDecisionFixture(t *testing.T, results []namespaceCommandResult) *appArmorDecisionFixture {
	t.Helper()
	directory := t.TempDir()
	fixture := &appArmorDecisionFixture{results: results, files: map[string]string{}}
	profile := "abi <abi/4.0>,\ninclude <tunables/global>\n\n" +
		"profile laneboss-bwrap /usr/bin/bwrap " + "flags=(unconfined) {\n  userns,\n}\n"
	for index, input := range []struct {
		path string
		data string
		mode fs.FileMode
	}{{appArmorProfilePath, profile, 0644}, {appArmorSysctlPath, "1\n", 0644},
		{profileRegistryPath, "laneboss-bwrap (unconfined)\n", 0000}} {
		file := filepath.Join(directory, []string{"policy", "restriction", "registry"}[index])
		if err := os.WriteFile(file, []byte(input.data), input.mode); err != nil {
			t.Fatal(err)
		}
		fixture.files[input.path] = file
	}
	if _, err := os.ReadFile(fixture.files[profileRegistryPath]); !errors.Is(err, fs.ErrPermission) {
		t.Fatal("registry fixture must actually be unreadable; run as the non-root test account")
	}
	fixture.probe.resolve = func(path string) (string, error) {
		for _, expected := range []string{"/etc/apparmor.d/laneboss-bwrap", "/usr/bin/bwrap", "/usr/bin/unshare", "/usr/bin/true"} {
			if path == expected {
				return path, nil // Synthetic protected ownership for this decision test only.
			}
		}
		return "", fs.ErrNotExist
	}
	fixture.probe.readFile = func(path string) ([]byte, error) {
		fixture.reads = append(fixture.reads, path)
		file, ok := fixture.files[path]
		if !ok {
			return nil, fs.ErrNotExist
		}
		return os.ReadFile(file)
	}
	fixture.probe.command = func(ctx context.Context, path string, args []string) namespaceCommandResult {
		if _, bounded := ctx.Deadline(); !bounded {
			t.Fatal("namespace decision omitted its bounded deadline")
		}
		control := []string{"--user", "--map-root-user", "--mount", "--", "/usr/bin/true"}
		wantPath, wantArgs := "/usr/bin/unshare", control
		if fixture.calls%3 == 1 {
			wantPath = "/usr/bin/bwrap"
			wantArgs = []string{"--die-with-parent", "--unshare-user", "--unshare-pid",
				"--unshare-net", "--ro-bind", "/", "/", "--", "/usr/bin/true"}
		}
		if path != wantPath || !reflect.DeepEqual(args, wantArgs) {
			t.Fatal("namespace decision used the wrong fixed command or order")
		}
		if fixture.calls >= len(fixture.results) {
			t.Fatal("namespace decision requested an unprovided observation")
		}
		observed := fixture.results[fixture.calls]
		fixture.calls++
		return observed
	}
	return fixture
}

func TestAppArmorUnreadableRegistry(t *testing.T) {
	fixture := newAppArmorDecisionFixture(t, []namespaceCommandResult{
		deniedNamespaceFixture(), {exitCode: 0}, deniedNamespaceFixture(),
	})
	if err := fixture.probe.check(context.Background()); err != nil {
		t.Fatal("unreadable registry blocked independently observed namespace behavior:", err)
	}
	if fixture.calls != 3 || !reflect.DeepEqual(fixture.reads,
		[]string{appArmorProfilePath, appArmorSysctlPath, appArmorSysctlPath}) {
		t.Fatal("prerequisite skipped behavior/switch checks or read the root-only registry")
	}
}

func TestAppArmorUIDMapDenial(t *testing.T) {
	// Exact diagnostic text supplied by the restriction-on box, without
	// assuming a trailing newline. It fails during --map-root-user setup.
	denied := namespaceCommandResult{exitCode: 1, err: errors.New("fixture exit status 1"),
		stderr: "unshare: write failed /proc/self/uid_map: Operation not permitted"}
	fixture := newAppArmorDecisionFixture(t, []namespaceCommandResult{denied, {exitCode: 0}, denied})
	if err := fixture.probe.check(context.Background()); err != nil {
		t.Fatal("namespace mapping permission denial was rejected:", err)
	}
	if fixture.calls != 3 {
		t.Fatal("mapping denial bypassed a before/after observation")
	}
}

func TestAppArmorOtherExitOne(t *testing.T) {
	for _, diagnostic := range []string{
		"unshare: write failed /proc/self/uid_map: Invalid argument",
		"unshare: write failed /tmp/record: Operation not permitted",
	} {
		for _, index := range []int{0, 2} {
			cause := errors.New("fixture unrelated exit status 1")
			results := []namespaceCommandResult{deniedNamespaceFixture(), {exitCode: 0}, deniedNamespaceFixture()}
			results[index] = namespaceCommandResult{exitCode: 1, err: cause, stderr: diagnostic}
			fixture := newAppArmorDecisionFixture(t, results)
			err := fixture.probe.check(context.Background())
			if !errors.Is(err, cause) || fixture.calls != index+1 {
				t.Fatal("unrelated exit 1 was accepted or its cause was lost:", err)
			}
			firstLine, _, _ := strings.Cut(err.Error(), "\n")
			phase := "before bwrap"
			if index == 2 {
				phase = "after bwrap"
			}
			for _, required := range []string{phase, "exit 1", "stderr head: " + strconv.Quote(diagnostic),
				"failed conditions: namespace permission diagnostic missing"} {
				if !strings.Contains(firstLine, required) {
					t.Fatal("first-line refusal omitted its phase, exit, stderr or failed condition:", firstLine)
				}
			}
		}
	}
}

func TestNamespacePermissionDiagnostics(t *testing.T) {
	for _, target := range []string{"uid_map", "gid_map", "setgroups"} {
		for _, cause := range []string{"Operation not permitted", "Permission denied"} {
			diagnostic := "unshare: write failed /proc/self/" + target + ": " + cause + "\n"
			if !namespacePermissionDenied(diagnostic) {
				t.Fatal("namespace setup permission diagnostic was rejected")
			}
		}
	}
	for _, diagnostic := range []string{"unshare: bad option: Permission denied",
		"unshare: unshare failed: Invalid argument",
		"other: unshare failed: Operation not permitted",
		"unshare: write failed /proc/self/uid_map: Operation not permitted elsewhere"} {
		if namespacePermissionDenied(diagnostic) {
			t.Fatal("unrelated operation, program or cause was treated as namespace denial")
		}
	}
}

func TestNamespaceStderrHead(t *testing.T) {
	var head namespaceStderrHead
	prefix := "first diagnostic\n"
	fill := strings.Repeat("x", 8192)
	for _, chunk := range []string{prefix, fill, "last diagnostic\n"} {
		written, err := head.Write([]byte(chunk))
		if err != nil || written != len(chunk) {
			t.Fatal("bounded capture did not drain the complete stderr stream")
		}
	}
	if string(head.data) != (prefix + fill)[:8192] {
		t.Fatal("stderr capture lost its original head or exceeded its limit")
	}
}

func TestAppArmorAbsentBehavior(t *testing.T) {
	denied := deniedNamespaceFixture()
	fixture := newAppArmorDecisionFixture(t, []namespaceCommandResult{denied,
		{exitCode: 1, err: fs.ErrPermission, stderr: "bwrap: namespace permission denied\n"}, denied})
	err := fixture.probe.check(context.Background())
	if !errors.Is(err, fs.ErrPermission) || !strings.Contains(err.Error(), "profiled bwrap namespace probe failed") {
		t.Fatal("absent bwrap behavior did not refuse with its cause:", err)
	}
	if fixture.calls != 2 {
		t.Fatal("failed bwrap behavior did not stop at the failed command")
	}
}

func TestAppArmorControlRefusals(t *testing.T) {
	for _, cell := range []struct {
		name     string
		index    int
		observed namespaceCommandResult
	}{
		{"unprofiled-before-allowed", 0, namespaceCommandResult{exitCode: 0}},
		{"unprofiled-after-allowed", 2, namespaceCommandResult{exitCode: 0}},
		{"control-missing", 0, namespaceCommandResult{exitCode: -1, err: fs.ErrNotExist}},
		{"control-other-error", 0, namespaceCommandResult{exitCode: 1, err: fs.ErrInvalid, stderr: "unshare: bad option"}},
		{"control-empty-diagnostic", 0, namespaceCommandResult{exitCode: 1, err: fs.ErrPermission}},
		{"control-no-exit-error", 0, namespaceCommandResult{exitCode: 1,
			stderr: "unshare: unshare failed: Operation not permitted"}},
		{"control-timeout", 0, namespaceCommandResult{exitCode: 1, err: context.DeadlineExceeded,
			stderr: "unshare: unshare failed: Operation not permitted"}},
		{"control-canceled", 0, namespaceCommandResult{exitCode: 1, err: context.Canceled,
			stderr: "unshare: unshare failed: Operation not permitted"}},
		{"bwrap-missing", 1, namespaceCommandResult{exitCode: -1, err: fs.ErrNotExist}},
		{"bwrap-timeout", 1, namespaceCommandResult{exitCode: 0, err: context.DeadlineExceeded}},
	} {
		t.Run(cell.name, func(t *testing.T) {
			results := []namespaceCommandResult{deniedNamespaceFixture(), {exitCode: 0}, deniedNamespaceFixture()}
			results[cell.index] = cell.observed
			fixture := newAppArmorDecisionFixture(t, results)
			err := fixture.probe.check(context.Background())
			if err == nil || fixture.calls != cell.index+1 {
				t.Fatal("ambiguous/missing namespace evidence did not stop the prerequisite:", err)
			}
			if cell.observed.err != nil && !errors.Is(err, cell.observed.err) {
				t.Fatal("namespace command cause was lost:", err)
			}
			firstLine, _, _ := strings.Cut(err.Error(), "\n")
			for _, required := range []string{"exit " + strconv.Itoa(cell.observed.exitCode),
				"stderr head: " + strconv.Quote(cell.observed.stderr), "failed conditions: "} {
				if !strings.Contains(firstLine, required) {
					t.Fatal("refusal lost the captured exit, stderr head or failed conditions:", firstLine)
				}
			}
			for cause, condition := range map[error]string{context.Canceled: "command canceled",
				context.DeadlineExceeded: "command timed out"} {
				if errors.Is(cell.observed.err, cause) && !strings.Contains(firstLine, condition) {
					t.Fatal("refusal omitted its cancellation/timeout condition:", firstLine)
				}
			}
		})
	}
}

func TestAppArmorProfileInputsRemainRequired(t *testing.T) {
	for _, cell := range []string{"unreadable-policy", "different-policy", "linked-input", "untrusted-input", "missing-behavior"} {
		t.Run(cell, func(t *testing.T) {
			fixture := newAppArmorDecisionFixture(t, nil)
			switch cell {
			case "unreadable-policy":
				fixture.files[appArmorProfilePath] = fixture.files[profileRegistryPath]
			case "different-policy":
				if err := os.WriteFile(fixture.files[appArmorProfilePath], []byte("broad policy"), 0644); err != nil {
					t.Fatal(err)
				}
			case "linked-input":
				fixture.probe.resolve = func(path string) (string, error) { return path + ".linked", nil }
			case "untrusted-input":
				fixture.probe.resolve = func(string) (string, error) { return "", fs.ErrPermission }
			case "missing-behavior":
				fixture.probe.command = nil
			}
			if err := fixture.probe.check(context.Background()); err == nil || fixture.calls != 0 {
				t.Fatal("missing integrity/behavior input was accepted or executed a command:", err)
			}
		})
	}
}

func TestAppArmorBehaviorAndSwitchRechecked(t *testing.T) {
	denied := deniedNamespaceFixture()
	fixture := newAppArmorDecisionFixture(t, []namespaceCommandResult{denied, {exitCode: 0}, denied,
		denied, {exitCode: 1, err: fs.ErrPermission}})
	if err := fixture.probe.check(context.Background()); err != nil {
		t.Fatal("initial behavior control failed:", err)
	}
	if err := fixture.probe.check(context.Background()); !errors.Is(err, fs.ErrPermission) || fixture.calls != 5 {
		t.Fatal("prior successful behavior substituted for the current failed observation:", err)
	}
	fixture = newAppArmorDecisionFixture(t, []namespaceCommandResult{denied, {exitCode: 0}, denied})
	command := fixture.probe.command
	fixture.probe.command = func(ctx context.Context, path string, args []string) namespaceCommandResult {
		observed := command(ctx, path, args)
		if fixture.calls == 3 {
			if err := os.WriteFile(fixture.files[appArmorSysctlPath], []byte("0\n"), 0644); err != nil {
				t.Fatal(err)
			}
		}
		return observed
	}
	if err := fixture.probe.check(context.Background()); err == nil || !strings.Contains(err.Error(), "restriction changed") {
		t.Fatal("changed host restriction was credited as a bwrap-only exception:", err)
	}
}
