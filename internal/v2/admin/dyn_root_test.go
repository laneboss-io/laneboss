//go:build linux && laneboss_root_canary

package admin

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// The installed artifact, runtime reader, fd mounts, UID/cgroup, fixed
// bootstrap and release are real. Only service authority uses the shared
// disposable fixture; this is not an authenticated vendor request.
func TestDynamicRuntime(t *testing.T) {
	workerLaunchCanary(t, false, dynamicRuntime)
}

func dynamicRuntime(t *testing.T, ctx context.Context, m *leaseManager, data dataReg, ref api.BlobRef, _ api.Executable) {
	t.Helper()
	record, err := m.find(data.Request.AgentLeaseID)
	if err != nil {
		t.Fatal(err)
	}
	reserved := record
	reserved.Phase = "reserved"
	if err := m.resources.Ensure(ctx, reserved); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := m.waitContainmentEmpty(ctx, record); err != nil {
			t.Error(err)
			return
		}
		if err := m.resources.Remove(ctx, reserved); err != nil {
			t.Error(err)
		}
	}()
	closeProc, err := mountHelperProc(m.binding.runtimePath())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := closeProc(); err != nil {
			t.Error(err)
		}
	}()
	manifest, err := loadInstalledRuntime(ctx, m.binding, ref)
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(filepath.Dir(m.binding.binaryPath()), "runtime", m.binding.Config)
	root := filepath.Join(base, "root")
	stage := filepath.Join(m.binding.runtimePath(), "dynamic-inputs")
	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	const host = "/usr/lib/laneboss-v2"
	loader := host + "/dep-loader"
	self, err := elf.Open("/usr/bin/dash")
	if err != nil {
		t.Fatal(err)
	}
	interpreter := ""
	for _, program := range self.Progs {
		if program.Type == elf.PT_INTERP {
			raw, err := io.ReadAll(program.Open())
			if err != nil {
				t.Fatal(err)
			}
			interpreter = strings.TrimRight(string(raw), "\x00")
		}
	}
	self.Close()
	if interpreter == "" {
		t.Fatal("dynamic control requires an actual system ELF interpreter")
	}
	raw, err := os.ReadFile(interpreter)
	if err != nil {
		t.Fatal(err)
	}
	workerCanaryWrite(t, loader, raw, 0555)
	leaf := filepath.Join(stage, "leaf.c")
	middle := filepath.Join(stage, "middle.c")
	main := filepath.Join(stage, "main.c")
	workerCanaryWrite(t, leaf, []byte("#include <unistd.h>\nint leaf(const char *p) { return access(p, F_OK); }\n"), 0444)
	workerCanaryWrite(t, middle, []byte("extern int leaf(const char *);\nint dep(const char *p) { return leaf(p); }\n"), 0444)
	workerCanaryWrite(t, main, []byte(`#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/statvfs.h>
#include <unistd.h>
extern int dep(const char *);
int main(int argc, char **argv) {
    if (argc != 3 || getuid() == 0) return 10;
    if (dep(argv[1]) == 0 || errno != ENOENT) {
        puts("unpinned-visible"); return 11;
    }
    struct statvfs facts;
    if (statvfs(argv[2], &facts) || !(facts.f_flag & ST_RDONLY)) return 12;
    int fd = open(argv[2], O_WRONLY);
    if (fd >= 0) { close(fd); return 13; }
    puts("dynamic-ok");
    return 0;
}
`), 0444)
	run := func(program string, args ...string) []byte {
		t.Helper()
		command := exec.CommandContext(ctx, program, args...)
		command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "TMPDIR=" + stage}
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("dynamic enrollment tool failed: %v\n%s", err, output)
		}
		return output
	}
	run("/usr/bin/cc", "-shared", "-fPIC", "-Wl,-soname,liblb-leaf.so", "-o", host+"/liblb-leaf.so", leaf)
	run("/usr/bin/cc", "-shared", "-fPIC", "-Wl,-soname,liblb-dep.so", "-Wl,-rpath,"+host,
		"-o", host+"/liblb-dep.so", middle, "-L"+host, "-llb-leaf")
	binary := filepath.Join(stage, "dynamic")
	run("/usr/bin/cc", "-Wl,--dynamic-linker="+loader, "-Wl,-rpath,"+host,
		"-o", binary, main, "-L"+host, "-llb-dep", "-llb-leaf")
	for _, path := range []string{binary, host + "/liblb-leaf.so", host + "/liblb-dep.so"} {
		if err := os.Chmod(path, 0555); err != nil {
			t.Fatal(err)
		}
	}
	hidden := host + "/lib-hidden.so"
	raw, err = os.ReadFile(host + "/liblb-leaf.so")
	if err != nil {
		t.Fatal(err)
	}
	workerCanaryWrite(t, hidden, raw, 0555)
	script := filepath.Join(stage, "script")
	envScript := filepath.Join(stage, "env-script")
	workerCanaryWrite(t, script, []byte("#!/bin/sh\nexec /runtime/dynamic \"$@\"\n"), 0555)
	workerCanaryWrite(t, envScript, []byte("#!/usr/bin/env -S sh\nexec /runtime/dynamic \"$@\"\n"), 0555)
	objects := filepath.Join(stage, "objects")
	if err := os.Mkdir(objects, 0700); err != nil {
		t.Fatal(err)
	}
	output := run("/usr/bin/python3", "-I", "-B", "../../../scripts/v2-admin/runtime_deps.py",
		"--root", objects, "--root-id", "root", "--executable", "dynamic="+binary,
		"--executable", "script="+script, "--executable", "env-script="+envScript)
	var additions []api.RuntimeObject
	if err := json.Unmarshal(output, &additions); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"dynamic": binary, "script": script, "env-script": envScript} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		workerCanaryWrite(t, filepath.Join(root, name), raw, 0555)
		id := api.ID(name)
		manifest.Objects = append(manifest.Objects, api.RuntimeObject{ID: id, Role: "dynamic-test", RootID: "root", RelativePath: name, Mode: 0555,
			Content: api.BlobRef{ID: id, Class: "artifact", Bytes: int64(len(raw)), SHA256: digestBytes(raw)}})
	}
	seen := map[string]api.RuntimeObject{}
	for _, object := range manifest.Objects {
		seen[object.RelativePath] = object
	}
	for _, object := range additions {
		if prior, exists := seen[object.RelativePath]; exists {
			if prior.Content.SHA256 != object.Content.SHA256 {
				t.Fatal("bootstrap and dynamic library bytes differ")
			}
			continue
		}
		raw, err := os.ReadFile(filepath.Join(objects, object.RelativePath))
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, object.RelativePath)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		// Match boot.py's installed directory modes despite the root unit's
		// private umask. The unprivileged bind-fd source walk needs traversal.
		for parent := filepath.Dir(path); parent != root; parent = filepath.Dir(parent) {
			if err := os.Chmod(parent, 0755); err != nil {
				t.Fatal(err)
			}
		}
		workerCanaryWrite(t, path, raw, os.FileMode(object.Mode))
		manifest.Objects = append(manifest.Objects, object)
		seen[object.RelativePath] = object
	}
	for _, path := range []string{loader, host + "/liblb-dep.so", host + "/liblb-leaf.so", "/bin/sh", "/usr/bin/env", "/usr/bin/sh"} {
		if _, exists := seen[strings.TrimPrefix(path, "/")]; !exists {
			t.Fatalf("interpreter or transitive dependency was not enrolled: %s", path)
		}
	}
	work := filepath.Join(storageBase(m.binding, record), string(record.Storage.Directories[0].ID))
	local := record
	local.Storage = nil
	compose := func(selected api.RuntimeManifest) ([]*nativeMount, error) {
		raw := mustCanaryJSON(t, selected)
		workerCanaryWrite(t, filepath.Join(base, "manifest.json"), raw, 0444)
		selectedRef := api.BlobRef{ID: "dynamic-runtime", Class: "manifest", Bytes: int64(len(raw)), SHA256: digestBytes(raw)}
		local.Spec = &specRegistration{Handoff: api.PreparedSpecHandoff{Spec: api.LaunchSpec{RuntimeManifest: selectedRef}}}
		_, mounts, err := m.gateMounts(ctx, local)
		return mounts, err
	}
	closeMounts := func(mounts []*nativeMount) {
		for _, mount := range mounts {
			if err := mount.file.Close(); err != nil {
				t.Error(err)
			}
		}
	}
	execute := func(selected api.RuntimeManifest, entry string, expose bool) (int, string) {
		t.Helper()
		mounts, err := compose(selected)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { closeMounts(mounts) }()
		mount, err := pinNativeMount(work, "/work/main", true, true, true, record.Lease.UID, record.Lease.GID)
		if err != nil {
			t.Fatal(err)
		}
		mounts = append(mounts, mount)
		if expose {
			mount, err := pinNativeMount(hidden, hidden, false, false, true, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			mounts = append(mounts, mount)
		}
		stdout, err := os.CreateTemp(stage, "stdout-")
		if err != nil {
			t.Fatal(err)
		}
		defer stdout.Close()
		stderr, err := os.CreateTemp(stage, "stderr-")
		if err != nil {
			t.Fatal(err)
		}
		defer stderr.Close()
		token, err := randomID("dynamic-release-")
		if err != nil {
			t.Fatal(err)
		}
		payload := gatePayload{Config: m.binding.Config, Mode: "prepared-gate", GateID: "dynamic-gate", Token: string(token),
			UID: record.Lease.UID, GID: record.Lease.GID, CWD: "/work/main", Budget: record.Request.Budget,
			Argv: []string{"/runtime/" + entry, hidden, loader}, Environment: []string{"PATH=/usr/bin:/bin"}}
		gate, err := startNativeGate(ctx, m.binding, local, payload, mounts, stdout, stderr, nil, nil, m.bootID)
		if err != nil {
			captured, readErr := os.ReadFile(stderr.Name())
			if readErr == nil {
				t.Logf("dynamic bootstrap stderr: %s", captured)
			}
			t.Fatal("installed dynamic gate did not prepare", err)
		}
		defer func() {
			if err := gate.Close(); err != nil {
				t.Error(err)
			}
		}()
		if err := gate.Release(); err != nil {
			t.Fatal(err)
		}
		native := gate.(*nativeGate)
		select {
		case <-native.done:
		case <-time.After(10 * time.Second):
			t.Fatal("installed dynamic gate did not exit")
		}
		if native.state == nil {
			t.Fatal("installed dynamic gate has no actual exit state")
		}
		captured, err := os.ReadFile(stdout.Name())
		if err != nil {
			t.Fatal(err)
		}
		return native.state.ExitCode(), string(captured)
	}
	for _, missing := range []string{loader, host + "/liblb-leaf.so"} {
		selected := manifest
		selected.Objects = nil
		for _, object := range manifest.Objects {
			if nativeRuntimeTarget(object) != missing {
				selected.Objects = append(selected.Objects, object)
			}
		}
		code, observed := execute(selected, "dynamic", false)
		if code == 0 || strings.Contains(observed, "dynamic-ok") {
			t.Fatal("missing dependency did not prevent actual dynamic execution")
		}
		t.Log("RED: omitted pinned dependency prevents installed dynamic execution")
	}
	for _, changed := range []string{loader, host + "/liblb-leaf.so"} {
		path := filepath.Join(root, strings.TrimPrefix(changed, "/"))
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		altered := bytes.Clone(raw)
		altered[len(altered)-1] ^= 1
		mode := os.FileMode(seen[strings.TrimPrefix(changed, "/")].Mode)
		workerCanaryWrite(t, path, altered, mode)
		mounts, refused := compose(manifest)
		closeMounts(mounts)
		gate, startErr := m.startConfinedGate(ctx, local)
		workerCanaryWrite(t, path, raw, mode)
		if gate != nil {
			_, stopErr := gate.Stop(ctx, api.ProcessHandle{})
			closeErr := gate.Close()
			t.Fatalf("tampered dependency created a native gate: stopped=%t closed=%t", stopErr == nil, closeErr == nil)
		}
		if refused == nil || !strings.Contains(refused.Error(), "runtime object bytes or mode differ") ||
			startErr == nil || !strings.Contains(startErr.Error(), "runtime object bytes or mode differ") {
			t.Fatal("changed loader or library digest was not refused before native spawn", refused, startErr)
		}
		t.Log("tampered pinned dependency: integrity refusal before spawn; no exec")
	}
	code, observed := execute(manifest, "dynamic", true)
	if code != 11 || observed != "unpinned-visible\n" {
		t.Fatal("unlisted-library visibility control did not fail the actual canary", code, observed)
	}
	t.Log("RED: explicitly exposing one unpinned library fails the actual visibility canary")
	for _, entry := range []string{"dynamic", "script", "env-script"} {
		code, observed := execute(manifest, entry, false)
		if code != 0 || observed != "dynamic-ok\n" {
			t.Fatal("pinned dynamic or script execution failed in the installed gate", entry, code, observed)
		}
		t.Log("GREEN: installed gate executes", entry, "with read-only pinned closure and unpinned host library absent")
	}
}
