//go:build linux && laneboss_root_canary && laneboss_gate_integration

package admin

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	release "laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/v2/api"
)

// Exercise the actual source installer with a compiled product and fresh boot
// inputs. A private mount namespace isolates the release destination between
// red and candidate runs; the test never rewrites an earlier installed binary.
func TestCredentialFreshInstallation(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("fresh credential installation requires the disposable Linux root box")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if len(os.Args) >= 3 && os.Args[len(os.Args)-2] == "credential-install-child" {
		credentialInstallChild(t, ctx, os.Args[len(os.Args)-1])
		return
	}
	if len(os.Args) >= 3 && os.Args[len(os.Args)-2] == "credential-bind-child" {
		credentialInstalledBinding(t, ctx, os.Args[len(os.Args)-1])
		return
	}
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root = filepath.Clean(filepath.Join(root, "../../.."))
	base, err := os.MkdirTemp("/opt", "lb-v2-s3fix-install-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(base, 0755); err != nil {
		t.Fatal(err)
	}
	// Retain the installed inputs and command output on the disposable box.
	for _, relative := range []string{"scripts/v2-admin/install.sh", "scripts/v2-admin/boot.py", "packaging/v2/linux/laneboss-helper.service.in", "packaging/v2/linux/laneboss-service.service.in", "packaging/v2/linux/laneboss-credential.service.in"} {
		data, err := os.ReadFile(filepath.Join(root, relative))
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(base, "source", relative)
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			t.Fatal(err)
		}
		workerCanaryWrite(t, target, data, 0444)
	}
	binary := filepath.Join(base, "laneboss")
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "./cmd/laneboss")
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("compile the actual installed product: %v\n%s", err, output)
	}
	if err := os.Chmod(binary, 0555); err != nil {
		t.Fatal(err)
	}
	child := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestCredentialFreshInstallation$", "-test.v", "--", "credential-install-child", base)
	child.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS}
	output, err := child.CombinedOutput()
	workerCanaryWrite(t, filepath.Join(base, "test.log"), output, 0600)
	if err != nil {
		t.Fatalf("fresh installed credential peers: %v\n%s", err, output)
	}
	t.Log(string(output))
}

func credentialInstallChild(t *testing.T, ctx context.Context, base string) {
	t.Helper()
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	releases := "/usr/lib/laneboss-v2"
	if err := os.MkdirAll(releases, 0755); err != nil {
		t.Fatal(err)
	}
	backing := filepath.Join(base, "releases")
	if err := os.Mkdir(backing, 0755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(backing, releases, "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	unitBinds := []string{backing + ":" + releases}
	var stateBacking string
	for index, path := range []string{"/var/lib/laneboss-v2", "/run/laneboss-v2", "/run/laneboss-v2-service", "/run/lb-v2-cred"} {
		if err := os.MkdirAll(path, 0755); err != nil {
			t.Fatal(err)
		}
		name := filepath.Join(base, fmt.Sprintf("installed-root-%d", index))
		if err := os.Mkdir(name, 0755); err != nil {
			t.Fatal(err)
		}
		if err := unix.Mount(name, path, "", unix.MS_BIND, ""); err != nil {
			t.Fatal(err)
		}
		unitBinds = append(unitBinds, name+":"+path)
		if index == 0 {
			stateBacking = name
		}
	}
	binary := filepath.Join(base, "laneboss")
	artifact, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	id, err := randomID("s3-")
	if err != nil {
		t.Fatal(err)
	}
	config := string(id[:32])
	writeJSON := func(name string, value any) string {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(base, name)
		workerCanaryWrite(t, path, data, 0600)
		return path
	}
	content := api.BlobRef{ID: "installed-artifact", SHA256: digestBytes(artifact), Bytes: int64(len(artifact)), Class: "manifest"}
	executable := api.Executable{ID: content.ID, SHA256: content.SHA256, Version: release.Version}
	runtimeBytes, err := json.Marshal(api.RuntimeManifest{Schema: "laneboss.runtime.v2", Generation: 1, Artifact: executable, Bootstrap: executable,
		Objects: []api.RuntimeObject{{ID: content.ID, Role: "artifact", RootID: "input", RelativePath: "laneboss", Content: content, Mode: 0555}}, Bindings: []api.InstalledBinding{}})
	if err != nil {
		t.Fatal(err)
	}
	runtimePath := filepath.Join(base, "runtime.json")
	workerCanaryWrite(t, runtimePath, runtimeBytes, 0600)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(base, "native.key")
	workerCanaryWrite(t, keyPath, key, 0600)
	clear(key)
	manifest := writeJSON("release.json", map[string]any{"version": release.Version, "protocol": api.Protocol, "schema": 2,
		"source_sha256": digestBytes(artifact), "artifacts": []api.ReleaseArtifact{{OS: "linux", Arch: runtime.GOARCH, SHA256: content.SHA256, Bytes: content.Bytes}}, "vendor_manifest": content})
	boot := writeJSON("boot.json", map[string]any{"schema": "laneboss.boot-input.v2", "runtime_manifest": api.BlobRef{ID: "runtime", SHA256: digestBytes(runtimeBytes), Bytes: int64(len(runtimeBytes)), Class: "manifest"},
		"runtime_file": runtimePath, "runtime_roots": []map[string]string{{"id": "input", "path": base}}, "secret_key_file": keyPath,
		"judge_endpoint": "http://127.0.0.1:1", "judge": api.JudgeConfig{Provider: "clef-sglang", Model: "Cloudflare/clef-flash", DeploymentSHA256: digestBytes([]byte(config)), TokenizerSHA256: digestBytes(runtimeBytes), ContextTokens: 256, MaxBytes: 256, MaxQuestions: 1, CommandDeadlineMS: 1000, GuidanceDeadlineMS: 1000, OutagePolicy: "critical-only"}})
	install := exec.CommandContext(ctx, "/bin/bash", filepath.Join(base, "source/scripts/v2-admin/install.sh"), "--install", "--config", config, "--binary", binary, "--manifest", manifest, "--boot", boot, "--evidence", filepath.Join(base, "install"))
	install.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	output, err := install.CombinedOutput()
	workerCanaryWrite(t, filepath.Join(base, "installer.log"), output, 0600)
	if err != nil {
		t.Fatalf("actual protected installer: %v\n%s", err, output)
	}
	binding, err := loadInstallation(config)
	if err != nil {
		t.Fatal(err)
	}
	data, err := readProtected(filepath.Join("/etc/laneboss-v2/credential-peers", config+".json"), api.MaxFrameBytes)
	if err != nil {
		t.Fatal("acceptance: fresh source installation omitted protected native credential peers", err)
	}
	var peers credentialPeerCatalog
	if err := decodeStrict(data, &peers); err != nil || peers.Schema != "laneboss.credential-peers.v2" || peers.Config != config || peers.Generation != binding.Generation || peers.Broker.UID == 0 || peers.Broker.UID == binding.Service.UID || peers.Identity.UID != binding.Service.UID {
		t.Fatal("acceptance: native peer catalog lost the installed generation or separate owners", err)
	}
	for _, lane := range binding.Lanes {
		if peers.Broker.UID == lane.UID {
			t.Fatal("acceptance: broker was placed in the lane UID pool")
		}
	}
	for role, pin := range map[string]credentialPeerPin{"broker": peers.Broker, "identity": peers.Identity} {
		if pin.Bytes != content.Bytes || pin.Executable.SHA256 != content.SHA256 || pin.Executable.Version != release.Version || pin.Cgroup == "" || pin.Cgroup == "/" || pin.ContainmentID == "" || !strings.HasPrefix(pin.Cgroup, "/system.slice/") {
			t.Fatalf("acceptance: %s peer lacks the actual installed executable and containment pins", role)
		}
	}
	// Systemd's manager lives outside this test's private release mount. Give
	// each actual installed unit the same read-only release through a bind;
	// all shipped hardening, accounts and command lines remain in force.
	for _, role := range []string{"helper", "credential", "service"} {
		dropin := filepath.Join("/etc/systemd/system", "laneboss-"+role+"@"+config+".service.d")
		if err := os.MkdirAll(dropin, 0755); err != nil {
			t.Fatal(err)
		}
		logPath := filepath.Join(base, "unit-"+role+".log")
		definition := "[Service]\nBindReadOnlyPaths=" + strings.Join(unitBinds, " ") + "\nStandardOutput=append:" + logPath + "\nStandardError=append:" + logPath + "\n"
		if role == "credential" {
			definition += "LoadCredential=\nLoadCredential=native.key:" + filepath.Join(stateBacking, "secrets", config, "keys", "key-"+string(digestBytes(mustCredentialKey(t, keyPath)))[:32]+".key") + "\n"
		}
		workerCanaryWrite(t, filepath.Join(dropin, "test-release.conf"), []byte(definition), 0644)
	}
	unitCommand := func(args ...string) {
		t.Helper()
		command := exec.CommandContext(ctx, "/usr/bin/systemctl", args...)
		command.Env = []string{}
		if out, err := command.CombinedOutput(); err != nil {
			t.Fatalf("installed unit operation failed: %v\n%s", err, out)
		}
	}
	unitCommand("daemon-reload")
	defer unitCommand("stop", "laneboss-service@"+config+".service", "laneboss-credential@"+config+".service", "laneboss-helper@"+config+".service")
	unitCommand("start", "laneboss-service@"+config+".service")
	ready := time.NewTicker(100 * time.Millisecond)
	defer ready.Stop()
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
waiting:
	for {
		all := true
		for _, path := range []string{filepath.Join(binding.credentialRuntimePath(), "owners", "broker", "credential-broker.sock"), filepath.Join(binding.credentialRuntimePath(), "owners", "identity", "credential-identity.sock"), filepath.Join(binding.credentialRuntimePath(), "owners", "identity", "credential-component.sock")} {
			info, err := os.Lstat(path)
			if err != nil || info.Mode()&os.ModeSocket == 0 {
				all = false
				break
			}
		}
		if all {
			break waiting
		}
		select {
		case <-ready.C:
		case <-ctx.Done():
			t.Fatal("installed native owners did not become ready within the test deadline")
		case <-deadline.C:
			for _, role := range []string{"helper", "credential", "service"} {
				command := exec.CommandContext(ctx, "/usr/bin/systemctl", "show", "laneboss-"+role+"@"+config+".service", "--property=ActiveState,Result,ExecMainStatus")
				out, err := command.CombinedOutput()
				t.Logf("%s native owner verdict: %s (%v)", role, strings.ReplaceAll(string(out), "\n", " "), err)
				if log, readErr := os.ReadFile(filepath.Join(base, "unit-"+role+".log")); readErr == nil {
					t.Logf("%s native owner diagnostic: %s", role, strings.ReplaceAll(string(log), "\n", " "))
				}
			}
			t.Fatal("acceptance: installed native credential owners did not create their actual listeners")
		}
	}
	self, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	canary := filepath.Join(base, "binding-canary")
	workerCanaryWrite(t, canary, self, 0555)
	args := []string{"--quiet", "--wait", "--pipe", "--collect", "--unit=laneboss-s3fix-bind@" + config + ".service"}
	args = append(args, workerCanaryProperties(t, config)...)
	args = append(args, "--property=BindReadOnlyPaths="+strings.Join(unitBinds, " "), canary, "-test.run=^TestCredentialFreshInstallation$", "-test.v", "--", "credential-bind-child", config)
	command := exec.CommandContext(ctx, "/usr/bin/systemd-run", args...)
	command.Env = []string{}
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("installed helper-policy credential binding failed: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}

func mustCredentialKey(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(data) })
	return data
}

func credentialInstalledBinding(t *testing.T, ctx context.Context, config string) {
	t.Helper()
	b, err := loadInstallation(config)
	if err != nil {
		t.Fatal(err)
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	m := newLeaseManager(b, strings.TrimSpace(string(boot)), nil, nil)
	bound := m.bindCredentials(ctx)
	if !bound.Bound || bound.Failure != nil || m.credentials == nil {
		t.Fatal("acceptance: fresh installed native credential peers did not bind", bound.Failure)
	}
	broker := m.credentials.broker.(*nativeCredentialBroker).channel
	identity := m.credentials.identity.(*nativeCredentialIdentity).channel
	defer broker.Close()
	defer identity.Close()
	if err := m.credentials.checkBinding(ctx); err != nil {
		t.Fatal("acceptance: installed native peers lost their actual measured channels", err)
	}
	for _, mode := range []string{"cgroup", "executable", "uid"} {
		pin := broker.pin
		switch mode {
		case "cgroup":
			pin.Cgroup += "-foreign"
		case "executable":
			pin.Executable.SHA256 = digestBytes([]byte(pin.Executable.SHA256))
		case "uid":
			pin.UID = b.Service.UID
		}
		channel, err := openCredentialChannel(ctx, b, m.bootID, "credential-broker.sock", pin)
		if err == nil {
			channel.Close()
			t.Fatalf("acceptance: %s drift was accepted as the installed native broker", mode)
		}
	}
	if err := unix.PidfdSendSignal(broker.peer.pidfd, unix.SIGTERM, nil, 0); err != nil {
		t.Fatal(err)
	}
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		if err := broker.Alive(ctx); err != nil {
			break
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("acceptance: native broker exit left its credential authority live")
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	t.Log("installed native peers bound under helper policy; UID, executable, cgroup and exited-owner controls refused")
}
