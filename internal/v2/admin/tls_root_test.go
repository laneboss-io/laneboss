//go:build linux && laneboss_root_canary

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func init() {
	if len(os.Args) != 2 || os.Args[1] != "measured-tls-probe" {
		return
	}
	if os.Geteuid() == 0 {
		os.Exit(10)
	}
	if _, err := os.Stat("/etc/passwd"); !os.IsNotExist(err) {
		os.Exit(11)
	}
	if _, err := os.Stat("/sys"); !os.IsNotExist(err) {
		os.Exit(12)
	}
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		os.Exit(13)
	}
	if err := os.WriteFile("/home/lane/tls-ready", []byte("private home\n"), 0600); err != nil {
		os.Exit(14)
	}
	if err := os.WriteFile("/home/lane/README.md", []byte("# Runtime README\n\nProbe input.\n"), 0600); err != nil {
		os.Exit(17)
	}
	tool := exec.Command("/usr/bin/sh", "-c", `git --version && uname -s && while IFS= read -r line; do case "$line" in '# '*) printf '%s\n' "$line"; break;; esac; done < /home/lane/README.md`)
	tool.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	toolOutput, toolErr := tool.CombinedOutput()
	if toolErr != nil || !strings.HasPrefix(string(toolOutput), "git version ") || !strings.HasSuffix(string(toolOutput), "\nLinux\n# Runtime README\n") {
		fmt.Fprintln(os.Stderr, "audited startup program probe failed:", toolErr)
		os.Exit(16)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", "api.anthropic.com")
	if err != nil || len(addresses) == 0 {
		os.Exit(7)
	}
	// The standard resolver reads the installed resolv.conf. egressProbe's
	// auto mode installs no Resolver.Dial function and verifies the real peer.
	code := egressProbe("tls", "api.anthropic.com:443", "auto")
	if code == 0 {
		bundle, bundleErr := os.ReadFile("/etc/ssl/certs/ca-certificates.crt")
		alias, aliasErr := os.ReadFile("/etc/ssl/cert.pem")
		if bundleErr != nil || aliasErr != nil || len(bundle) == 0 || !bytes.Equal(bundle, alias) {
			os.Exit(15)
		}
		fmt.Println("dns-tls-ok")
	}
	os.Exit(code)
}

func TestRuntimeTLS(t *testing.T) {
	if os.Geteuid() == 0 && os.Args[len(os.Args)-1] != "worker-root" {
		previous, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(string(previous)) != "1" {
			if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", previous, 0644); err != nil {
					t.Error(err)
				}
			})
		}
	}
	workerLaunchCanary(t, false, runtimeTLS)
}

// The real installed gate uses production controlled egress, including its
// public DNS resolution, firewall, private namespace and sealed resolver.
func runtimeTLS(t *testing.T, ctx context.Context, m *leaseManager, data dataReg, ref api.BlobRef, executable api.Executable) {
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
	stage := filepath.Join(m.binding.runtimePath(), "tls-inputs")
	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, "/usr/bin/python3", "-I", "-B", "../../../scripts/v2-admin/runtime_deps.py",
		"--root", stage, "--root-id", "root", "--measured", "--executable", string(executable.ID)+"="+m.binding.binaryPath())
	command.Env = []string{}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("measured enrollment failed: %v\n%s", err, output)
	}
	var additions []api.RuntimeObject
	if err := json.Unmarshal(output, &additions); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(filepath.Dir(m.binding.binaryPath()), "runtime", m.binding.Config)
	root := filepath.Join(base, "root")
	seen := map[string]api.RuntimeObject{}
	for _, object := range manifest.Objects {
		seen[object.RelativePath] = object
	}
	aliasCount, certCount := 0, 0
	for _, object := range additions {
		aliasCount += len(object.Aliases)
		if object.Role == "runtime-cert" {
			certCount++
		}
		if prior, exists := seen[object.RelativePath]; exists {
			if prior.Content.SHA256 != object.Content.SHA256 {
				t.Fatal("measured and bootstrap runtime differ")
			}
			continue
		}
		raw, err := os.ReadFile(filepath.Join(stage, object.RelativePath))
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(root, object.RelativePath)
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			t.Fatal(err)
		}
		for parent := filepath.Dir(target); parent != root; parent = filepath.Dir(parent) {
			if err := os.Chmod(parent, 0755); err != nil {
				t.Fatal(err)
			}
		}
		workerCanaryWrite(t, target, raw, os.FileMode(object.Mode))
		manifest.Objects = append(manifest.Objects, object)
		seen[object.RelativePath] = object
	}
	if len(manifest.Objects) > 128 || certCount != 1 || aliasCount != 1 {
		t.Fatal("measured pins exceeded the unchanged object bound or did not use one CA bundle and alias")
	}
	bundle := seen["etc/ssl/certs/ca-certificates.crt"]
	if bundle.Role != "runtime-cert" || bundle.Mode != 0444 || len(bundle.Aliases) != 1 || bundle.Aliases[0] != "/etc/ssl/cert.pem" {
		t.Fatal("CA bundle or its measured alias was not pinned read-only")
	}
	if seen["etc/resolv.conf"].ID != "" {
		t.Fatal("host resolver was enrolled")
	}
	for _, name := range []string{"etc/nsswitch.conf", "etc/hosts", "etc/ld.so.cache"} {
		if seen[name].ID == "" {
			t.Fatal("measured resolver file was not pinned", name)
		}
	}
	linkage, err := os.ReadFile(filepath.Join(stage, "runtime-links.json"))
	if err != nil {
		t.Fatal(err)
	}
	var classes struct {
		Files []struct {
			Path           string `json:"path"`
			Classification string `json:"classification"`
			Reason         string `json:"reason"`
			Provider       string `json:"provider"`
		} `json:"files"`
	}
	if err := json.Unmarshal(linkage, &classes); err != nil {
		t.Fatal(err)
	}
	for _, file := range classes.Files {
		if strings.HasPrefix(file.Path, "/etc/") && file.Classification != "" {
			entry := fmt.Sprintf("etc %s %s", file.Path, file.Classification)
			if file.Provider != "" {
				entry += " provider=" + file.Provider
			}
			if file.Reason != "" && !strings.HasPrefix(file.Path, "/etc/ssl/certs/") {
				entry += " reason=" + file.Reason
			}
			t.Log(entry)
		}
	}
	lease, err := newEgressLease(ctx, api.NetworkEndpoint{ID: "anthropic-api", Host: "api.anthropic.com", Protocol: "tcp", Port: 443}, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal("real controlled egress setup failed", err)
	}
	defer func() {
		if err := lease.close(); err != nil {
			t.Error(err)
		}
		if err := lease.ns.Close(); err != nil {
			t.Error(err)
		}
	}()
	local := record
	local.Storage = nil
	execute := func(selected api.RuntimeManifest) (int, string) {
		t.Helper()
		raw := mustCanaryJSON(t, selected)
		workerCanaryWrite(t, filepath.Join(base, "manifest.json"), raw, 0444)
		selectedRef := api.BlobRef{ID: "tls-runtime", Class: "manifest", Bytes: int64(len(raw)), SHA256: digestBytes(raw)}
		local.Spec = &specRegistration{Handoff: api.PreparedSpecHandoff{Spec: api.LaunchSpec{RuntimeManifest: selectedRef}}}
		_, mounts, err := m.gateMounts(ctx, local)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			for _, mount := range mounts {
				if err := mount.file.Close(); err != nil {
					t.Error(err)
				}
			}
		}()
		resolver, err := resolverReader(lease.resolv)
		if err != nil {
			t.Fatal(err)
		}
		mounts = append(mounts, &nativeMount{file: resolver, target: privateResolver, resolver: true})
		for index, target := range []string{"/work/main", "/home/lane"} {
			path := filepath.Join(storageBase(m.binding, record), string(record.Storage.Directories[index].ID))
			mount, err := pinNativeMount(path, target, true, true, true, record.Lease.UID, record.Lease.GID)
			if err != nil {
				t.Fatal(err)
			}
			mounts = append(mounts, mount)
		}
		stdout, err := os.CreateTemp(stage, "tls-out-")
		if err != nil {
			t.Fatal(err)
		}
		defer stdout.Close()
		stderr, err := os.CreateTemp(stage, "tls-err-")
		if err != nil {
			t.Fatal(err)
		}
		defer stderr.Close()
		token, err := randomID("tls-release-")
		if err != nil {
			t.Fatal(err)
		}
		payload := gatePayload{Config: m.binding.Config, Mode: "prepared-gate", GateID: "tls-gate", Token: string(token),
			UID: record.Lease.UID, GID: record.Lease.GID, CWD: "/work/main", Budget: record.Request.Budget,
			Argv:        []string{"/runtime/" + string(executable.ID), "measured-tls-probe"},
			Environment: []string{"HOME=/home/lane", "PATH=/usr/bin:/bin", "GOMAXPROCS=1"}}
		gate, err := startNativeGate(ctx, m.binding, local, payload, mounts, stdout, stderr, nil, lease.ns, m.bootID)
		if err != nil {
			captured, _ := os.ReadFile(stderr.Name())
			t.Fatalf("measured installed gate failed: %v\n%s", err, captured)
		}
		defer gate.Close()
		if err := gate.Release(); err != nil {
			t.Fatal(err)
		}
		native := gate.(*nativeGate)
		select {
		case <-native.done:
		case <-time.After(20 * time.Second):
			t.Fatal("measured TLS gate did not exit")
		}
		if native.state == nil {
			t.Fatal("TLS gate has no exit state")
		}
		if native.state.ExitCode() != 0 {
			captured, _ := os.ReadFile(stderr.Name())
			t.Logf("measured probe stderr: %s", captured)
		}
		captured, err := os.ReadFile(stdout.Name())
		if err != nil {
			t.Fatal(err)
		}
		return native.state.ExitCode(), string(captured)
	}
	withoutTools := manifest
	withoutTools.Objects = nil
	for _, object := range manifest.Objects {
		if object.RelativePath != "usr/bin/git" && object.RelativePath != "usr/bin/sh" && object.RelativePath != "usr/bin/uname" {
			withoutTools.Objects = append(withoutTools.Objects, object)
		}
	}
	if code, _ := execute(withoutTools); code != 16 {
		t.Fatal("missing startup program control did not fail actual execution", code)
	}
	t.Log("RED: omitted audited startup programs fail actual child execution")
	withoutCA := manifest
	withoutCA.Objects = nil
	for _, object := range manifest.Objects {
		if !strings.HasPrefix(nativeRuntimeTarget(object), "/etc/ssl/") {
			withoutCA.Objects = append(withoutCA.Objects, object)
		}
	}
	if code, _ := execute(withoutCA); code != 8 {
		t.Fatal("missing CA control did not fail actual certificate verification", code)
	}
	t.Log("RED: missing measured CA files fail the real TLS certificate verification")
	withoutAlias := manifest
	withoutAlias.Objects = append([]api.RuntimeObject(nil), manifest.Objects...)
	for index := range withoutAlias.Objects {
		if withoutAlias.Objects[index].Role == "runtime-cert" {
			withoutAlias.Objects[index].Aliases = nil
		}
	}
	if code, _ := execute(withoutAlias); code != 15 {
		t.Fatal("missing bundle alias control did not fail the in-gate byte check", code)
	}
	t.Log("RED: missing measured bundle alias fails the in-gate byte check after verified TLS")
	if code, observed := execute(manifest); code != 0 || observed != "dns-tls-ok\n" {
		t.Fatal("measured pins did not resolve the real hostname and verify TLS", code, observed)
	}
	t.Logf("GREEN: audited sh/git/uname execute and read the README fixture, egress sealed resolver and verified public TLS inside installed gate; objects=%d certificate_aliases=%d; proc and private home present, sys and unpinned etc file absent", len(manifest.Objects), aliasCount)
}
