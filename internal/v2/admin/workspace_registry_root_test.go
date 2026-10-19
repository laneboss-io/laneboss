//go:build linux && laneboss_root_canary && laneboss_gate_integration

package admin

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// The child uses every shipped helper property via workerCanaryProperties,
// including ProtectSystem, the capability ceiling, seccomp and write paths.
// Only its executable/type and bounded test lifetime come from systemd-run.
func TestWorkspaceRegistryInstalled(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("installed registry canary requires disposable Linux root")
	}
	if os.Args[len(os.Args)-1] == "workspace-registry-unit" {
		workspaceRegistryUnitChild(t, os.Args[len(os.Args)-2])
		return
	}
	nonce, err := randomID("")
	if err != nil {
		t.Fatal(err)
	}
	config := "lb-v2-nb-g1-" + string(nonce[:12])
	stage, err := os.MkdirTemp("/run", "lb-v2-nb-g1-registry-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(stage); err != nil {
			t.Error(err)
		}
	})
	b := installation{Config: config}
	properties := workerCanaryProperties(t, config)
	if err := errors.Join(os.Chown(b.statePath(), 0, 0), os.Chmod(b.statePath(), 0700)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(b.statePath()); err != nil {
			t.Error(err)
		}
	})
	self, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(stage, "canary")
	workerCanaryWrite(t, binary, self, 0555)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	args := []string{"--quiet", "--wait", "--pipe", "--collect", "--unit=laneboss-helper@" + config + ".service"}
	args = append(args, properties...)
	args = append(args, "--property=RuntimeMaxSec=60s", "--property=WorkingDirectory="+b.statePath(), binary,
		"-test.run=^TestWorkspaceRegistryInstalled$", "-test.v", "--", config, "workspace-registry-unit")
	command := exec.CommandContext(ctx, "/usr/bin/systemd-run", args...)
	command.Env = []string{}
	command.WaitDelay = 3 * time.Second
	output, err := command.CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte("--- PASS: TestWorkspaceRegistryInstalled ")) {
		t.Fatalf("shipped helper registry publication failed: %v\n%s", err, output)
	}
	if !bytes.Contains(output, []byte("shipped policy: etc_readonly=true sibling_readonly=true registry_verified=true inventory_verified=true")) {
		t.Fatal("installed registry canary lost its native policy/publication readbacks")
	}
	t.Log("shipped helper policy: readonly boundaries and registry readbacks verified")
}

func workspaceRegistryUnitChild(t *testing.T, config string) {
	t.Helper()
	if !validConfig(config) {
		t.Fatal("unit supplied an invalid configuration")
	}
	b := installation{Config: config}
	membership, err := cgroupMembership(os.Getpid())
	if err != nil || membership != "/system.slice/laneboss-helper@"+config+".service" {
		t.Fatal("registry canary did not run in its shipped helper unit", err)
	}
	probe := filepath.Join("/etc/laneboss-v2", config+"-probe")
	if err := os.Mkdir(probe, 0700); !errors.Is(err, unix.EROFS) {
		t.Fatal("shipped helper did not enforce the readonly installation namespace", err)
	}
	sibling := filepath.Join(filepath.Dir(b.statePath()), config+"-other")
	if err := os.Mkdir(sibling, 0700); !errors.Is(err, unix.EROFS) {
		t.Fatal("shipped helper write permission escaped its configuration", err)
	}
	e := cleanupEnrollment{Schema: "laneboss.workspace-native.v2", Config: config, LeaseID: "registry-unit-lease",
		Workspace: api.CleanupWorkspace{ID: "registry-unit-workspace", RootID: "registry-unit-root", RepositoryID: "registry-unit-repository", Target: api.LifeRef{LifeID: "registry-unit-life", Run: 1}, Generation: 1}}
	if err := publishWorkspaceEnrollment(e); err != nil {
		t.Fatal("installed workspace publication did not reach its protected registry", err)
	}
	want := filepath.Join(b.statePath(), "workspaces", string(e.Workspace.ID)+".json")
	if workspaceEnrollmentPath(e) != want {
		t.Fatal("runtime workspace registry is outside helper-private state")
	}
	raw, err := readProtected(want, api.MaxFrameBytes)
	if err != nil {
		t.Fatal(err)
	}
	var actual cleanupEnrollment
	if err := decodeStrict(raw, &actual); err != nil || !reflect.DeepEqual(actual, e) {
		t.Fatal("installed registry did not retain the exact enrollment bytes", err)
	}
	var record, directory unix.Stat_t
	if unix.Lstat(want, &record) != nil || record.Uid != 0 || record.Gid != 0 || record.Mode&07777 != 0444 || record.Nlink != 1 ||
		unix.Lstat(filepath.Dir(want), &directory) != nil || directory.Uid != 0 || directory.Gid != 0 || directory.Mode&07777 != 0700 {
		t.Fatal("installed registry lost its exact owner, mode or link protection")
	}
	if err := publishWorkspaceEnrollment(e); err != nil {
		t.Fatal("installed registry exact replay failed", err)
	}
	changed := e
	changed.LeaseID = "foreign-registry-lease"
	var typed *api.Error
	if err := publishWorkspaceEnrollment(changed); !errors.As(err, &typed) || typed.Code != api.CodeIdempotencyConflict {
		t.Fatal("installed registry accepted changed retry bytes", err)
	}
	root, err := os.OpenRoot(b.statePath())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	store := &fileLeaseStore{root: root}
	if records, err := store.Records(); err != nil || len(records) != 0 {
		t.Fatal("real helper inventory did not recognize its private workspace namespace", err)
	}
	if err := os.Chmod(filepath.Dir(want), 0770); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Records(); err == nil {
		t.Fatal("helper inventory accepted a writable workspace registry")
	}
	if err := os.Chmod(filepath.Dir(want), 0700); err != nil {
		t.Fatal(err)
	}
	if err := publishWorkspaceEnrollment(e); err != nil {
		t.Fatal("protected registry did not recover after restoring its exact mode", err)
	}
	t.Log("shipped policy: etc_readonly=true sibling_readonly=true registry_verified=true inventory_verified=true")
}
