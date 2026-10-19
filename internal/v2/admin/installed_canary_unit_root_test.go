//go:build linux && laneboss_root_canary && laneboss_gate_integration

package admin

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const installedCanaryPattern = `^(TestInstalled.*|TestNativeBwrapDescriptorInheritance|TestAgentOwnerNativeCanary)$`

// The installed helper owns the state flock during ordinary service operation.
// The canary unit uses the same shipped unit properties, creates the same
// delegated control leaf through setupCgroups, and then lets the tests take
// the canonical lock themselves. A marker pair prevents nested agent units
// from repeating this maintenance setup for their unrelated configurations.
func init() {
	if len(os.Args) < 4 || os.Args[len(os.Args)-1] != "agent-open-root" || os.Args[len(os.Args)-3] != "installed-canary-root" {
		return
	}
	config := os.Args[len(os.Args)-2]
	binding, err := loadInstallation(config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "installed canary could not load its protected binding")
		os.Exit(201)
	}
	membership, err := cgroupMembership(os.Getpid())
	expected := "/system.slice/laneboss-helper@" + config + ".service"
	if err != nil || membership != expected {
		fmt.Fprintln(os.Stderr, "installed canary did not start in the fixed helper unit")
		os.Exit(202)
	}
	if err := setupCgroups(binding); err != nil {
		fmt.Fprintln(os.Stderr, "installed canary could not create its helper control cgroup")
		os.Exit(203)
	}
	membership, err = cgroupMembership(os.Getpid())
	if err != nil || membership != expected+"/control" {
		fmt.Fprintln(os.Stderr, "installed canary did not join its helper control cgroup")
		os.Exit(204)
	}
}

func TestCanaryLauncher(t *testing.T) {
	t.Helper()
	if len(os.Args) < 5 || os.Args[len(os.Args)-1] != "installed-canary-launch" {
		t.Fatal("installed canary launcher marker is missing")
	}
	config, pattern, catalogPath := os.Args[len(os.Args)-4], os.Args[len(os.Args)-3], os.Args[len(os.Args)-2]
	if !validConfig(config) || pattern != installedCanaryPattern {
		t.Fatal("installed canary launcher arguments are not the retained selection")
	}
	if _, err := loadInstallation(config); err != nil {
		t.Fatalf("installed canary launcher could not verify its protected binding: %v", err)
	}
	fixture := loadFixtureAccounts(t, config, catalogPath)
	t.Logf("installed fixture accounts ready: run=%s group=%s users=%d", fixture.Run, fixture.Group.Name, len(fixture.Users))
	self, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp("/run", "lb-v2-installed-canary-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	binary := filepath.Join(directory, "canary")
	workerCanaryWrite(t, binary, self, 0555)
	properties := workerCanaryProperties(t, config)
	args := []string{"--quiet", "--wait", "--pipe", "--collect", "--unit=laneboss-helper@" + config + ".service"}
	args = append(args, properties...)
	args = append(args, "--property=RuntimeMaxSec=120s", "--property=WorkingDirectory="+directory,
		binary, "-test.run="+pattern, "-test.v", "--", "installed-canary-root", config, "agent-open-root")
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/bin/systemd-run", args...)
	command.Env = []string{}
	command.WaitDelay = 3 * time.Second
	output, err := command.CombinedOutput()
	if _, writeErr := os.Stdout.Write(output); writeErr != nil {
		t.Fatal(writeErr)
	}
	if err != nil || !bytes.Contains(output, []byte("--- PASS: TestInstalledNativeClosedGate ")) {
		t.Fatalf("installed canary unit failed: %v\n%s", err, output)
	}
}

func loadFixtureAccounts(t *testing.T, config, path string) fixtureAccountCatalog {
	t.Helper()
	raw, err := readProtected(path, 1<<20)
	if err != nil {
		t.Fatalf("installed fixture catalog is unreadable: %v", err)
	}
	var catalog bootCatalog
	if err := decodeStrict(raw, &catalog); err != nil || catalog.Config != config || catalog.FixtureAccounts == nil {
		t.Fatal("installed fixture catalog is missing or bound to another configuration")
	}
	fixture := *catalog.FixtureAccounts
	if len(fixture.Run) != 8 || fixture.Group.Name != "lbrpc"+fixture.Run || len(fixture.Users) != 3 {
		t.Fatal("installed fixture account contract differs")
	}
	for index, prefix := range []string{"lbsvc", "lbop", "lblane"} {
		if fixture.Users[index].Name != prefix+fixture.Run || fixture.Users[index].UID == 0 || fixture.Users[index].GID == 0 {
			t.Fatal("installed fixture account identity differs")
		}
		entry, lookupErr := user.Lookup(fixture.Users[index].Name)
		if lookupErr != nil {
			t.Fatal("installed fixture account was not handed to the canary")
		}
		uid, uidErr := strconv.ParseUint(entry.Uid, 10, 32)
		gid, gidErr := strconv.ParseUint(entry.Gid, 10, 32)
		if uidErr != nil || gidErr != nil || uint32(uid) != fixture.Users[index].UID || uint32(gid) != fixture.Users[index].GID {
			t.Fatal("installed fixture account was not handed to the canary")
		}
	}
	if fixture.Group.GID == 0 || strings.TrimSpace(fixture.Group.Name) != fixture.Group.Name {
		t.Fatal("installed fixture RPC group is invalid")
	}
	group, err := user.LookupGroup(fixture.Group.Name)
	if err != nil {
		t.Fatal("installed fixture RPC group is unavailable")
	}
	gid, err := strconv.ParseUint(group.Gid, 10, 32)
	if err != nil || uint32(gid) != fixture.Group.GID {
		t.Fatal("installed fixture RPC group identity differs")
	}
	return fixture
}
