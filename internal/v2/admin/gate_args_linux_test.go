//go:build linux

package admin

import (
	"context"
	"encoding/base64"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func unprivilegedBwrapCommand(ctx context.Context, args ...string) *exec.Cmd {
	command := exec.CommandContext(ctx, "/usr/bin/bwrap", args...)
	command.Env = []string{}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	if uid == 0 {
		uid, gid = 65534, 65534
	}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
		Uid: uid, Gid: gid, Groups: []uint32{}, NoSetGroups: os.Geteuid() != 0}}
	return command
}

func TestNativeBwrapOptions(t *testing.T) {
	if err := verifyBwrap(); err != nil {
		t.Fatal("actual unprivileged bwrap prerequisite unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	version, err := unprivilegedBwrapCommand(ctx, "--version").Output()
	if err != nil || !regexp.MustCompile(`^bubblewrap [0-9]+\.[0-9]+\.[0-9]+\s*$`).Match(version) {
		t.Fatal("actual unprivileged bwrap version unavailable")
	}
	help, err := unprivilegedBwrapCommand(ctx, "--help").Output()
	if err != nil || len(help) == 0 {
		t.Fatal("actual unprivileged bwrap help unavailable")
	}
	// Retain exact public tool output in the test transcript, without runtime
	// arguments, settings, environment values or private identifiers.
	t.Logf("bwrap-version-base64=%s", base64.StdEncoding.EncodeToString(version))
	t.Logf("bwrap-help-base64=%s", base64.StdEncoding.EncodeToString(help))
	option := regexp.MustCompile(`^\s*(--[a-z][a-z0-9-]*)(?: +([A-Z][A-Z0-9_-]*(?: [A-Z][A-Z0-9_-]*)*))? {2,}`)
	accepted := map[string]int{}
	for _, line := range strings.Split(string(help), "\n") {
		if fields := option.FindStringSubmatch(line); fields != nil {
			accepted[fields[1]] = len(strings.Fields(fields[2]))
		}
	}
	if len(accepted) < 20 {
		t.Fatal("actual bwrap help did not yield an independent option grammar")
	}
	for _, unshareNetwork := range []bool{false, true} {
		controls := []*os.File{nil, nil, nil, nil}
		mounts := []*nativeMount{
			{file: new(os.File), target: fixedBootstrapPath, executable: true},
			{file: new(os.File), target: "/work/main", writable: true},
			{file: new(os.File), target: "/runtime/binding.json", sealed: true},
			{file: new(os.File), target: "/runtime/endpoint.sock", socket: true},
		}
		args, files := nativeGateArgs("options-fixture", "prepared-gate", controls, mounts, unshareNetwork)
		if len(files) != len(controls)+len(mounts) {
			t.Fatal("native option fixture lost descriptor positions")
		}
		seen := map[string]bool{}
		boundedBootstrap := false
		var projections [][]string
		for index := 0; index < len(args); {
			name := args[index]
			if name == "--" {
				if index+1 >= len(args) || args[index+1] != fixedBootstrapPath {
					t.Fatal("native bwrap command boundary changed")
				}
				break
			}
			arity, found := accepted[name]
			if !found || index+arity >= len(args) {
				t.Fatal("acceptance: native gate passes an unadvertised bwrap option")
			}
			switch name {
			case "--setenv":
				if args[index+1] == "GOMAXPROCS" && args[index+2] == "1" {
					boundedBootstrap = true
				}
			case "--ro-bind-fd", "--bind-fd", "--ro-bind", "--bind", "--symlink":
				projections = append(projections, args[index:index+3])
			case "--disable-userns", "--assert-userns-disabled":
				t.Fatal("acceptance: native gate restored a sysctl-based user namespace option")
			case "--cap-add", "--uid", "--gid", "--userns", "--userns2", "--pidns", "--unshare-user-try":
				t.Fatal("acceptance: native gate added a privileged or optional namespace form")
			}
			seen[name] = true
			index += 1 + arity
		}
		if !seen["--unshare-user"] || !seen["--proc"] || seen["--unshare-net"] != unshareNetwork {
			t.Fatal("native bwrap namespace ordering/prerequisite changed")
		}
		if !boundedBootstrap {
			t.Fatal("fixed bootstrap runtime has no explicit thread-concurrency bound")
		}
		if len(projections) != len(mounts) || !slices.Equal(files[:len(controls)], controls) {
			t.Fatal("acceptance: native bwrap lost an inherited control or mount")
		}
		for index, mount := range mounts {
			flag, source := "--ro-bind-fd", strconv.Itoa(3+len(controls)+index)
			if mount.writable {
				flag = "--bind-fd"
			}
			if mount.sealed || mount.socket {
				flag, source = "--symlink", "/proc/self/fd/"+source
			}
			if !slices.Equal(projections[index], []string{flag, source, mount.target}) || files[len(controls)+index] != mount.file {
				t.Fatal("acceptance: native bwrap changed a mount descriptor, target or access mode")
			}
		}
	}
}
