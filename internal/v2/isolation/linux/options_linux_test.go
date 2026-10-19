//go:build linux

package linux

import (
	"context"
	"encoding/base64"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestBwrapAdvertisedOptions(t *testing.T) {
	info, err := os.Stat(bwrapPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		t.Fatal("actual bwrap must be a regular unprivileged executable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	command := func(option string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, bwrapPath, option)
		cmd.Env = []string{}
		uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
		if uid == 0 {
			uid, gid = 65534, 65534
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
			Uid: uid, Gid: gid, Groups: []uint32{}, NoSetGroups: os.Geteuid() != 0}}
		return cmd
	}
	version, err := command("--version").Output()
	if err != nil || !regexp.MustCompile(`^bubblewrap [0-9]+\.[0-9]+\.[0-9]+\s*$`).Match(version) {
		t.Fatal("actual unprivileged bwrap version unavailable")
	}
	help, err := command("--help").Output()
	if err != nil || len(help) == 0 {
		t.Fatal("actual unprivileged bwrap help unavailable")
	}
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
	plan := launchPlan{}
	plan.helper = &pinnedMount{target: helperPath, readOnly: true}
	plan.runtime = []*pinnedMount{{target: "/usr", readOnly: true}}
	plan.data = []*pinnedMount{{target: "/work/main"}, {target: "/data/input", readOnly: true}}
	plan.links, plan.cwd = [][2]string{{"usr/bin", "/bin"}}, "/work/main"
	args, files := buildArgs(plan)
	if len(files) != 4 {
		t.Fatal("isolation option fixture lost descriptor positions")
	}
	for index := 0; index < len(args); {
		name := args[index]
		if name == "--" {
			if index+1 >= len(args) || args[index+1] != helperPath {
				t.Fatal("isolation bwrap command boundary changed")
			}
			break
		}
		arity, found := accepted[name]
		if !found || index+arity >= len(args) {
			t.Fatal("acceptance: isolation builder passes an unadvertised bwrap option")
		}
		switch name {
		case "--cap-add", "--uid", "--gid", "--userns", "--userns2", "--pidns", "--unshare-user-try":
			t.Fatal("acceptance: isolation builder added a privileged or optional namespace form")
		}
		index += 1 + arity
	}
}
