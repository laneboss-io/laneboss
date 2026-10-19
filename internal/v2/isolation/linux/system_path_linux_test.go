//go:build linux

package linux

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRuntimeSystemOwners(t *testing.T) {
	policy := testRuntimePolicy()
	for _, tc := range []struct {
		name string
		stat runtimePathStat
		want bool
	}{
		{"root_file", runtimePathStat{uid: 0, gid: 0, mode: 0644}, true},
		{"system_file", runtimePathStat{uid: 991, gid: 991, mode: 0644}, true},
		{"login_owner", runtimePathStat{uid: 1000, gid: 1000, mode: 0644}, false},
		{"other_login_owner", runtimePathStat{uid: 1001, gid: 1001, mode: 0644}, false},
		{"uid_limit", runtimePathStat{uid: 999, gid: 0, mode: 0644}, false},
		{"lane_pool_owner", runtimePathStat{uid: 550, gid: 0, mode: 0644}, false},
		{"lane_pool_group", runtimePathStat{uid: 0, gid: 550, mode: 0644}, false},
		{"group_write", runtimePathStat{uid: 0, gid: 991, mode: 0664}, false},
		{"login_group_write", runtimePathStat{uid: 0, gid: 1000, mode: os.ModeDir | 0770}, false},
		{"world_write", runtimePathStat{uid: 0, gid: 0, mode: 0666}, false},
		{"root_sticky_system_group", runtimePathStat{uid: 0, gid: 991, mode: os.ModeDir | os.ModeSticky | 0777}, true},
		{"root_sticky_login_group", runtimePathStat{uid: 0, gid: 1000, mode: os.ModeDir | os.ModeSticky | 0770}, false},
		{"system_sticky", runtimePathStat{uid: 991, gid: 991, mode: os.ModeDir | os.ModeSticky | 0770}, false},
		{"sticky_file", runtimePathStat{uid: 0, gid: 0, mode: os.ModeSticky | 0666}, false},
		{"symlink_after_resolve", runtimePathStat{uid: 0, gid: 0, mode: os.ModeSymlink | 0777}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := policy.check(tc.stat) == nil; got != tc.want {
				t.Fatalf("runtime ownership verdict %t, want %t", got, tc.want)
			}
		})
	}
	policy.laneUID = 991
	if policy.check(runtimePathStat{uid: 991, gid: 991, mode: 0644}) == nil {
		t.Fatal("lane UID admitted merely because it is in the system range")
	}
	policy.laneUID = 1000
	policy.limits.uidMax, policy.limits.gidMax = 2000, 2000
	if policy.check(runtimePathStat{uid: 1001, gid: 0, mode: 0644}) == nil ||
		policy.check(runtimePathStat{uid: 0, gid: 1001, mode: os.ModeDir | os.ModeSticky | 0770}) == nil {
		t.Fatal("overlapping system/login ranges admitted a login identity")
	}
}

func TestRuntimeOwnerChain(t *testing.T) {
	policy := testRuntimePolicy()
	target := "/run/systemd/resolve/stub-resolv.conf"
	for _, tc := range []struct {
		name   string
		owner  uint32
		badUID bool
		badGID bool
		want   bool
	}{
		{"root_chain", 0, false, false, true},
		{"resolver_chain", 991, false, false, true},
		{"login_parent", 991, true, false, false},
		{"login_group_parent", 991, false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var visited []string
			stat := func(path string) (runtimePathStat, error) {
				visited = append(visited, path)
				info := runtimePathStat{uid: 0, gid: 0, mode: os.ModeDir | 0755}
				if path == target || path == "/run/systemd/resolve" {
					info.uid, info.gid = tc.owner, tc.owner
				}
				if path == target {
					info.mode = 0644
				}
				if path == "/run/systemd" && tc.badUID {
					info.uid = 1000
				}
				if path == "/run/systemd" && tc.badGID {
					info.gid, info.mode = 1000, os.ModeDir|0775
				}
				return info, nil
			}
			resolved, err := checkSystemPath("/etc/resolv.conf", policy,
				func(path string) (string, error) {
					if path != "/etc/resolv.conf" {
						return "", fs.ErrNotExist
					}
					return target, nil
				}, stat)
			if (err == nil) != tc.want {
				t.Fatalf("resolved ownership chain verdict mismatch: %v", err)
			}
			if tc.want && (resolved != target || !reflect.DeepEqual(visited,
				[]string{target, "/run/systemd/resolve", "/run/systemd", "/run", "/"})) {
				t.Fatal("did not check the entire resolved chain")
			}
		})
	}
}

func TestRuntimeSymlinkUserTarget(t *testing.T) {
	root := t.TempDir()
	userDir := filepath.Join(root, "user")
	if err := os.Mkdir(userDir, 0755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(userDir, "resolver")
	if err := os.WriteFile(target, []byte("canary"), 0644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "resolver-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	policy := testRuntimePolicy()
	stat := func(path string) (runtimePathStat, error) {
		info := runtimePathStat{uid: 0, gid: 0, mode: os.ModeDir | 0755}
		if path == target {
			info.mode = 0644
		}
		if path == userDir {
			info.uid = 1000
		}
		return info, nil
	}
	if _, err := checkSystemPath(link, policy, filepath.EvalSymlinks, stat); err == nil || !strings.Contains(err.Error(), userDir) {
		t.Fatal("symlink into a user-owned directory was not refused at its parent")
	}
	// Control: the same real symlink and file become admissible only when
	// synthetic ownership of the target directory changes to a system UID.
	systemStat := func(path string) (runtimePathStat, error) {
		info, err := stat(path)
		if path == userDir {
			info.uid = 991
		}
		return info, err
	}
	if resolved, err := checkSystemPath(link, policy, filepath.EvalSymlinks, systemStat); err != nil || resolved != target {
		t.Fatalf("system-owned symlink control failed: %v", err)
	}
	_, err := checkSystemPath(link, policy, filepath.EvalSymlinks,
		func(string) (runtimePathStat, error) { return runtimePathStat{}, fs.ErrPermission })
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatal("failed ownership inspection did not refuse the path")
	}
}

func TestSystemIDLimits(t *testing.T) {
	defaults, err := parseSystemIDLimits(strings.NewReader("# comment\nOTHER_SETTING ignored\n"))
	if err != nil || defaults != (systemIDLimits{uidMax: 999, gidMax: 999, uidMin: 1000, gidMin: 1000}) {
		t.Fatal("missing settings did not use conservative defaults")
	}
	input := strings.Join([]string{"SYS_UID_MAX 500 # limit", "SYS_GID_MAX 600", "UID_MIN 700", "GID_MIN 800", ""}, "\n")
	limits, err := parseSystemIDLimits(strings.NewReader(input))
	if err != nil || limits != (systemIDLimits{uidMax: 500, gidMax: 600, uidMin: 700, gidMin: 800}) {
		t.Fatal("host account ranges were ignored")
	}
	for _, input := range []string{"SYS_UID_MAX nope", "SYS_UID_MAX -1", "SYS_UID_MAX 4294967296",
		"SYS_GID_MAX 0", "UID_MIN", "GID_MIN 1000 extra", "SYS_UID_MAX 400\nSYS_UID_MAX 500"} {
		if _, err := parseSystemIDLimits(strings.NewReader(input)); err == nil {
			t.Error("malformed account ranges were accepted")
		}
	}
}

func testRuntimePolicy() runtimePathPolicy {
	return runtimePathPolicy{limits: systemIDLimits{uidMax: 999, gidMax: 999, uidMin: 1000, gidMin: 1000},
		laneUID: 1000, laneGID: 1000, uidPool: []IDRange{{First: 500, Last: 600}},
		gidPool: []IDRange{{First: 500, Last: 600}}}
}

func TestMissingPoolInventory(t *testing.T) {
	policy := testRuntimePolicy()
	policy.uidPool, policy.gidPool = nil, nil
	if policy.systemUID(991) || policy.systemGID(991) || !policy.systemUID(0) || !policy.systemGID(0) {
		t.Fatal("missing lane inventory widened ownership")
	}
	for _, pool := range [][]IDRange{{{First: 0, Last: 500}}, {{First: 600, Last: 500}}} {
		if outsidePool(991, pool) {
			t.Fatal("invalid lane pool was trusted")
		}
	}
}
