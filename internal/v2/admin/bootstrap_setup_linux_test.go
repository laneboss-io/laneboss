//go:build linux

package admin

import (
	"strings"
	"testing"
)

func TestSetupCategories(t *testing.T) {
	private, err := randomID("setup-")
	if err != nil {
		t.Fatal(err)
	}
	for _, cell := range []struct{ name, prefix, want string }{
		{"namespace", "bwrap: Creating new namespace failed: No space left on device ", "namespace_setup_failed"},
		{"userns-policy", "bwrap: --disable-userns requires ", "userns_policy_failed"},
		{"source", "bwrap: Can't find source path /", "mount_source_unavailable"},
		{"bind", "bwrap: Can't bind mount /", "bind_mount_failed"},
		{"destination", "bwrap: Can't mkdir /", "destination_create_failed"},
		{"propagation", "bwrap: Failed to make / slave: ", "mount_propagation_failed"},
		{"root", "bwrap: pivot_root: ", "root_switch_failed"},
		{"cwd", "bwrap: Can't chdir to /", "cwd_failed"},
		{"capability", "bwrap: capset failed: ", "capability_setup_failed"},
		{"parent-death", "bwrap: prctl(PR_SET_PDEATHSIG): ", "parent_death_setup_failed"},
		{"nnp", "bwrap: prctl(PR_SET_NO_NEW_PRIVS): ", "no_new_privileges_failed"},
		{"sync", "bwrap: Failed to sync with child ", "child_sync_failed"},
		{"seccomp", "bwrap: Can't load seccomp ", "seccomp_setup_failed"},
		{"fork", "bwrap: fork: ", "process_create_failed"},
		{"allocation", "bwrap: malloc: ", "allocation_failed"},
		{"runtime-memory", "fatal error: runtime: out of memory ", "runtime_memory_failed"},
		{"runtime-thread", "runtime: failed to create new OS thread ", "runtime_thread_failed"},
	} {
		t.Run(cell.name, func(t *testing.T) {
			data := []byte(cell.prefix + string(private) + "\n")
			actual := classifyBwrapStderr(data)
			if actual != cell.want || strings.Contains(actual, string(private)) {
				t.Fatal("acceptance: setup stderr lost its closed operation category")
			}
		})
	}
}
