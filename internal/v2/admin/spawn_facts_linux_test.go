//go:build linux

package admin

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestNativeCapabilityFacts(t *testing.T) {
	for _, entry := range []struct {
		bits uint32
		want string
	}{
		{0, "helper CAP_SETUID=absent, CAP_SETGID=absent, CAP_SYS_ADMIN=absent"},
		{1 << unix.CAP_SETUID, "helper CAP_SETUID=present, CAP_SETGID=absent, CAP_SYS_ADMIN=absent"},
		{1 << unix.CAP_SETGID, "helper CAP_SETUID=absent, CAP_SETGID=present, CAP_SYS_ADMIN=absent"},
		{1 << unix.CAP_SYS_ADMIN, "helper CAP_SETUID=absent, CAP_SETGID=absent, CAP_SYS_ADMIN=present"},
		{^uint32(0), "helper CAP_SETUID=present, CAP_SETGID=present, CAP_SYS_ADMIN=present"},
	} {
		calls := 0
		got := nativeCapabilityFacts(func(header *unix.CapUserHeader, data *unix.CapUserData) error {
			calls++
			if header.Version != unix.LINUX_CAPABILITY_VERSION_3 || header.Pid != 0 {
				t.Fatal("capability observation did not select the actual calling thread")
			}
			data.Effective, data.Permitted, data.Inheritable = entry.bits, ^uint32(0), ^uint32(0)
			return nil
		})
		if calls != 1 || got != entry.want {
			t.Fatal("acceptance: capability verdict ignored actual effective bits")
		}
	}
	private, err := randomID("private-capability-")
	if err != nil {
		t.Fatal(err)
	}
	got := nativeCapabilityFacts(func(*unix.CapUserHeader, *unix.CapUserData) error {
		return fmt.Errorf("%s: %w", private, unix.EPERM)
	})
	if got != "helper capabilities=unavailable(EPERM)" || strings.Contains(got, string(private)) {
		t.Fatal("acceptance: unavailable capability observation was lost or disclosed private text")
	}
}

func TestNativeFactValues(t *testing.T) {
	private, err := randomID("private-observation-")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range []struct {
		value  string
		domain bool
		want   string
	}{
		{"domain", true, "domain"}, {"threaded", true, "threaded"}, {"domain threaded", true, "domain threaded"},
		{"domain invalid", true, "domain invalid"}, {string(private), true, "unrecognized"},
		{"", false, "empty"}, {string(private), false, "nonempty"},
	} {
		if got := nativeCgroupValue(entry.value, nil, entry.domain); got != entry.want {
			t.Fatal("acceptance: cgroup observation leaked values or lost the observed state")
		}
	}
	if nativeCgroupValue("domain", unix.EACCES, true) != "unavailable(EACCES)" {
		t.Fatal("acceptance: failed cgroup read became a known domain")
	}
	for _, entry := range []struct {
		value   int
		seccomp bool
		want    string
	}{
		{0, false, "off"}, {1, false, "on"}, {2, false, "unrecognized"},
		{0, true, "none"}, {1, true, "strict"}, {2, true, "filter"}, {3, true, "unrecognized"},
	} {
		if nativeThreadMode(entry.value, nil, entry.seccomp) != entry.want || nativeThreadMode(entry.value, unix.EPERM, entry.seccomp) != "unavailable(EPERM)" {
			t.Fatal("acceptance: thread policy observation was lost or overstated")
		}
	}
}

func TestNativeCgroupFacts(t *testing.T) {
	if nativeCgroupFacts(nil) != "cgroup=not-requested" || nativeCgroupFacts(&syscall.SysProcAttr{}) != "cgroup=not-requested" {
		t.Fatal("unrequested cgroup diagnostic invented a target")
	}
	if got := nativeCgroupFacts(nativeGateAttributes(0, 0, missingNativeCgroupFD(t))); got != "cgroup=unavailable(EBADF)" {
		t.Fatal("acceptance: absent cgroup descriptor became a valid observation")
	}
	root := privateTestDir(t)
	for name, content := range map[string]string{"cgroup.type": "domain\n", "cgroup.subtree_control": "", "cgroup.procs": ""} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	directory, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if nativeCgroupFacts(nativeGateAttributes(0, 0, int(directory.Fd()))) != "cgroup=not-cgroup-v2" {
		t.Fatal("acceptance: ordinary directory impersonated kernel cgroup observations")
	}
	file, err := os.Open(filepath.Join(root, "cgroup.type"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if nativeCgroupFacts(nativeGateAttributes(0, 0, int(file.Fd()))) != "cgroup=not-directory" {
		t.Fatal("acceptance: regular file became a cgroup directory observation")
	}
}

func TestNativeCgroupReads(t *testing.T) {
	root := privateTestDir(t)
	private, err := randomID("private-control-")
	if err != nil {
		t.Fatal(err)
	}
	content := []byte(string(private) + "\n")
	path := filepath.Join(root, "cgroup.procs")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	directory, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	fd := int(directory.Fd())
	if value, err := readNativeCgroupControl(fd, "cgroup.procs"); err != nil || value != string(private) {
		t.Fatal("actual control reader lost the supplied exact bytes")
	}
	if nativeCgroupWriteOpen(fd) != "openable" {
		t.Fatal("actual control open observation did not reach its real file")
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != string(content) {
		t.Fatal("acceptance: diagnostic changed its observed control file")
	}
	if err := os.Symlink("cgroup.procs", filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	if _, err := readNativeCgroupControl(fd, "linked"); !errors.Is(err, unix.ELOOP) {
		t.Fatal("acceptance: diagnostic control reader followed a symlink")
	}
	if err := os.WriteFile(filepath.Join(root, "oversized"), []byte(strings.Repeat("x", 4097)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readNativeCgroupControl(fd, "oversized"); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatal("acceptance: diagnostic control reader lost its byte bound")
	}
	if _, err := unix.FcntlInt(directory.Fd(), unix.F_GETFD, 0); err != nil {
		t.Fatal("diagnostic closed its caller's pinned cgroup descriptor")
	}
}

func TestNativeThreadFacts(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	data, err := os.ReadFile("/proc/thread-self/status")
	if err != nil {
		t.Fatal("native thread fact control is unavailable")
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		name, value, found := strings.Cut(line, ":")
		if found && (name == "CapEff" || name == "NoNewPrivs" || name == "Seccomp") {
			fields[name] = strings.TrimSpace(value)
		}
	}
	bits, capErr := strconv.ParseUint(fields["CapEff"], 16, 64)
	nnp, nnpErr := strconv.Atoi(fields["NoNewPrivs"])
	seccomp, seccompErr := strconv.Atoi(fields["Seccomp"])
	if capErr != nil || nnpErr != nil || seccompErr != nil {
		t.Fatal("native thread control lacks complete policy fields")
	}
	want := "helper CAP_SETUID=absent, CAP_SETGID=absent, CAP_SYS_ADMIN=absent"
	for _, name := range []struct {
		name string
		bit  uint
	}{{"CAP_SETUID", unix.CAP_SETUID}, {"CAP_SETGID", unix.CAP_SETGID}, {"CAP_SYS_ADMIN", unix.CAP_SYS_ADMIN}} {
		if bits&(uint64(1)<<name.bit) != 0 {
			want = strings.Replace(want, name.name+"=absent", name.name+"=present", 1)
		}
	}
	if nativeCapabilityFacts(unix.Capget) != want || nativeThreadFacts() != "helper nnp="+nativeThreadMode(nnp, nil, false)+", seccomp="+nativeThreadMode(seccomp, nil, true) {
		t.Fatal("acceptance: native facts disagree with the actual locked thread")
	}
}
