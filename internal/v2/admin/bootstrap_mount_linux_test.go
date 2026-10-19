//go:build linux

package admin

import (
	"bytes"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func TestBwrapMountFacts(t *testing.T) {
	private, err := randomID("mount-facts-")
	if err != nil {
		t.Fatal(err)
	}
	source, target := "/"+string(private)+"/source", "/"+string(private)+"/target"
	binds := []bootstrapBindRequest{{target: target, readonly: true}, {target: target + "-rw"}}
	for _, sample := range []struct{ name, line, operation, errno string }{
		{"proc", "bwrap: Can't mount proc on " + target + ": Operation not permitted", "proc", "EPERM"},
		{"tmpfs", "bwrap: Can't mount tmpfs on " + target + ": Permission denied", "tmpfs", "EACCES"},
		{"bind", "bwrap: Can't bind mount " + source + " on " + target + "-rw: Invalid argument", "bind", "EINVAL"},
		{"ro-bind", "bwrap: Can't bind mount " + source + " on /newroot" + target + ": Unable to mount source on destination: Permission denied", "ro-bind", "EACCES"},
		{"remount", "bwrap: Can't remount " + target + " read-only: Read-only file system", "remount", "EROFS"},
		{"dev", "bwrap: Can't mount devpts on " + target + ": No such device", "dev", "ENODEV"},
		{"mqueue", "bwrap: Can't mount mqueue on " + target + ": No space left on device", "mqueue", "ENOSPC"},
		{"other", "bwrap: Can't mount " + source + "/proc on " + target + ": Device or resource busy", "other", "EBUSY"},
		{"unknown-errno", "bwrap: Can't mount proc on " + target + ": " + string(private), "proc", "other"},
		{"truncated-errno", "bwrap: Can't mount proc on " + target + ": Operation not permit", "proc", "other"},
		{"missing-errno", "bwrap: Can't mount proc on " + target, "proc", "other"},
		{"no-mount", "bwrap: Unknown option --" + string(private), "none", "none"},
		{"first-error", "bwrap: Unknown option --" + string(private) + "\nbwrap: Can't mount proc on /proc: Operation not permitted", "none", "none"},
		{"private-text", string(private) + ": Operation not permitted", "none", "none"},
	} {
		t.Run(sample.name, func(t *testing.T) {
			operation, errno := bwrapMountFacts([]byte(sample.line+"\n"), binds)
			if operation != sample.operation || errno != sample.errno || strings.Contains(operation+errno, string(private)) {
				t.Fatal("acceptance: mount diagnostic lost its observed closed operation or errno")
			}
		})
	}
	operation, errno := bwrapMountFacts([]byte("bwrap: Can't bind mount "+source+" on "+target+": Permission denied"),
		append(binds, bootstrapBindRequest{target: target}))
	if operation != "other" || errno != "EACCES" {
		t.Fatal("acceptance: ambiguous bind mode was reported as a known request")
	}
}

func TestBwrapMountErrnos(t *testing.T) {
	for _, sample := range []struct{ text, errno string }{
		{"Operation not permitted", "EPERM"}, {"Permission denied", "EACCES"},
		{"Read-only file system", "EROFS"}, {"Invalid argument", "EINVAL"},
		{"No such file or directory", "ENOENT"}, {"Not a directory", "ENOTDIR"},
		{"No such device", "ENODEV"}, {"Device or resource busy", "EBUSY"},
		{"Cannot allocate memory", "ENOMEM"}, {"No space left on device", "ENOSPC"},
		{"Too many levels of symbolic links", "ELOOP"}, {"Function not implemented", "ENOSYS"},
		{"Operation not supported", "EOPNOTSUPP"}, {"Input/output error", "EIO"},
		{"Bad file descriptor", "EBADF"}, {"Too many open files", "EMFILE"},
		{"Too many open files in system", "ENFILE"}, {"", "other"},
	} {
		t.Run(sample.errno, func(t *testing.T) {
			operation, errno := bwrapMountFacts([]byte("bwrap: Can't mount tmpfs on /newroot: "+sample.text), nil)
			if operation != "tmpfs" || errno != sample.errno {
				t.Fatal("acceptance: mount errno did not follow the actual C-locale error")
			}
		})
	}
}

func TestBwrapBindRequests(t *testing.T) {
	args := []string{"/usr/bin/bwrap", "--symlink", "--", "--ro-bind", "--dir", "--bind",
		"--bind", "/source", "/writable", "--ro-bind", "/source", "/immutable", "--bind-fd", "7", "/fd-write", "--ro-bind-fd", "8", "/fd-read", "--", "/vendor", "--bind", "/ignored", "/ignored"}
	want := []bootstrapBindRequest{{target: "/writable"}, {target: "/immutable", readonly: true}, {target: "/fd-write"}, {target: "/fd-read", readonly: true}}
	if got := bootstrapBindRequests(args); !reflect.DeepEqual(got, want) {
		t.Fatal("acceptance: bind mode context consumed an operand or vendor argument")
	}
	if got := bootstrapBindRequests([]string{"/usr/bin/bwrap", "--ro-bind", "/source"}); got != nil {
		t.Fatal("acceptance: incomplete bind request produced a mode observation")
	}
}

func TestBwrapMountCapture(t *testing.T) {
	private, err := randomID("mount-capture-")
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("bwrap: Can't mount proc on /" + string(private) + ": Operation not permitted\n")
	var forwarded bytes.Buffer
	observer := &bootstrapStderr{destination: &forwarded}
	for _, value := range data {
		if n, err := observer.Write([]byte{value}); err != nil || n != 1 {
			t.Fatal("mount stderr capture did not accept exact private bytes")
		}
	}
	want := "bwrap_stderr=mount_failed; bwrap_mount=proc; bwrap_errno=EPERM"
	if got := observer.diagnosticFacts(); got != want || forwarded.String() != string(data) {
		t.Fatal("acceptance: captured mount failure lost its operation, errno or private forwarding")
	}
	observer.freeze()
	later := []byte("bwrap: Can't mount tmpfs on /newroot: Permission denied\n")
	if n, err := observer.Write(later); err != nil || n != len(later) || observer.diagnosticFacts() != want || !bytes.Equal(forwarded.Bytes(), append(data, later...)) {
		t.Fatal("acceptance: post-readiness stderr replaced the captured mount diagnostic")
	}
	var absent *bootstrapStderr
	if absent.diagnosticFacts() != "bwrap_stderr=unavailable; bwrap_mount=unavailable; bwrap_errno=unavailable" {
		t.Fatal("acceptance: absent mount capture invented a failure fact")
	}
}

func TestBwrapBindCapture(t *testing.T) {
	private, err := randomID("bind-capture-")
	if err != nil {
		t.Fatal(err)
	}
	source, target := "/"+string(private)+"/source", "/"+string(private)+"/target"
	file, err := os.CreateTemp(privateTestDir(t), "capture-")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	command := exec.Command("/usr/bin/bwrap", "--ro-bind", source, target, "--", "/canary")
	observer, err := attachBootstrapStderr(command, file)
	if err != nil {
		t.Fatal("cannot attach the bind capture fixture")
	}
	defer observer.close()
	data := []byte("bwrap: Can't bind mount " + source + " on " + target + ": Unable to mount source on destination: Permission denied\n")
	if n, err := observer.Write(data); err != nil || n != len(data) {
		t.Fatal("bind capture did not forward its private input")
	}
	retained, err := os.ReadFile(file.Name())
	if err != nil || !bytes.Equal(retained, data) || observer.diagnosticFacts() != "bwrap_stderr=bind_mount_failed; bwrap_mount=ro-bind; bwrap_errno=EACCES" {
		t.Fatal("acceptance: owned bind capture lost its actual argv mode or exact private bytes")
	}
}
