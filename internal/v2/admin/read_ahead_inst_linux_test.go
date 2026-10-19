//go:build linux && laneboss_gate_integration

package admin

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func init() {
	if len(os.Args) != 3 || os.Args[1] != "admin-private-proc-canary" {
		return
	}
	if os.Geteuid() == 0 || lanePrivateProc() != nil {
		os.Exit(73)
	}
	if n, err := os.Stdout.WriteString(os.Args[2]); err != nil || n != len(os.Args[2]) {
		os.Exit(74)
	}
	os.Exit(0)
}

// This is the installed-unit deciding pair for the procfs premise: the same
// unprivileged bwrap and source pass only after the private pristine mount.
// A wrong setup failure, unavailable binary or skipped test is not evidence.
func TestInstalledPristineProc(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("installed procfs canary requires disposable root")
	}
	binding := installedGateBinding(t)
	membership, err := cgroupMembership(os.Getpid())
	if err != nil || membership != "/system.slice/laneboss-helper@"+binding.Config+".service/control" {
		t.Fatal("installed procfs canary is outside its restricted root fixture")
	}
	root, err := os.OpenRoot(binding.statePath())
	if err != nil {
		t.Fatal("cannot pin the installed procfs canary's state root")
	}
	defer root.Close()
	lock, err := root.OpenFile("lock", os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		t.Fatal("cannot pin the installed procfs canary's exclusive lock")
	}
	defer lock.Close()
	var lockStat unix.Stat_t
	if unix.Fstat(int(lock.Fd()), &lockStat) != nil || lockStat.Uid != 0 || lockStat.Mode&unix.S_IFMT != unix.S_IFREG || lockStat.Mode&07777 != 0600 || lockStat.Nlink != 1 {
		t.Fatal("installed procfs canary lock is unsafe")
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal("installed procfs canary requires exclusive helper ownership")
	}
	id, err := randomID("proc-canary-")
	if err != nil {
		t.Fatal(err)
	}
	stage := laneStagePath(binding, id)
	if err := createLaneStage(stage, binding.Lanes[0].GID); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(stage)
	executable := filepath.Join(stage, "canary")
	data, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, data, 0555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(executable, 0555); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(executable)
	file, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	mounts := []*nativeMount{{file: file, target: fixedBootstrapPath, executable: true}}
	// The landing canary executes the real distro bwrap and true, including
	// the platform loader. All standard runtime projections remain read-only.
	for _, path := range []string{"/usr", "/lib", "/lib64", "/bin"} {
		runtimeFile, err := os.Open(path)
		if path == "/lib64" && os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal("installed userns canary runtime is unavailable")
		}
		defer runtimeFile.Close()
		mounts = append(mounts, &nativeMount{file: runtimeFile, target: path, directory: true, executable: true})
	}
	args, files := nativeGateArgs(binding.Config, "prepared-gate", nil, mounts, true)
	for index, word := range args {
		if word == "--" {
			args = append(args[:index+2], "admin-private-proc-canary", string(id))
			break
		}
	}
	verified := false
	run := func() (bool, string, string, string) {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		command := unprivilegedBwrapCommand(ctx, args...)
		command.SysProcAttr.Credential.Uid, command.SysProcAttr.Credential.Gid = binding.Lanes[0].UID, binding.Lanes[0].GID
		command.ExtraFiles = files
		var stdout, stderr bytes.Buffer
		command.Stdout, command.Stderr = &stdout, &stderr
		lifetime := newNativeSpawnLifetime()
		start := func() error { return startInNetworkNamespacePinned(command, nil, lifetime) }
		if verified {
			start = func() error { return startInNetworkNamespaceVerified(command, nil, lifetime, binding.runtimePath()) }
		}
		if err := start(); err != nil {
			t.Fatal("installed procfs canary failed before bwrap exec")
		}
		err := command.Wait()
		lifetime.observedWait(command.ProcessState)
		select {
		case <-lifetime.threadDone:
		case <-time.After(3 * time.Second):
			t.Fatal("installed procfs canary creator did not observe actual bwrap exit")
		}
		observer := &bootstrapStderr{prefix: stderr.Bytes(), binds: bootstrapBindRequests(append([]string{"/usr/bin/bwrap"}, args...))}
		operation, errno := bwrapMountFacts(stderr.Bytes(), observer.binds)
		return ctx.Err() == nil && err == nil && stdout.String() == string(id), operation, errno, observer.diagnosticFacts() + "; " + nativeReadinessWait(command.ProcessState)
	}
	if passed, operation, errno, facts := run(); passed || operation != "proc" || errno != "EPERM" {
		t.Fatalf("procfs negative control did not reach the installed masked-proc mount refusal (%s)", facts)
	}
	closeProc, err := mountHelperProc(binding.runtimePath())
	if err != nil {
		t.Fatal("acceptance: pristine procfs setup failed under the installed unit")
	}
	defer func() {
		if err := closeProc(); err != nil {
			t.Error(err)
		}
	}()
	testInstalledProcInheritance(t, binding, executable)
	if t.Failed() {
		return
	}
	verified = true
	if passed, _, _, facts := run(); !passed {
		t.Fatalf("acceptance: pristine procfs did not yield a private lane process view (%s)", facts)
	}
	if err := verifyBwrap(); err != nil {
		t.Fatal("installed landing canary requires the unprivileged distro bwrap")
	}
	for index, word := range args {
		if word == "--" {
			args[index+2] = "admin-lane-userns-canary"
			break
		}
	}
	if passed, _, _, facts := run(); !passed {
		t.Fatalf("acceptance: installed lane user namespace or kernel tunable boundary failed (%s)", facts)
	}
}
