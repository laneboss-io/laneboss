//go:build linux

package admin

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

type restrictionObservation struct {
	Stage string `json:"stage"`
	Errno int    `json:"errno"`
}

func restrictionErrno(err error) int {
	if err == nil {
		return 0
	}
	var number unix.Errno
	if errors.As(err, &number) {
		return int(number)
	}
	return -1
}

func nativeRestrictionFixture(kind string) {
	emit := func(stage string, err error) {
		if err := json.NewEncoder(os.Stdout).Encode(restrictionObservation{Stage: stage, Errno: restrictionErrno(err)}); err != nil {
			os.Exit(30)
		}
	}
	payload, err := readBootstrapInput()
	if err != nil {
		emit("input", err)
		os.Exit(31)
	}
	runtime.LockOSThread()
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		emit("no_new_privs", err)
		os.Exit(31)
	}
	switch kind {
	case "landlock":
		if len(payload.Paths) != 1 {
			emit("input", unix.EINVAL)
			os.Exit(31)
		}
		path := payload.Paths[0].Path
		if err := os.WriteFile(path, []byte(payload.Token), 0600); err != nil {
			emit("writable_control", err)
			os.Exit(31)
		}
		if err := bootstrapLandlock(payload.Paths); err != nil {
			emit("landlock_setup", err)
			os.Exit(31)
		}
		emit("observed", os.WriteFile(path, []byte(payload.Token+"-changed"), 0600))
	case "seccomp":
		if err := unix.Unshare(0); err != nil {
			emit("unshare_control", err)
			os.Exit(31)
		}
		if err := bootstrapSeccomp(); err != nil {
			emit("seccomp_setup", err)
			os.Exit(31)
		}
		emit("observed", unix.Unshare(0))
	default:
		emit("input", unix.EINVAL)
		os.Exit(31)
	}
	os.Exit(0)
}

func restrictionChild(t *testing.T, kind string, paths []bootstrapPath) restrictionObservation {
	t.Helper()
	token, err := randomID("native-restriction-")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sealedBootstrap(gatePayload{Token: string(token), Argv: []string{}, Environment: []string{}, Paths: paths})
	if err != nil {
		t.Fatal(err)
	}
	defer sealed.Close()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "admin-native-restriction-fixture", kind)
	command.Env, command.ExtraFiles = []string{}, []*os.File{sealed}
	bytes, err := command.Output()
	var observed restrictionObservation
	if decodeStrict(bytes, &observed) != nil || err != nil || observed.Stage != "observed" {
		t.Fatalf("native restriction setup did not reach its kernel observation: stage=%s", observed.Stage)
	}
	return observed
}

func TestNativeBootstrapLandlock(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "writable-control")
	observed := restrictionChild(t, "landlock", []bootstrapPath{{Path: path}})
	if observed.Errno != int(unix.EACCES) {
		t.Fatal("acceptance: actual bootstrap Landlock write denial was absent")
	}
}

func TestNativeBootstrapSeccomp(t *testing.T) {
	observed := restrictionChild(t, "seccomp", []bootstrapPath{})
	if observed.Errno != int(unix.EPERM) {
		t.Fatal("acceptance: actual bootstrap seccomp syscall denial was absent")
	}
}

func TestNativeGateMembership(t *testing.T) {
	actual, err := cgroupMembership(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	allowed := captureAllowed(t)
	if err := verifyGateMembership(os.Getpid(), actual); err != nil || len(allowed()) != 0 {
		t.Fatal(err, allowed())
	}
	// Owner R181-R192: cgroup pinning is allowed and logged instead of refused.
	if err := verifyGateMembership(os.Getpid(), actual+"-foreign"); err != nil || !slices.Equal(allowed(), []string{"ready_cgroup"}) {
		t.Fatal("foreign native containment was not allowed and logged", err, allowed())
	}
}

func TestNativeGateNamespaces(t *testing.T) {
	// Owner R181-R192: a shared namespace is allowed and logged, one line per namespace, instead of refused.
	allowed := captureAllowed(t)
	err := verifyPrivateNamespaces(os.Getpid())
	want := []string{"ready_private_namespace_mnt", "ready_private_namespace_user", "ready_private_namespace_pid",
		"ready_private_namespace_ipc", "ready_private_namespace_uts", "ready_private_namespace_net"}
	if err != nil || !slices.Equal(allowed(), want) {
		t.Fatal("shared native namespace was not allowed and logged", err, allowed())
	}
}
