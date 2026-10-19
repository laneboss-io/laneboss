//go:build linux

package linux

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type mountAdmissionResult struct {
	Original, Active                            uint64
	Stack                                       []uint64
	BaselineAllowed, AliasAllowed, StaleAllowed bool
	MismatchAllowed                             bool
	ActualSHA256                                string
}

func runMountAdmission(input canaryInput) (resultErr error) {
	target := filepath.Join(input.Work, "mount")
	if err := os.Mkdir(target, 0700); err != nil {
		return err
	}
	if err := unix.Mount("tmpfs", target, "tmpfs", unix.MS_NODEV|unix.MS_NOSUID, "size=1m"); err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, unix.Unmount(target, 0)) }()
	before, err := pinPath(target, "/work/main", true)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, before.file.Close()) }()
	result := mountAdmissionResult{Original: before.identity.Mount, BaselineAllowed: checkPinnedMounts(before) == nil}
	points, err := mountPoints()
	if err != nil {
		return err
	}
	other, err := pinPath(input.Work, "/data/other", true)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, other.file.Close()) }()
	if other.identity.Mount == before.identity.Mount {
		return errors.New("the actual separate-mount control was not established")
	}
	result.MismatchAllowed = checkMounts(target, points, other.identity.Mount) == nil
	private := filepath.Join(target, "private")
	if err := os.Mkdir(private, 0700); err != nil {
		return err
	}
	seed, err := os.ReadFile(filepath.Join(input.Work, "outside/record"))
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(private, "record"), seed, 0600); err != nil {
		return err
	}
	if err := unix.Mount(private, target, "", unix.MS_BIND, ""); err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, unix.Unmount(target, 0)) }()
	active, err := pinPath(target, "/data/runtime", true)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, active.file.Close()) }()
	result.Active = active.identity.Mount
	data, err := os.ReadFile(filepath.Join(target, "record"))
	if err != nil {
		return err
	}
	result.ActualSHA256 = bytesDigest(data)
	points, err = mountPoints()
	if err != nil {
		return err
	}
	for _, point := range points {
		if point.target == target {
			result.Stack = append(result.Stack, point.id)
		}
	}
	result.AliasAllowed = checkPinnedMounts(active) == nil
	result.StaleAllowed = checkMounts(target, points, before.identity.Mount) == nil
	return json.NewEncoder(os.Stdout).Encode(result)
}

func TestKernelMountAdmission(t *testing.T) {
	directory, spec, seed := kernelFixture(t)
	input := canaryInput{Mode: "mount-admission", Work: directory}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// A fixed diagnostic in a new user/mount namespace, never an agent. The
	// host caller remains non-root. UID/GID zero and CAP_SYS_ADMIN exist only
	// inside this new user namespace so the fixture can create real mounts.
	args := []string{"--die-with-parent", "--unshare-user", "--unshare-pid", "--uid", "0", "--gid", "0", "--cap-add", "CAP_SYS_ADMIN",
		"--ro-bind", "/", "/", "--bind", directory, directory, "--"}
	args = append(args, canaryArgs(t, spec.Helper, input)...)
	command := exec.CommandContext(ctx, bwrapPath, args...)
	command.Env = []string{}
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	saveBytes(t, directory, "mount-admission.stdout", stdout.Bytes())
	saveBytes(t, directory, "mount-admission.stderr", stderr.Bytes())
	saveJSON(t, directory, "mount-admission.exit.json", map[string]int{"exit": exitNumber(err)})
	if err != nil {
		t.Fatal("real mount fixture did not execute:", err, stderr.String())
	}
	var result mountAdmissionResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.BaselineAllowed || result.Original == result.Active || len(result.Stack) < 2 || result.ActualSHA256 != bytesDigest(seed) {
		t.Fatal("real baseline/overmount controls were not established")
	}
	if result.AliasAllowed || result.StaleAllowed || result.MismatchAllowed {
		t.Fatal("actual mount alias or descriptor mount mismatch was admitted")
	}
	points, err := mountPoints()
	if err != nil {
		t.Fatal(err)
	}
	for _, point := range points {
		if within(point.target, filepath.Join(directory, "mount")) {
			t.Fatal("diagnostic mount escaped its owned namespace")
		}
	}
}
