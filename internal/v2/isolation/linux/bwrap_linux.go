//go:build linux

package linux

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

const probeReadOnly = "/data/probe-ro"

type bwrapObservation struct {
	Nonce              string            `json:"nonce"`
	Writable           objectIdentity    `json:"writable"`
	ReadOnly           objectIdentity    `json:"read_only"`
	WritableSHA256     string            `json:"writable_sha256"`
	ReadOnlySHA256     string            `json:"read_only_sha256"`
	WriteErrno         int               `json:"write_errno"`
	ReadOnlyWriteErrno int               `json:"read_only_write_errno"`
	ReadOnlyFS         uint64            `json:"read_only_fs"`
	SeccompErrno       int               `json:"seccomp_errno"`
	Namespaces         map[string]string `json:"namespaces"`
	ExitCode           int               `json:"exit_code"`
	StderrTail         string            `json:"stderr_tail,omitempty"`
}

// observeBwrapOptions runs fixed diagnostic operations only. In particular it
// does not install Landlock: EROFS must prove the read-only bind rather than be masked
// by an additional filesystem policy. This mode never execs a runner.
func observeBwrapOptions(nonce string) error {
	result := bwrapObservation{Nonce: nonce}
	var err error
	result.Namespaces, err = namespaces()
	if err != nil {
		return err
	}
	for _, item := range []struct {
		path string
		out  *objectIdentity
	}{{"/work/main", &result.Writable}, {probeReadOnly, &result.ReadOnly}} {
		fd, err := unix.Open(item.path, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		identity, identifyErr := identify(fd)
		closeErr := unix.Close(fd)
		if err := errors.Join(identifyErr, closeErr); err != nil {
			return err
		}
		*item.out = identity
	}
	writable, err := os.ReadFile("/work/main/record")
	if err != nil {
		return err
	}
	readOnly, err := os.ReadFile(probeReadOnly + "/record")
	if err != nil {
		return err
	}
	result.WritableSHA256, result.ReadOnlySHA256 = bytesDigest(writable), bytesDigest(readOnly)
	result.WriteErrno = errnoNumber(os.WriteFile("/work/main/record", append(writable, []byte(":fd")...), 0600))
	result.ReadOnlyWriteErrno = errnoNumber(os.WriteFile(probeReadOnly+"/record", append(readOnly, []byte(":fd")...), 0600))
	var fs unix.Statfs_t
	if err := unix.Statfs(probeReadOnly, &fs); err != nil {
		return err
	}
	result.ReadOnlyFS = uint64(fs.Flags)
	result.SeccompErrno = errnoNumber(unix.Unshare(0))
	return json.NewEncoder(os.Stdout).Encode(result)
}

func bytesDigest(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

type bwrapProbe struct {
	root     string
	plan     launchPlan
	payload  launchPayload
	writable []byte
	readOnly []byte
	hostNS   map[string]string
	owned    []*pinnedMount
}

func newBwrapProbe(runtimePlan launchPlan) (_ *bwrapProbe, resultErr error) {
	if runtimePlan.helper == nil || runtimePlan.helper.file == nil {
		return nil, &PrerequisiteError{Check: "bwrap_options", Err: errors.New("pinned bootstrap is missing")}
	}
	root, err := os.MkdirTemp("/var/tmp", "lb-v2-linux-probe-")
	if err != nil {
		return nil, err
	}
	probe := &bwrapProbe{root: root, plan: launchPlan{runtime: runtimePlan.runtime,
		helper: runtimePlan.helper, links: runtimePlan.links, cwd: "/work/main"}}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, probe.close())
		}
	}()
	probe.hostNS, err = namespaces()
	if err != nil {
		return nil, err
	}
	var random [96]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	probe.writable, probe.readOnly = random[:32], random[32:64]
	probe.payload = launchPayload{Mode: "options", Nonce: hex.EncodeToString(random[64:])}
	for _, item := range []struct {
		name, target string
		data         []byte
		ro           bool
	}{{"rw", "/work/main", probe.writable, false}, {"ro", probeReadOnly, probe.readOnly, true}} {
		directory := filepath.Join(root, item.name)
		if err := os.Mkdir(directory, 0700); err != nil {
			return nil, err
		}
		// The same UID can actually write both objects before confinement.
		// A source permission denial cannot satisfy the read-only mount probe.
		file, err := os.OpenFile(filepath.Join(directory, "record"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if err != nil {
			return nil, err
		}
		n, writeErr := file.Write(item.data)
		closeErr := file.Close()
		if writeErr == nil && n != len(item.data) {
			writeErr = io.ErrShortWrite
		}
		if err := errors.Join(writeErr, closeErr); err != nil {
			return nil, err
		}
		mount, err := pinPath(directory, item.target, item.ro)
		if err != nil {
			return nil, err
		}
		probe.owned = append(probe.owned, mount)
		probe.plan.data = append(probe.plan.data, mount)
	}
	return probe, nil
}

func (probe *bwrapProbe) close() error {
	var failures []error
	for _, mount := range probe.owned {
		failures = append(failures, mount.file.Close())
	}
	probe.owned = nil
	// Only this freshly created private diagnostic tree is collected. It
	// contains no user export, runner output, environment value or credential.
	if probe.root != "" {
		failures = append(failures, os.RemoveAll(probe.root))
		probe.root = ""
	}
	return errors.Join(failures...)
}

func (probe *bwrapProbe) run(ctx context.Context, args []string) (result bwrapObservation, resultErr error) {
	result.ExitCode = -1
	if _, err := probePrerequisites(ctx); err != nil {
		return result, err
	}
	if err := unix.Unshare(0); err != nil {
		return result, &PrerequisiteError{Check: "bwrap_probe_control", Err: err}
	}
	payload, err := sealedPayload(probe.payload)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, payload.Close()) }()
	filter, err := denyFilter()
	if err != nil {
		return result, err
	}
	seccomp, err := sealedBytes(filterBytes(filter))
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, seccomp.Close()) }()
	_, files := buildArgs(probe.plan)
	probeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(probeCtx, bwrapPath, args...)
	cmd.Env, cmd.Dir = []string{}, "/"
	cmd.ExtraFiles = append([]*os.File{payload, seccomp}, files...)
	var stdout bytes.Buffer
	tail := &boundedTail{max: 8192}
	cmd.Stdout, cmd.Stderr = &stdout, tail
	if err := cmd.Run(); err != nil {
		var exited *exec.ExitError
		if errors.As(err, &exited) {
			result.ExitCode = exited.ExitCode()
		}
		result.StderrTail = string(tail.bytes())
		return result, &PrerequisiteError{Check: "bwrap_options",
			Err: fmt.Errorf("binary probe failed: %w; stderr tail: %s", err, tail.bytes())}
	}
	decoder := json.NewDecoder(&stdout)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF || result.Nonce != probe.payload.Nonce {
		return result, &PrerequisiteError{Check: "bwrap_options", Err: errors.New("invalid binary probe observation")}
	}
	result.ExitCode, result.StderrTail = 0, string(tail.bytes())
	if result.Writable.Device != probe.plan.data[0].identity.Device || result.Writable.Inode != probe.plan.data[0].identity.Inode ||
		result.ReadOnly.Device != probe.plan.data[1].identity.Device || result.ReadOnly.Inode != probe.plan.data[1].identity.Inode ||
		result.WritableSHA256 != bytesDigest(probe.writable) || result.ReadOnlySHA256 != bytesDigest(probe.readOnly) ||
		result.WriteErrno != 0 || result.ReadOnlyWriteErrno != int(unix.EROFS) || result.ReadOnlyFS&unix.ST_RDONLY == 0 {
		return result, &PrerequisiteError{Check: "bwrap_fd_mounts", Err: errors.New("descriptor mount identity or access behavior differs")}
	}
	writable, readErr := os.ReadFile(filepath.Join(probe.root, "rw/record"))
	readOnly, roErr := os.ReadFile(filepath.Join(probe.root, "ro/record"))
	if readErr != nil || roErr != nil || !bytes.Equal(writable, append(append([]byte{}, probe.writable...), []byte(":fd")...)) ||
		!bytes.Equal(readOnly, probe.readOnly) {
		return result, &PrerequisiteError{Check: "bwrap_fd_mounts", Err: errors.Join(errors.New("outside mount read-back differs"), readErr, roErr)}
	}
	if result.SeccompErrno != int(unix.EPERM) {
		return result, &PrerequisiteError{Check: "bwrap_seccomp", Err: errors.New("escape syscall was not denied by the supplied filter")}
	}
	for name, host := range probe.hostNS {
		if result.Namespaces[name] == "" || result.Namespaces[name] == host {
			return result, &PrerequisiteError{Check: "bwrap_namespaces", Err: fmt.Errorf("%s namespace did not change", name)}
		}
	}
	return result, nil
}

var bwrapBehaviorCache probeCache

func requireBwrapOptions(ctx context.Context, plan launchPlan) error {
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return &PrerequisiteError{Check: "boot_identity", Err: err}
	}
	var binary unix.Stat_t
	if err := unix.Stat(bwrapPath, &binary); err != nil {
		return &PrerequisiteError{Check: "distro_bwrap", Err: err}
	}
	if plan.helper == nil {
		return &PrerequisiteError{Check: "bwrap_options", Err: errors.New("missing pinned bootstrap")}
	}
	identities := []objectIdentity{plan.helper.identity}
	for _, item := range plan.runtime {
		identities = append(identities, item.identity)
	}
	key, err := json.Marshal([]any{string(boot), os.Geteuid(), os.Getegid(), binary, identities, plan.links})
	if err != nil {
		return err
	}
	_, err = bwrapBehaviorCache.get(bytesDigest(key), func() (api.IsolationCapabilities, error) {
		probe, err := newBwrapProbe(plan)
		if err != nil {
			return api.IsolationCapabilities{}, &PrerequisiteError{Check: "bwrap_options", Err: err}
		}
		args, _ := buildArgs(probe.plan)
		_, probeErr := probe.run(ctx, args)
		closeErr := probe.close()
		if closeErr != nil {
			closeErr = &PrerequisiteError{Check: "bwrap_probe_collection", Err: closeErr}
		}
		if err := errors.Join(probeErr, closeErr); err != nil {
			return api.IsolationCapabilities{}, err
		}
		return api.IsolationCapabilities{Checks: []api.Capability{{Name: "bwrap_options", Available: true}}}, nil
	})
	return err
}
