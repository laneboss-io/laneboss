//go:build linux

package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

const fixedBootstrapPath = "/.laneboss-bootstrap"
const bootstrapSeals = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL

type bootstrapPath struct {
	Path       string `json:"path"`
	Directory  bool   `json:"directory"`
	Writable   bool   `json:"writable"`
	Executable bool   `json:"executable"`
}

// Only the root helper constructs this sealed descriptor. It contains no host
// path, credential value, command selector or inherited ambient environment.
type gatePayload struct {
	workerJournal      io.Writer
	stdin              *os.File
	beforeSpawn        func() error
	Prompt             *api.BlobRef          `json:"prompt,omitempty"`
	CredentialRequired bool                  `json:"credential_required,omitempty"`
	PreparedID         api.ID                `json:"prepared_id,omitempty"`
	SpecSHA256         api.Digest            `json:"spec_sha256,omitempty"`
	IsolationReady     bool                  `json:"-"`
	Config             string                `json:"config"`
	Mode               string                `json:"mode"`
	GateID             api.ID                `json:"gate_id"`
	Token              string                `json:"token"`
	UID                uint32                `json:"uid"`
	GID                uint32                `json:"gid"`
	Argv               []string              `json:"argv"`
	Environment        []string              `json:"environment"`
	CWD                string                `json:"cwd"`
	Paths              []bootstrapPath       `json:"paths"`
	Budget             api.Budget            `json:"budget"`
	Capture            *spoolInput           `json:"capture,omitempty"`
	Inherited          []bootstrapDescriptor `json:"inherited,omitempty"`
}

type bootstrapDescriptor struct {
	FD     int    `json:"fd"`
	Target string `json:"target"`
	Socket bool   `json:"socket"`
}

type nativeMount struct {
	file       *os.File
	target     string
	directory  bool
	writable   bool
	executable bool
	socket     bool
	sealed     bool
	resolver   bool
}

type nativeGate struct {
	workerJournal   io.Writer
	workerFiles     [2]*os.File
	workerPins      [2]workerDescriptorPin
	mu              sync.Mutex
	command         *exec.Cmd
	pidfd           int
	generation      string
	release         *os.File
	token           string
	released        bool
	done            chan struct{}
	state           *os.ProcessState
	waitErr         error
	wall            *time.Timer
	control         *net.UnixConn
	execAck         *net.UnixConn
	execHashRead    func(int)
	wallMS          int64
	kill            func() error
	killErr         error
	innerPID        int
	innerFD         int
	innerGeneration string
	bootstrapUmask  *uint32
	stderr          *bootstrapStderr
	primaryDone     chan struct{}
	drainBound      chan struct{}
	primaryExited   bool
	primaryExitAt   time.Time
	primaryErr      error
	waitFinishedAt  time.Time
	drainExpired    bool
	spawnLifetime   *nativeSpawnLifetime
	cgroupFD        int
	cgroupBefore    nativeCgroupSnapshot
	helperKill      string
}

func (g *nativeGate) PID() int           { return g.command.Process.Pid }
func (g *nativeGate) Generation() string { return g.generation }

func (g *nativeGate) innerLifetime(bootID string) (resultErr error) {
	defer helperCheck(&resultErr, "bootstrap_lifetime")
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.innerFD < 0 || g.innerPID <= 1 || g.innerGeneration == "" {
		return failure(api.CodeContainmentUnknown, "fixed bootstrap lifetime is unavailable")
	}
	fds := []unix.PollFd{{Fd: int32(g.innerFD), Events: unix.POLLIN}}
	count, err := pollHelperLifetime(fds, unix.Poll)
	if err != nil || count != 0 || fds[0].Revents != 0 {
		return failure(api.CodeContainmentUnknown, "fixed bootstrap kernel lifetime ended")
	}
	generation, err := processGeneration(g.innerPID, bootID)
	if err != nil || generation != g.innerGeneration {
		return failure(api.CodeContainmentUnknown, "fixed bootstrap process generation changed")
	}
	return nil
}

func (g *nativeGate) connectionCount() (uint64, error) {
	if g.control == nil {
		return 0, failure(api.CodeContainmentUnknown, "native readiness connection inventory is absent")
	}
	raw, err := g.control.SyscallConn()
	if errors.Is(err, net.ErrClosed) {
		return 0, nil
	}
	if err != nil {
		return 0, failure(api.CodeContainmentUnknown, "cannot observe native readiness connection")
	}
	var count uint64
	err = raw.Control(func(uintptr) { count++ })
	if errors.Is(err, net.ErrClosed) {
		return 0, nil
	}
	if err != nil {
		return 0, failure(api.CodeContainmentUnknown, "native readiness connection lifetime is unknown")
	}
	return count, nil
}

func (g *nativeGate) Release() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.release == nil || g.released {
		return failure(api.CodeConflict, "native release descriptor was already consumed")
	}
	if err := g.releaseLifetimeLocked(); err != nil {
		return err
	}
	file := g.release
	g.release, g.released = nil, true
	n, err := file.WriteString(g.token)
	closeErr := file.Close()
	if err != nil || closeErr != nil || n != len(g.token) {
		return failure(api.CodeContainmentUnknown, "native gate release acknowledgement is uncertain")
	}
	g.armWallTimerLocked()
	return nil
}

func (g *nativeGate) armWallTimerLocked() {
	if g.wallMS > 0 && g.kill != nil {
		g.wall = time.AfterFunc(time.Duration(g.wallMS)*time.Millisecond, func() {
			err := g.kill()
			if err != nil {
				g.mu.Lock()
				g.killErr = err
				g.mu.Unlock()
			}
		})
	}
}

func (g *nativeGate) releaseLifetimeLocked() error {
	return g.releaseLifetimeWithPollLocked(unix.Poll)
}

func (g *nativeGate) releaseLifetimeWithPollLocked(poll func([]unix.PollFd, int) (int, error)) error {
	if err := g.drainErrorLocked(); err != nil {
		return err
	}
	select {
	case <-g.done:
		return failure(api.CodeContainmentUnknown, "native gate ended before release")
	case <-g.primaryDone:
		return failure(api.CodeContainmentUnknown, "native primary ended before release")
	default:
	}
	// The watcher is asynchronous. Require a fresh native observation too,
	// so an already-readable pidfd cannot release while its callback is queued.
	fds := []unix.PollFd{{Fd: int32(g.pidfd), Events: unix.POLLIN}}
	// Runtime preemption and child-exit signals can interrupt a live pidfd
	// observation. Only a completed poll establishes liveness; exhausting the
	// small retry bound still refuses release without consuming the pipe.
	count, err := pollHelperLifetime(fds, poll)
	if err != nil || count != 0 || fds[0].Revents != 0 {
		reason := "unknown"
		switch {
		case errors.Is(err, unix.EINTR):
			reason = "interrupted"
		case errors.Is(err, unix.EBADF) || fds[0].Revents&unix.POLLNVAL != 0:
			reason = "invalid"
		case err == nil && fds[0].Revents&(unix.POLLIN|unix.POLLHUP) != 0:
			reason = "ended"
		}
		return failure(api.CodeContainmentUnknown, "native primary is not live for release (poll="+reason+")")
	}
	return nil
}

func (g *nativeGate) Observe(ctx context.Context, handle api.ProcessHandle) (_ api.ProcessObservation, resultErr error) {
	defer helperCheck(&resultErr, "gate_observation")
	if err := contextError(ctx); err != nil {
		return api.ProcessObservation{}, err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	result := api.ProcessObservation{Handle: handle, State: "running", PromptStatus: "not_written", ObservedAt: gateTimestamp()}
	if err := g.drainErrorLocked(); err != nil {
		return api.ProcessObservation{}, err
	}
	if g.released {
		result.PromptStatus = "unknown"
	}
	if g.killErr != nil {
		return api.ProcessObservation{}, failure(api.CodeContainmentUnknown, "native budget stop failed; retain its lease")
	}
	select {
	case <-g.done:
		if g.state == nil {
			return api.ProcessObservation{}, failure(api.CodeContainmentUnknown, "native wait did not retain a process status")
		}
		var exited *exec.ExitError
		if g.waitErr != nil && !errors.As(g.waitErr, &exited) {
			return api.ProcessObservation{}, failure(api.CodeContainmentUnknown, "native wait or descriptor collection was not observed")
		}
		status, ok := g.state.Sys().(syscall.WaitStatus)
		if !ok || !status.Exited() && !status.Signaled() {
			return api.ProcessObservation{}, failure(api.CodeContainmentUnknown, "native wait status is not terminal")
		}
		// This is the actual containment supervisor's wait status. No runner
		// text, fabricated exit or request observation supplies it.
		result.State = "exited"
		if status.Signaled() {
			signal := int(status.Signal())
			result.Signal = &signal
		} else {
			code := status.ExitStatus()
			result.ExitCode = &code
		}
		return result, nil
	default:
		if g.primaryExited {
			return api.ProcessObservation{}, failure(api.CodeContainmentUnknown, "native primary exit is observed; stderr drain is pending")
		}
		fds := []unix.PollFd{{Fd: int32(g.pidfd), Events: unix.POLLIN}}
		count, err := pollHelperLifetime(fds, unix.Poll)
		if err != nil || count != 0 || fds[0].Revents != 0 {
			return api.ProcessObservation{}, failure(api.CodeContainmentUnknown, "native wait is not yet reconciled with its pidfd")
		}
		return result, nil
	}
}

func (g *nativeGate) Stop(ctx context.Context, handle api.ProcessHandle) (api.ProcessObservation, error) {
	select {
	case <-ctx.Done():
		return api.ProcessObservation{}, failure(api.CodeContainmentUnknown, "native stop wait expired; retain the lease")
	case <-g.done:
		return g.Observe(ctx, handle)
	case <-g.primaryDone:
		select {
		case <-ctx.Done():
			return api.ProcessObservation{}, failure(api.CodeContainmentUnknown, "native stop drain wait expired; retain the lease")
		case <-g.done:
		case <-g.drainBound:
		}
		return g.Observe(ctx, handle)
	}
}

func (g *nativeGate) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	for i, file := range g.workerFiles {
		if file != nil {
			if err := file.Close(); err != nil {
				return failure(api.CodeContainmentUnknown, "cannot close retained worker descriptor")
			}
			g.workerFiles[i] = nil
		}
	}
	if g.execAck != nil {
		if err := g.execAck.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			return failure(api.CodeContainmentUnknown, "cannot close native gate exec proof")
		}
	}
	if g.control != nil {
		if err := g.control.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			return failure(api.CodeContainmentUnknown, "cannot close native gate control")
		}
	}
	if g.release != nil {
		if err := g.release.Close(); err != nil {
			return failure(api.CodeContainmentUnknown, "cannot close retained gate")
		}
		g.release = nil
	}
	if g.wall != nil {
		g.wall.Stop()
	}
	select {
	case <-g.done:
		if g.helperKill == "" {
			g.helperKill = "not_needed_waited"
		}
		return nil
	default:
	}
	if g.primaryFactLocked() == "exited" {
		if g.helperKill == "" {
			g.helperKill = "not_needed_exited"
		}
		return nil
	}
	err := unix.PidfdSendSignal(g.pidfd, unix.SIGKILL, nil, 0)
	if err == nil {
		g.helperKill = "sent"
	} else if g.helperKill != "sent" {
		if errors.Is(err, unix.ESRCH) {
			g.helperKill = "already_ended"
		} else {
			g.helperKill = "failed_" + nativeSpawnErrno(err)
		}
	}
	if err != nil && !errors.Is(err, unix.ESRCH) {
		return failure(api.CodeContainmentUnknown, "cannot stop pinned native gate")
	}
	return nil
}

func sealedBootstrap(value any) (*os.File, error) {
	data, err := json.Marshal(value)
	if err != nil || len(data) == 0 || len(data) > api.MaxFrameBytes {
		return nil, failure(api.CodeInvalid, "fixed bootstrap input exceeds its bound")
	}
	fd, err := unix.MemfdCreate("laneboss-fixed-input", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, failure(api.CodePrerequisite, "sealed bootstrap descriptors are unavailable")
	}
	file := os.NewFile(uintptr(fd), "sealed-bootstrap")
	n, writeErr := file.Write(data)
	_, seekErr := file.Seek(0, io.SeekStart)
	_, sealErr := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, bootstrapSeals)
	if writeErr != nil || n != len(data) || seekErr != nil || sealErr != nil {
		file.Close()
		return nil, failure(api.CodeIntegrity, "cannot seal exact bootstrap bytes")
	}
	return file, nil
}

func pinNativeMount(source, target string, directory, writable, executable bool, uid, gid uint32) (*nativeMount, error) {
	return pinNativeMountWithOpenat2(source, target, directory, writable, executable, uid, gid, unix.Openat2)
}

// The syscall dependency is private and explicit so component tests can force
// its refusal while exercising the real walk and final descriptor checks.
func pinNativeMountWithOpenat2(source, target string, directory, writable, executable bool, uid, gid uint32, openat2 nativeMountOpenat2) (*nativeMount, error) {
	fd, err := openNativeMountSource(source, openat2)
	if err != nil {
		return nil, nativeMountPinError(err)
	}
	file := os.NewFile(uintptr(fd), "owned-native-mount")
	var info unix.Stat_t
	if unix.Fstat(fd, &info) != nil ||
		directory != (info.Mode&unix.S_IFMT == unix.S_IFDIR) || !directory && info.Mode&unix.S_IFMT != unix.S_IFREG {
		file.Close()
		return nil, failure(api.CodeIntegrity, "native mount owner, mode or type differs")
	}
	if info.Uid != uid || info.Gid != gid || info.Mode&07022 != 0 {
		allowAndLog("native_mount_owner")
	}
	return &nativeMount{file: file, target: target, directory: directory, writable: writable, executable: executable}, nil
}

// Keep the syscall category without returning source paths or arbitrary error
// strings. A denied syscall is not evidence of a linked or missing source.
func nativeMountPinError(err error) error {
	reason := "native open failed"
	switch {
	case errors.Is(err, unix.EPERM):
		reason = "openat2 denied"
	case errors.Is(err, unix.EACCES):
		reason = "source access denied"
	case errors.Is(err, unix.ENOENT):
		reason = "source missing"
	case errors.Is(err, unix.ELOOP):
		reason = "symbolic or magic link refused"
	case errors.Is(err, unix.ENOSYS):
		reason = "openat2 unavailable"
	case errors.Is(err, unix.ENOTDIR):
		reason = "source component is not a directory"
	case errors.Is(err, unix.EINVAL):
		reason = "openat2 flags unsupported"
	}
	var walk *nativeMountWalkError
	if errors.As(err, &walk) {
		switch {
		case errors.Is(err, unix.EPERM):
			reason = "openat denied"
		case errors.Is(err, unix.ENOSYS):
			reason = "openat unavailable"
		case errors.Is(err, unix.EINVAL):
			reason = "source components invalid"
		}
		reason = "component walk: " + reason
	}
	return failure(api.CodeContainmentUnknown, "cannot pin native mount source without links ("+reason+")")
}

// Runtime paths have a fixed namespace projection. System-library objects
// retain their relative ABI path; all other files are named by enrolled ID.
// No request supplies a host path or mount destination.
func nativeRuntimeTarget(object api.RuntimeObject) string {
	switch object.RelativePath {
	case "etc/ld.so.cache", "etc/nsswitch.conf", "etc/hosts", "etc/gai.conf",
		"etc/host.conf", "etc/localtime", "etc/machine-id", "etc/os-release":
		return "/" + object.RelativePath
	}
	for _, prefix := range []string{"usr/", "lib/", "lib64/", "bin/", "sbin/", "etc/ssl/"} {
		if strings.HasPrefix(object.RelativePath, prefix) {
			return "/" + object.RelativePath
		}
	}
	return "/runtime/" + string(object.ID)
}

func (m *leaseManager) gateMounts(ctx context.Context, record leaseRecord) (api.RuntimeManifest, []*nativeMount, error) {
	spec := record.Spec.Handoff.Spec
	manifest, err := loadInstalledRuntime(ctx, m.binding, spec.RuntimeManifest)
	if err != nil {
		return manifest, nil, err
	}
	if manifest.Bootstrap.SHA256 != m.binding.Artifact.SHA256 {
		return manifest, nil, failure(api.CodeUnsupported, "enrolled bootstrap is not this release's fixed administrator bootstrap")
	}
	var mounts []*nativeMount
	failed := true
	defer func() {
		if failed {
			for _, mount := range mounts {
				mount.file.Close()
			}
		}
	}()
	base := filepath.Join(filepath.Dir(m.binding.binaryPath()), "runtime", m.binding.Config)
	targets := map[string]bool{}
	for _, object := range manifest.Objects {
		target := nativeRuntimeTarget(object)
		if targets[target] {
			return manifest, nil, failure(api.CodeIntegrity, "runtime projection aliases a destination")
		}
		targets[target] = true
		source := filepath.Join(base, string(object.RootID), object.RelativePath)
		mount, err := pinNativeMount(source, target, false, false, object.Mode == 0555, 0, 0)
		if err != nil {
			return manifest, nil, err
		}
		mounts = append(mounts, mount)
		// Hash through the pinned inode rather than reopening the source name.
		reader, err := os.Open("/proc/self/fd/" + strconv.Itoa(int(mount.file.Fd())))
		if err != nil {
			return manifest, nil, failure(api.CodeIntegrity, "cannot read pinned runtime bytes")
		}
		readErr := hashRuntime(reader, object)
		closeErr := reader.Close()
		if readErr != nil || closeErr != nil {
			return manifest, nil, failure(api.CodeIntegrity, "pinned runtime bytes differ")
		}
		for _, alias := range object.Aliases {
			if targets[alias] {
				return manifest, nil, failure(api.CodeIntegrity, "runtime certificate destination repeats")
			}
			targets[alias] = true
			fd, err := unix.FcntlInt(mount.file.Fd(), unix.F_DUPFD_CLOEXEC, 3)
			if err != nil {
				return manifest, nil, failure(api.CodeIntegrity, "cannot pin runtime certificate alias")
			}
			mounts = append(mounts, &nativeMount{file: os.NewFile(uintptr(fd), "runtime-cert"), target: alias})
		}
		if object.ID == manifest.Bootstrap.ID {
			copyFD, err := unix.FcntlInt(mount.file.Fd(), unix.F_DUPFD_CLOEXEC, 3)
			if err != nil {
				return manifest, nil, failure(api.CodeIntegrity, "cannot pin fixed bootstrap projection")
			}
			mounts = append(mounts, &nativeMount{file: os.NewFile(uintptr(copyFD), "fixed-bootstrap"), target: fixedBootstrapPath, executable: true})
		}
	}
	if record.Storage != nil {
		if err := m.syncLaunchStorage(ctx, &record, false); err != nil {
			return manifest, nil, err
		}
		storageBase := filepath.Join("/var/lib/laneboss-v2/lanes", m.binding.Config, string(record.Lease.ID))
		for index, target := range []string{"/work/main", "/home/lane", "/history"} {
			item := record.Storage.Directories[index]
			writable := true
			if index == 0 && record.Spec != nil {
				for _, grant := range record.Spec.Handoff.Spec.Grants.Data {
					if grant.Destination == "/work/main" && grant.Access == "ro" {
						writable = false
					}
				}
			}
			mount, err := pinNativeMount(filepath.Join(storageBase, string(item.ID)), target, true, writable, true, record.Lease.UID, record.Lease.GID)
			if err != nil {
				return manifest, nil, err
			}
			var info unix.Stat_t
			if unix.Fstat(int(mount.file.Fd()), &info) != nil {
				mount.file.Close()
				return manifest, nil, failure(api.CodeIntegrity, "private mount inode changed")
			}
			if item.Device != strconv.FormatUint(uint64(info.Dev), 10) || item.Inode != strconv.FormatUint(info.Ino, 10) {
				allowAndLog("private_mount_inode")
			}
			mounts = append(mounts, mount)
		}
	}
	failed = false
	return manifest, mounts, nil
}

func gateDestinationNeedsExport(grant api.DataGrant) bool {
	return grant.Destination != "/work/main" || grant.Delivery == "mount" || grant.HistoryScope == "reachable"
}

func validateGateDataGrant(grant api.DataGrant) error {
	parts := strings.Split(grant.Destination, "/")
	if len(parts) != 3 || parts[0] != "" || parts[1] != "work" && parts[1] != "data" || !validID(api.ID(parts[2])) {
		return failure(api.CodeInvalid, "data export destination is not a logical private target")
	}
	if grant.Access != "ro" && grant.Access != "rw" {
		return failure(api.CodeInvalid, "data export access is unknown")
	}
	if grant.Delivery != "copy" && grant.Delivery != "mount" {
		return failure(api.CodeInvalid, "data export delivery is unknown")
	}
	if grant.HistoryScope != "snapshot" && grant.HistoryScope != "tree" && grant.HistoryScope != "reachable" {
		return failure(api.CodeUnsupported, "data export history scope is not enrolled")
	}
	if grant.HistoryScope == "reachable" && grant.Delivery != "mount" {
		return failure(api.CodeUnsupported, "reachable Git history requires a registered live export")
	}
	if grant.Delivery == "mount" && grant.HistoryScope == "snapshot" {
		return failure(api.CodeUnsupported, "snapshot data cannot be delivered as a live export")
	}
	return nil
}

func (m *leaseManager) registerGateExports(ctx context.Context, record *leaseRecord) error {
	if record == nil || record.Spec == nil {
		return failure(api.CodeIntegrity, "registered export needs its retained launch spec")
	}
	grants := record.Spec.Handoff.Spec.Grants.Data
	if len(grants) == 0 {
		if len(record.Exports) != 0 {
			return failure(api.CodeIntegrity, "registered exports have no retained data grants")
		}
		return nil
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := validateExportJournals(*record); err != nil {
		return err
	}
	byGrant := map[api.ID]exportJournal{}
	for _, entry := range record.Exports {
		byGrant[entry.GrantID] = entry
	}
	if m.exports == nil {
		m.exports = map[api.ID]map[api.ID]*registeredExport{}
	}
	owned := map[api.ID]*registeredExport{}
	journals := make([]exportJournal, 0, len(record.Exports))
	for _, grant := range grants {
		if err := validateGateDataGrant(grant); err != nil {
			return err
		}
		if !gateDestinationNeedsExport(grant) {
			continue
		}
		resolve := m.dataCopyExport
		if grant.Delivery == "mount" {
			if m.exportResolver == nil {
				return failure(api.CodeUnavailable, "registered export owner is not bound")
			}
			resolve = m.exportResolver
		}
		resolved, err := resolve(ctx, *record, grant)
		if err != nil {
			return err
		}
		if resolved.File == nil || resolved.Destination != grant.Destination || resolved.SourceIdentity == "" || resolved.DestinationIdentity == "" ||
			resolved.ClaimID != record.Spec.Handoff.Cause.EffectID || resolved.ReadOnly && resolved.Writable {
			return failure(api.CodeIntegrity, "registered export owner changed its pinned source or live claim")
		}
		if !resolved.Directory && grant.Delivery != "copy" {
			return failure(api.CodeUnsupported, "registered exports must provide directory identities")
		}
		if grant.Access == "rw" {
			if resolved.ReadOnly || !resolved.Writable || resolved.WriterLeaseID == "" {
				return failure(api.CodeForbidden, "writable export has no exclusive live writer claim")
			}
		} else if resolved.Writable || !resolved.ReadOnly {
			return failure(api.CodeIntegrity, "read-only export is not recursively read-only")
		}
		entry := exportJournal{GrantID: grant.ID, Destination: grant.Destination, SourceIdentity: resolved.SourceIdentity,
			DestinationIdentity: resolved.DestinationIdentity, ClaimID: resolved.ClaimID, WriterLeaseID: resolved.WriterLeaseID,
			Generation: record.Lease.EndpointGeneration}
		if prior, ok := byGrant[grant.ID]; ok && prior != entry {
			return failure(api.CodeIdempotencyConflict, "registered export replay changed its original pin")
		}
		copy := resolved
		owned[grant.ID] = &copy
		journals = append(journals, entry)
	}
	if len(journals) != len(record.Exports) {
		if len(record.Exports) != 0 {
			return failure(api.CodeIntegrity, "registered export journal contains a grant outside the current spec")
		}
		record.Exports = journals
	} else {
		record.Exports = append([]exportJournal(nil), journals...)
	}
	m.exports[record.Lease.ID] = owned
	return validateExportJournals(*record)
}

func (m *leaseManager) appendGateExports(record leaseRecord, mounts []*nativeMount) ([]*nativeMount, error) {
	if len(record.Exports) == 0 {
		return mounts, nil
	}
	fail := func(err error) ([]*nativeMount, error) {
		for _, mount := range mounts {
			if mount != nil && mount.file != nil {
				_ = mount.file.Close()
			}
		}
		return nil, err
	}
	owned := m.exports[record.Lease.ID]
	if len(owned) != len(record.Exports) {
		return fail(failure(api.CodeContainmentUnknown, "registered export descriptors are unavailable; replacement is forbidden"))
	}
	for _, entry := range record.Exports {
		resolved := owned[entry.GrantID]
		if resolved == nil || resolved.File == nil || resolved.Destination != entry.Destination || resolved.SourceIdentity != entry.SourceIdentity ||
			resolved.DestinationIdentity != entry.DestinationIdentity || resolved.ClaimID != entry.ClaimID || resolved.WriterLeaseID != entry.WriterLeaseID {
			return fail(failure(api.CodeContainmentUnknown, "registered export descriptor no longer matches its live claim"))
		}
		for _, existing := range mounts {
			if existing.target == resolved.Destination || strings.HasPrefix(existing.target, resolved.Destination+"/") || strings.HasPrefix(resolved.Destination, existing.target+"/") {
				return fail(failure(api.CodeIntegrity, "registered export destination aliases another native mount"))
			}
		}
		mounts = append(mounts, &nativeMount{file: resolved.File, target: resolved.Destination, directory: resolved.Directory,
			writable: resolved.Writable, executable: resolved.Executable})
		resolved.File = nil // nativeMount now owns the descriptor; collection must not close it twice.
	}
	return mounts, nil
}

func (m *leaseManager) collectGateExports(leaseID api.ID) error {
	owned := m.exports[leaseID]
	if owned == nil {
		return nil
	}
	var result error
	for _, export := range owned {
		if export != nil && export.File != nil {
			result = errors.Join(result, export.File.Close())
			export.File = nil
		}
	}
	delete(m.exports, leaseID)
	return result
}

func (m *leaseManager) startConfinedGate(ctx context.Context, record leaseRecord) (ownedGate, error) {
	spec := record.Spec.Handoff.Spec
	for _, grant := range spec.Grants.Data {
		if err := validateGateDataGrant(grant); err != nil {
			return nil, err
		}
	}
	if len(spec.Grants.Network) != 0 {
		if _, err := m.ownedNetwork(record); err != nil {
			return nil, failure(api.CodeUnavailable, "controlled egress namespace is not enrolled")
		}
		if err := m.networkHealth(record); err != nil {
			return nil, err
		}
	}
	if credentialRequired(spec) && m.credentials == nil {
		return nil, failure(api.CodeUnavailable, "native credential projection receiver is not bound")
	}
	manifest, mounts, err := m.gateMounts(ctx, record)
	if err != nil {
		return nil, err
	}
	mounts, err = m.appendClaudockSettings(ctx, record, mounts)
	if err != nil {
		return nil, err
	}
	mounts, err = m.appendGateExports(record, mounts)
	if err != nil {
		return nil, err
	}
	if len(manifest.Bindings) != 0 {
		for _, mount := range mounts {
			mount.file.Close()
		}
		return nil, api.NotImplemented(owner, "runtime endpoint projections require registered connection ownership")
	}
	defer func() {
		for _, mount := range mounts {
			mount.file.Close()
		}
	}()
	var argv []string
	provider, err := m.watchdogProviderMount(manifest, mounts)
	if err != nil {
		return nil, err
	}
	if provider != nil {
		mounts = append(mounts, provider)
	}
	var executable api.Executable
	cwd := "/work/main"
	if spec.Runner != nil {
		argv, executable, cwd = spec.Runner.Argv, spec.Runner.Executable, spec.Runner.CWD
	} else if spec.Worker != nil {
		// The worker still needs its exact immutable input/endpoint mapping.
		return nil, api.NotImplemented(owner, "worker input and endpoint descriptors require the fixed worker handoff")
	} else {
		return nil, failure(api.CodeInvalid, "gate has no retained executable")
	}
	expected := ""
	for _, object := range manifest.Objects {
		if object.ID == executable.ID && object.Content.SHA256 == executable.SHA256 {
			expected = nativeRuntimeTarget(object)
		}
	}
	if len(argv) == 0 || argv[0] != expected || expected == "" || filepath.Clean(cwd) != cwd || cwd != "/work/main" && !strings.HasPrefix(cwd, "/work/main/") {
		return nil, failure(api.CodeIntegrity, "runner argv or cwd differs from its enrolled namespace projection")
	}
	for _, argument := range argv {
		if strings.ContainsRune(argument, 0) {
			return nil, failure(api.CodeInvalid, "NUL in sealed runner arguments")
		}
	}
	mounts, err = m.appendNetworkMount(record, mounts)
	if err != nil {
		return nil, err
	}
	mounts, err = m.appendLaneEndpointMounts(ctx, record, mounts)
	if err != nil {
		return nil, err
	}
	stdin, err := m.runnerPromptInput(ctx, record)
	if err != nil {
		return nil, err
	}
	defer stdin.Close()
	token, err := randomID("release-")
	if err != nil {
		return nil, err
	}
	payload := gatePayload{Config: m.binding.Config, Mode: "prepared-gate", GateID: record.Gate.Prepared.GateID, Token: string(token),
		UID: record.Lease.UID, GID: record.Lease.GID, Argv: argv, CWD: cwd, Budget: spec.Budget,
		Environment: agentEnvironment(spec.Runner.Driver, spec.Runner.Slot.Mode)}
	payload.stdin, payload.Prompt = stdin, &spec.Runner.Prompt
	payload.CredentialRequired, payload.PreparedID, payload.SpecSHA256 = credentialRequired(spec), record.Gate.Prepared.ID, record.Spec.Handoff.SpecSHA256
	stdout, stderr, err := m.captureWriters(ctx, record)
	if err != nil {
		return nil, err
	}
	defer stdout.Close()
	defer stderr.Close()
	network, err := m.ownedNetwork(record)
	if err != nil {
		return nil, err
	}
	gate, err := startNativeGate(ctx, m.binding, record, payload, mounts, stdout, stderr, nil, network, m.bootID)
	if err != nil {
		return nil, err
	}
	native := gate.(*nativeGate)
	native.wallMS, native.kill = spec.Budget.WallMS, func() error { return m.killContainment(context.Background(), record) }
	return gate, nil
}

func agentEnvironment(driver api.Driver, modes ...string) []string {
	values := []string{"HOME=/home/lane", "PATH=/usr/bin:/bin:/runtime", "TMPDIR=/tmp", "XDG_RUNTIME_DIR=/run/lane",
		"XDG_CACHE_HOME=/home/lane/.cache", "XDG_CONFIG_HOME=/home/lane/.config", "XDG_STATE_HOME=/home/lane/.local/state", "GOMAXPROCS=1"}
	if driver == api.DriverCodex {
		values = append(values, "CODEX_HOME=/home/lane/.codex")
	}
	if driver == api.DriverClaudock {
		store := ".config/claudock/credential-store.json"
		if len(modes) == 1 && modes[0] == "claude-api-key" {
			store = ".config/claudock/key-store.json"
		}
		values = append(values, "CLAUDE_CONFIG_DIR=/home/lane/.claude", "CLAUDOCK_CREDENTIAL_STORE=file:/home/lane/"+store, "CLAUDOCK_REGISTRY_DIR=/home/lane/.config/claudock")
	}
	return values
}

func (m *leaseManager) appendLaneEndpointMounts(ctx context.Context, record leaseRecord, mounts []*nativeMount) ([]*nativeMount, error) {
	if err := checkLaneMountTargets(mounts); err != nil {
		return mounts, err
	}
	endpoints, err := m.laneEndpointMounts(ctx, record)
	if err != nil {
		return mounts, err
	}
	return append(mounts, endpoints...), nil
}

func startNativeGate(ctx context.Context, binding installation, record leaseRecord, payload gatePayload, mounts []*nativeMount, stdout, stderr *os.File, inherited []*os.File, network *os.File, bootID string) (_ ownedGate, resultErr error) {
	if err := verifyBwrap(); err != nil {
		return nil, err
	}
	if payload.Argv == nil {
		payload.Argv = []string{}
	}
	if payload.Environment == nil {
		payload.Environment = []string{}
	}
	if payload.Paths == nil {
		payload.Paths = []bootstrapPath{}
	}
	for index, mount := range mounts {
		// Connecting a pinned Unix socket requires no filesystem read/write
		// grant. Landlock file rights are invalid on socket inodes.
		if mount.socket || mount.sealed {
			payload.Inherited = append(payload.Inherited, bootstrapDescriptor{FD: 6 + len(inherited) + index, Target: mount.target, Socket: mount.socket})
			continue
		}
		payload.Paths = append(payload.Paths, bootstrapPath{Path: mount.target, Directory: mount.directory, Writable: mount.writable, Executable: mount.executable})
	}
	for _, path := range []string{"/tmp", "/run/lane", "/dev/shm"} {
		payload.Paths = append(payload.Paths, bootstrapPath{Path: path, Directory: true, Writable: true, Executable: true})
	}
	payload.Paths = append(payload.Paths, bootstrapPath{Path: "/proc", Directory: true})
	for _, device := range []string{"null", "zero", "random", "urandom", "full", "tty"} {
		payload.Paths = append(payload.Paths, bootstrapPath{Path: "/dev/" + device, Writable: true})
	}
	sealed, err := sealedBootstrap(payload)
	if err != nil {
		return nil, err
	}
	defer sealed.Close()
	releaseRead, releaseWrite, err := os.Pipe()
	if err != nil {
		return nil, failure(api.CodePrerequisite, "cannot create one-use release pipe")
	}
	defer releaseRead.Close()
	defer func() {
		if resultErr != nil {
			releaseWrite.Close()
		}
	}()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, failure(api.CodePrerequisite, "cannot create private readiness channel")
	}
	parentFile, childFile := os.NewFile(uintptr(pair[0]), "gate-ready-owner"), os.NewFile(uintptr(pair[1]), "gate-ready-child")
	defer parentFile.Close()
	defer childFile.Close()
	if unix.SetsockoptInt(pair[0], unix.SOL_SOCKET, unix.SO_PASSCRED, 1) != nil || payload.CredentialRequired && unix.SetsockoptInt(pair[1], unix.SOL_SOCKET, unix.SO_PASSCRED, 1) != nil {
		return nil, failure(api.CodePrerequisite, "readiness credentials unavailable")
	}
	connection, err := net.FileConn(parentFile)
	if err != nil {
		return nil, failure(api.CodePrerequisite, "cannot bound readiness channel")
	}
	defer func() {
		if resultErr != nil || !payload.CredentialRequired {
			connection.Close()
		}
	}()
	cgroupPath := filepath.Join(binding.cgroupPath(), string(record.Lease.ContainmentID))
	cgroup, err := os.Open(cgroupPath)
	if err != nil {
		return nil, api.WithHelperReason(failure(api.CodeContainmentUnknown, "cannot pin gate cgroup for clone"), "cgroup_open")
	}
	defer cgroup.Close()
	files := []*os.File{sealed, releaseRead, childFile}
	files = append(files, inherited...)
	args, files := nativeGateArgs(binding.Config, payload.Mode, files, mounts, network == nil)
	cmd := exec.Command("/usr/bin/bwrap", args...)
	cmd.Dir, cmd.Env, cmd.ExtraFiles = "/", []string{}, files
	diagnostic, err := attachBootstrapStderr(cmd, stderr)
	if err != nil {
		return nil, err
	}
	stderrInStarter := true
	defer func() {
		if stderrInStarter {
			if err := diagnostic.close(); err != nil {
				resultErr = errors.Join(resultErr, failure(api.CodeContainmentUnknown, "cannot close unstarted stderr capture owner"))
			}
		}
	}()
	defer diagnostic.freeze()
	cmd.Stdin, cmd.Stdout = payload.stdin, stdout
	cmd.SysProcAttr = nativeGateAttributes(payload.UID, payload.GID, int(cgroup.Fd()))
	cgroupBefore := readNativeCgroupSnapshot(int(cgroup.Fd()))
	lifetime := newNativeSpawnLifetime()
	// This process-local barrier is never sealed into a bootstrap payload.
	// Worker preparation uses it to durably distinguish validated inputs from
	// an attempt that may already have created a native process.
	if payload.beforeSpawn != nil {
		if err := payload.beforeSpawn(); err != nil {
			return nil, err
		}
	}
	if err := startInNetworkNamespaceVerified(cmd, network, lifetime, binding.runtimePath()); err != nil {
		return nil, err
	}
	g := &nativeGate{workerJournal: payload.workerJournal, command: cmd, pidfd: -1, innerFD: -1, release: releaseWrite, token: payload.Token, done: make(chan struct{}), stderr: diagnostic, spawnLifetime: lifetime,
		cgroupFD: int(cgroup.Fd()), cgroupBefore: cgroupBefore}
	defer func() { g.cgroupFD = -1 }() // Startup diagnostics borrow it only until cgroup.Close.
	g.pidfd, err = unix.PidfdOpen(cmd.Process.Pid, 0)
	if err != nil {
		killErr := cmd.Process.Kill()
		waitErr := cmd.Wait()
		lifetime.observedWait(cmd.ProcessState)
		var exited *exec.ExitError
		if killErr != nil || waitErr != nil && !errors.As(waitErr, &exited) {
			return nil, failure(api.CodeContainmentUnknown, "unpinable created gate could not be reaped")
		}
		return nil, failure(api.CodeContainmentUnknown, "cannot pin created gate lifetime")
	}
	unix.CloseOnExec(g.pidfd)
	if err := g.startWaitOwner(); err != nil {
		killErr := cmd.Process.Kill()
		waitErr := cmd.Wait()
		lifetime.observedWait(cmd.ProcessState)
		closeErr := unix.Close(g.pidfd)
		var exited *exec.ExitError
		if killErr != nil || closeErr != nil || waitErr != nil && !errors.As(waitErr, &exited) {
			return nil, failure(api.CodeContainmentUnknown, "unwatched native gate could not be collected")
		}
		return nil, err
	}
	stderrInStarter = false
	defer func() {
		if resultErr != nil {
			g.Close()
		}
	}()
	g.generation, err = processGeneration(cmd.Process.Pid, bootID)
	if err != nil {
		return nil, err
	}
	// Close the helper's duplicate of the child socket before waiting. EOF and
	// helper loss must remain meaningful; no unused producer end is retained.
	if err := childFile.Close(); err != nil {
		return nil, failure(api.CodeIntegrity, "cannot close unused readiness end")
	}
	if err := releaseRead.Close(); err != nil {
		return nil, failure(api.CodeIntegrity, "cannot close unused gate read end")
	}
	ready := connection.(*net.UnixConn)
	g.control = ready
	deadline := time.Now().Add(3 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := ready.SetReadDeadline(deadline); err != nil {
		return nil, failure(api.CodeUnavailable, "cannot bound native readiness")
	}
	controls, err := readNativeReadiness(ready, payload.Token, g)
	if err != nil {
		return nil, err
	}
	cred, ack, err := nativeReadinessPeer(controls, payload.CredentialRequired)
	if ack != nil {
		g.execAck = ack
	}
	if err != nil || cred.Pid <= 1 {
		return nil, failure(api.CodeIntegrity, "readiness was sent by a foreign native principal")
	}
	if cred.Uid != payload.UID || cred.Gid != payload.GID {
		allowAndLog("readiness_principal")
	}
	if err := verifyGateMembership(int(cred.Pid), strings.TrimPrefix(cgroupPath, "/sys/fs/cgroup")); err != nil {
		return nil, err
	}
	if err := verifyPrivateNamespaces(int(cred.Pid)); err != nil {
		return nil, err
	}
	innerFD, err := unix.PidfdOpen(int(cred.Pid), 0)
	if err != nil {
		return nil, failure(api.CodeContainmentUnknown, "cannot pin the actual ready bootstrap process")
	}
	unix.CloseOnExec(innerFD)
	g.mu.Lock()
	select {
	case <-g.done:
		g.mu.Unlock()
		unix.Close(innerFD)
		return nil, failure(api.CodeContainmentUnknown, "ready bootstrap ended before lifetime registration")
	default:
		g.innerFD, g.innerPID = innerFD, int(cred.Pid)
		g.mu.Unlock()
	}
	g.innerGeneration, err = processGeneration(g.innerPID, bootID)
	if err != nil {
		return nil, err
	}
	executable, err := os.Open("/proc/" + strconv.Itoa(g.innerPID) + "/exe")
	if err != nil {
		return nil, failure(api.CodeContainmentUnknown, "cannot observe actual fixed bootstrap executable")
	}
	verifyErr, closeErr := verifyExecutableFile(executable, binding.Artifact), executable.Close()
	if verifyErr != nil {
		return nil, verifyErr
	}
	if closeErr != nil {
		return nil, failure(api.CodeContainmentUnknown, "cannot close actual bootstrap executable verification")
	}
	if err := g.innerLifetime(bootID); err != nil {
		return nil, err
	}
	if payload.CredentialRequired || payload.Mode == "credential-probe" {
		actual, err := measureProcessUmask(strconv.Itoa(g.innerPID))
		if err != nil {
			return nil, err
		}
		if actual != 0077 {
			return nil, failure(api.CodeForbidden, "credential bootstrap lacks the measured private umask")
		}
		g.bootstrapUmask = &actual
	}
	return g, nil
}

func verifyGateMembership(pid int, expected string) error {
	membership, err := cgroupMembership(pid)
	if err != nil {
		return failure(api.CodeIntegrity, "ready process is outside the actual leased cgroup")
	}
	if membership != expected {
		allowAndLog("ready_cgroup")
	}
	return nil
}

func verifyPrivateNamespaces(pid int) error {
	for _, namespace := range []string{"mnt", "user", "pid", "ipc", "uts", "net"} {
		host, hostErr := os.Readlink("/proc/self/ns/" + namespace)
		child, childErr := os.Readlink("/proc/" + strconv.Itoa(pid) + "/ns/" + namespace)
		if hostErr != nil || childErr != nil {
			return failure(api.CodeContainmentUnknown, "ready bootstrap lacks an independently observed private namespace")
		}
		if host == child {
			allowAndLog("ready_private_namespace_" + namespace)
		}
	}
	return nil
}

func (m *leaseManager) killContainment(ctx context.Context, record leaseRecord) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	resources, ok := m.resources.(containmentController)
	if !ok {
		return failure(api.CodeContainmentUnknown, "native stop has no kernel containment owner")
	}
	return resources.KillContainment(ctx, record)
}

func (resources *linuxResources) KillContainment(ctx context.Context, record leaseRecord) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	root, err := resources.open(record)
	if err != nil {
		return err
	}
	defer root.Close()
	return writeControl(root, "cgroup.kill", "1")
}
