//go:build linux

package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

const captureSpoolLimit = 8 << 20

type spoolInput struct {
	BindingID api.ID                     `json:"binding_id"`
	Streams   []api.CaptureStreamBinding `json:"streams"`
	MaxBytes  int64                      `json:"max_bytes"`
}

type spoolPosition struct {
	StreamID api.ID     `json:"stream_id"`
	Bytes    int64      `json:"bytes"`
	SHA256   api.Digest `json:"sha256"`
	PipeEOF  bool       `json:"pipe_eof"`
}

// PipeEOF is an OS read result, never a capture.closed/AppendCapture receipt.
// There are deliberately no service-acknowledged offsets in this local marker.
type spoolMarker struct {
	BindingID   api.ID          `json:"binding_id"`
	Positions   []spoolPosition `json:"positions"`
	Failure     string          `json:"failure,omitempty"`
	GapStreamID api.ID          `json:"gap_stream_id,omitempty"`
	LostBytes   int64           `json:"lost_bytes,omitempty"`
}

type nativeCapture struct {
	mu      sync.Mutex
	gate    ownedGate
	writers [2]*os.File
	taken   bool
	spool   *os.Root
	binding api.CaptureBinding
	lease   api.HelperLease
	stopErr error
}

func (c *nativeCapture) TakeWriters(ctx context.Context) (*os.File, *os.File, error) {
	if err := c.Observe(ctx); err != nil {
		return nil, nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.taken || c.writers[0] == nil || c.writers[1] == nil {
		return nil, nil, failure(api.CodeConflict, "capture write ends are one-use and already assigned")
	}
	c.taken = true
	left, right := c.writers[0], c.writers[1]
	c.writers = [2]*os.File{}
	return left, right, nil
}

func (c *nativeCapture) Observe(ctx context.Context) error {
	c.mu.Lock()
	stopErr := c.stopErr
	c.mu.Unlock()
	if stopErr != nil {
		return stopErr
	}
	observation, err := c.gate.Observe(ctx, api.ProcessHandle{ID: c.binding.ProducerID, Target: c.binding.Target,
		ContainmentID: c.lease.ContainmentID, Generation: c.binding.ProducerGeneration})
	if err != nil {
		return err
	}
	native, ok := c.gate.(*nativeGate)
	if !ok || native.innerGeneration != c.binding.ProducerGeneration {
		return failure(api.CodeContainmentUnknown, "capture producer lacks its actual executable lifetime")
	}
	if observation.State == "exited" {
		return c.cleanExit(observation)
	}
	return native.innerLifetime(c.binding.BootID)
}

// Both durable pipe EOFs and a successful native wait end local production.
// Only authenticated drain can acknowledge the retained outside job.
func (c *nativeCapture) cleanExit(observation api.ProcessObservation) error {
	marker, err := readSpool(c.spool, c.binding)
	if err != nil {
		return err
	}
	if observation.State != "exited" || observation.ExitCode == nil || *observation.ExitCode != 0 || observation.Signal != nil ||
		marker.Failure != "" || len(marker.Positions) != 2 || !marker.Positions[0].PipeEOF || !marker.Positions[1].PipeEOF {
		return failure(api.CodeContainmentUnknown, "registered capture producer ended before clean pipe EOF; retain spool and record the gap through authenticated ingress")
	}
	return nil
}

func (c *nativeCapture) producerEnded(ctx context.Context, stop func() error) {
	observation, err := c.gate.Stop(ctx, api.ProcessHandle{ID: c.binding.ProducerID, Target: c.binding.Target,
		ContainmentID: c.lease.ContainmentID, Generation: c.binding.ProducerGeneration})
	if err == nil {
		err = c.cleanExit(observation)
	}
	if err == nil {
		return
	}
	if stopErr := stop(); stopErr != nil {
		err = failure(api.CodeContainmentUnknown, "capture producer failed and containment stop could not be measured")
	}
	c.mu.Lock()
	c.stopErr = err
	c.mu.Unlock()
}

func (c *nativeCapture) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var failures []error
	for index, file := range c.writers {
		if file != nil {
			failures = append(failures, file.Close())
			c.writers[index] = nil
		}
	}
	failures = append(failures, c.gate.Close())
	// Spools survive Close and process loss. They cannot be discarded as an
	// acknowledgement, nor can their outside UID be reused by allocation.
	return errors.Join(failures...)
}

func (m *leaseManager) captureWriters(ctx context.Context, record leaseRecord) (*os.File, *os.File, error) {
	if err := m.requireActive(record, storageReady); err != nil {
		return nil, nil, err
	}
	if record.Spec == nil || record.Spec.Plan == nil {
		return nil, nil, failure(api.CodeIntegrity, "agent has no retained capture plan")
	}
	binding := record.Spec.Plan.Capture
	if binding.Status == "registered" {
		if _, err := m.reconcileCapture(ctx, binding); err != nil {
			return nil, nil, err
		}
		return m.captures[binding.ID].TakeWriters(ctx)
	}
	if binding.Status != "refused" {
		return nil, nil, failure(api.CodeIntegrity, "agent has no explicit capture disposition")
	}
	if record.Spec.Plan.CapturePolicy == nil {
		return nil, nil, failure(api.CodeIntegrity, "capture refusal has no retained D6 policy")
	}
	if err := api.ValidateCapturePolicy(binding, *record.Spec.Plan.CapturePolicy); err != nil {
		return nil, nil, err
	}
	left, err := os.OpenFile("/dev/null", os.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, failure(api.CodePrerequisite, "refused capture cannot open nonblocking discard")
	}
	right, err := os.OpenFile("/dev/null", os.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		left.Close()
		return nil, nil, failure(api.CodePrerequisite, "refused capture cannot open stderr discard")
	}
	return left, right, nil
}

func captureSupervisor(ctx context.Context, binding installation, manifestRef api.BlobRef) (api.Executable, error) {
	data, err := readProtected(filepath.Join("/etc/laneboss-v2/boot", binding.Config+".json"), api.MaxFrameBytes)
	if err != nil {
		return api.Executable{}, err
	}
	var catalog bootCatalog
	if err := decodeStrict(data, &catalog); err != nil {
		return api.Executable{}, err
	}
	base := filepath.Join(filepath.Dir(binding.binaryPath()), "runtime", binding.Config)
	if catalog.Schema != "laneboss.boot-catalog.v2" || catalog.Revision != api.ContractRevision || catalog.Config != binding.Config ||
		catalog.RuntimeManifest != manifestRef || catalog.LaunchEnrollment == nil || catalog.LaunchEnrollmentFile != filepath.Join(base, "launch-enrollment.json") {
		return api.Executable{}, failure(api.CodeIntegrity, "capture enrollment differs from protected boot catalog")
	}
	enrollment, manifest, err := loadLaunchEnrollment(ctx, binding, manifestRef, *catalog.LaunchEnrollment)
	if err != nil {
		return api.Executable{}, err
	}
	if enrollment.Supervisor == nil {
		return api.Executable{}, failure(api.CodeUnsupported, "no outside capture supervisor is enrolled")
	}
	if enrollment.Supervisor.SHA256 != manifest.Artifact.SHA256 || manifest.Bootstrap.SHA256 != manifest.Artifact.SHA256 {
		return api.Executable{}, failure(api.CodeUnsupported, "outside capture supervisor does not implement this release's fixed spool entry")
	}
	return *enrollment.Supervisor, nil
}

func (m *leaseManager) registerNativeCapture(ctx context.Context, record *leaseRecord, registration captureRegistration) (_ api.CaptureBinding, _ bool, resultErr error) {
	check := "capture_registration"
	defer func() { helperCheck(&resultErr, check) }()
	if err := m.requireActive(*record, storageReady); err != nil {
		return api.CaptureBinding{}, false, err
	}
	check = "capture_supervisor"
	supervisor, err := captureSupervisor(ctx, m.binding, registration.Worker.RuntimeManifest)
	if err != nil {
		return api.CaptureBinding{}, false, err
	}
	records, err := m.records()
	if err != nil {
		return api.CaptureBinding{}, false, err
	}
	check = "capture_uid"
	used := map[uint32]bool{record.Lease.UID: true, m.binding.Service.UID: true}
	for _, item := range records {
		for _, job := range item.DataJobs {
			if job.State != "collected" {
				used[job.Lease.UID] = true
			}
		}
		if item.Phase != "released" && item.Phase != "aborted" {
			used[item.Lease.UID] = true
		}
		for _, capture := range item.Captures {
			if captureReservesUID(capture) {
				used[capture.Native.Lease.UID] = true
			}
		}
	}
	reserveArchiveUIDs(records, used)
	var account account
	for _, candidate := range m.binding.Lanes {
		if !used[candidate.UID] {
			account = candidate
			break
		}
	}
	if account.UID == 0 {
		return api.CaptureBinding{}, false, failure(api.CodeUnavailable, "outside capture needs a separate free installed UID")
	}
	id, err := randomID("capture-")
	if err != nil {
		return api.CaptureBinding{}, false, err
	}
	producer, err := randomID("capture-producer-")
	if err != nil {
		return api.CaptureBinding{}, false, err
	}
	containment, err := randomID("capture-cg-")
	if err != nil {
		return api.CaptureBinding{}, false, err
	}
	r := registration.Reservation
	binding := api.CaptureBinding{ID: id, Config: r.Config, ReservationID: r.ID, Target: r.Target, LaunchID: r.LaunchID,
		HelperLeaseID: record.Lease.ID, OperationID: r.OperationID, RequestID: r.RequestID, RequestedBy: r.RequestedBy,
		Generation: record.Lease.EndpointGeneration, Status: "registered", WorkerLeaseID: registration.Worker.ID,
		EffectID: registration.Worker.EffectID, ProducerID: producer, BootID: m.bootID, Supervisor: &supervisor}
	for _, stream := range []string{"stdout", "stderr"} {
		streamID, err := randomID("stream-")
		if err != nil {
			return api.CaptureBinding{}, false, err
		}
		pipeID, err := randomID("pipe-")
		if err != nil {
			return api.CaptureBinding{}, false, err
		}
		binding.Streams = append(binding.Streams, api.CaptureStreamBinding{ID: streamID, PipeID: pipeID, Stream: stream})
	}
	lease := api.HelperLease{ID: id, UID: account.UID, GID: account.GID, ContainmentID: containment, EndpointGeneration: record.Lease.EndpointGeneration}
	entry := captureJournal{Registration: registration, Binding: binding, Native: &captureNativeJournal{Phase: "preparing", Lease: lease, BindingID: id}}
	record.Captures = append(record.Captures, entry)
	if err := m.save(*record); err != nil {
		return api.CaptureBinding{}, true, err
	}
	// Every failure after this point retains the attempt. No fallback capture
	// disposition or replacement producer can overwrite its ownership.
	check = "capture_cgroup"
	outside := leaseRecord{Lease: lease, Request: record.Request, Phase: "reserved"}
	if err := m.resources.Ensure(ctx, outside); err != nil {
		return api.CaptureBinding{}, true, err
	}
	outside.Phase = "active"
	outside.Spec = &specRegistration{Handoff: api.PreparedSpecHandoff{Spec: api.LaunchSpec{RuntimeManifest: registration.Worker.RuntimeManifest}}}
	check = "capture_runtime"
	_, mounts, err := m.gateMounts(ctx, outside)
	if err != nil {
		return api.CaptureBinding{}, true, err
	}
	defer func() {
		for _, mount := range mounts {
			mount.file.Close()
		}
	}()
	check = "capture_spool"
	spool, files, err := createCaptureSpool(m.binding, id)
	if err != nil {
		return api.CaptureBinding{}, true, err
	}
	var reads, writes [2]*os.File
	retained := false
	defer func() {
		if !retained {
			for _, file := range writes {
				if file != nil {
					file.Close()
				}
			}
			spool.Close()
		}
	}()
	for index := range reads {
		reads[index], writes[index], err = os.Pipe()
		if err != nil {
			for _, file := range append(reads[:], writes[:]...) {
				if file != nil {
					file.Close()
				}
			}
			for _, file := range files {
				file.Close()
			}
			spool.Close()
			return api.CaptureBinding{}, true, failure(api.CodePrerequisite, "cannot create helper-owned capture pipes")
		}
	}
	defer func() {
		for _, file := range reads {
			file.Close()
		}
		for _, file := range files {
			file.Close()
		}
	}()
	token, err := randomID("spool-start-")
	if err != nil {
		return api.CaptureBinding{}, true, err
	}
	payload := gatePayload{Config: m.binding.Config, Mode: "capture-spool", GateID: id, Token: string(token), UID: lease.UID, GID: lease.GID,
		Budget: record.Request.Budget, Capture: &spoolInput{BindingID: id, Streams: binding.Streams, MaxBytes: min(captureSpoolLimit, int64(record.Request.Budget.DiskBytes))}}
	discard, err := os.OpenFile("/dev/null", os.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return api.CaptureBinding{}, true, failure(api.CodePrerequisite, "capture diagnostics discard unavailable")
	}
	defer discard.Close()
	inherited := append([]*os.File{reads[0], reads[1]}, files...)
	check = "capture_gate"
	gate, err := startNativeGate(ctx, m.binding, outside, payload, mounts, discard, discard, inherited, nil, m.bootID)
	if err != nil {
		for _, file := range writes {
			file.Close()
		}
		spool.Close()
		return api.CaptureBinding{}, true, err
	}
	native := gate.(*nativeGate)
	binding.ProducerGeneration = native.innerGeneration
	if err := api.ValidateCaptureBinding(binding); err != nil {
		gate.Close()
		return api.CaptureBinding{}, true, err
	}
	live := &nativeCapture{gate: gate, writers: writes, spool: spool, binding: binding, lease: lease}
	if m.captures == nil {
		m.captures = map[api.ID]ownedCapture{}
	}
	m.captures[id] = live
	retained = true
	check = "capture_publish"
	entry.Binding, entry.Native.PID, entry.Native.Phase = binding, native.innerPID, "registered"
	record.Captures[len(record.Captures)-1] = entry
	if err := m.save(*record); err != nil {
		live.Close()
		return api.CaptureBinding{}, true, err
	}
	if err := m.setCaptureDeadline(native, outside, registration.Worker.ExpiresAt); err != nil {
		live.Close()
		return api.CaptureBinding{}, true, err
	}
	if err := gate.Release(); err != nil {
		return api.CaptureBinding{}, true, err
	}
	// A full/unreadable spool or lost producer stops the original run. The
	// marker and exact bytes remain; no local result pretends Append committed.
	agentRecord := *record
	go func() {
		live.producerEnded(context.Background(), func() error { return m.killContainment(context.Background(), agentRecord) })
	}()
	return binding, true, nil
}

func (m *leaseManager) setCaptureDeadline(native *nativeGate, outside leaseRecord, deadline api.Timestamp) error {
	expires, err := time.Parse(time.RFC3339Nano, string(deadline))
	if err != nil {
		return failure(api.CodeIntegrity, "capture worker expiry changed")
	}
	native.wallMS, native.kill = max(int64(1), time.Until(expires).Milliseconds()), func() error { return m.killContainment(context.Background(), outside) }
	return nil
}

func createCaptureSpool(binding installation, id api.ID) (*os.Root, []*os.File, error) {
	base := filepath.Join(binding.statePath(), "spools")
	if err := os.Mkdir(base, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, nil, failure(api.CodePrerequisite, "cannot create private capture spool parent")
	}
	if err := privateDirectory(base, 0, 0700); err != nil {
		return nil, nil, err
	}
	path := filepath.Join(base, string(id))
	if err := os.Mkdir(path, 0700); err != nil {
		return nil, nil, failure(api.CodeContainmentUnknown, "capture spool already exists or cannot be created; no replacement")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, nil, failure(api.CodeContainmentUnknown, "cannot pin new capture spool")
	}
	var files []*os.File
	for _, name := range []string{"stdout", "stderr", "marker"} {
		file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
		if err != nil {
			for _, file := range files {
				file.Close()
			}
			root.Close()
			return nil, nil, failure(api.CodeIntegrity, "cannot create exclusive capture spool files")
		}
		files = append(files, file)
	}
	parent, err := root.Open(".")
	if err != nil {
		return nil, nil, failure(api.CodeIntegrity, "cannot sync private spool directory")
	}
	syncErr, closeErr := parent.Sync(), parent.Close()
	if syncErr != nil || closeErr != nil {
		return nil, nil, failure(api.CodeIntegrity, "private spool directory sync failed")
	}
	ancestor, err := os.Open(base)
	if err != nil {
		return nil, nil, failure(api.CodeIntegrity, "cannot sync capture spool identity parent")
	}
	syncErr, closeErr = ancestor.Sync(), ancestor.Close()
	if syncErr != nil || closeErr != nil {
		return nil, nil, failure(api.CodeIntegrity, "capture spool identity parent sync failed")
	}
	return root, files, nil
}

// Fixed descriptor grammar: input 3, release 4, readiness 5, stdout/stderr
// reads 6/7, their private spool files 8/9, and the retained failure/EOF marker 10.
func runCaptureBootstrap(payload gatePayload) error {
	input := payload.Capture
	if input == nil || input.BindingID != payload.GateID || len(input.Streams) != 2 || input.MaxBytes < 1 || input.MaxBytes > captureSpoolLimit || len(payload.Argv)+len(payload.Environment) != 0 {
		return failure(api.CodeInvalid, "capture bootstrap lacks its bounded fixed pipe binding")
	}
	for _, fd := range []int{6, 7} {
		var info unix.Stat_t
		if unix.Fstat(fd, &info) != nil || info.Mode&unix.S_IFMT != unix.S_IFIFO {
			return failure(api.CodeIntegrity, "capture read end is not an inherited helper pipe")
		}
	}
	for _, fd := range []int{8, 9, 10} {
		var info unix.Stat_t
		if unix.Fstat(fd, &info) != nil || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Size != 0 || info.Nlink != 1 {
			return failure(api.CodeIntegrity, "capture spool is not an exclusive empty inherited file")
		}
	}
	runtime.LockOSThread()
	if err := confineBootstrap(payload); err != nil {
		return err
	}
	if err := unix.CloseRange(3, ^uint(0), unix.CLOSE_RANGE_CLOEXEC); err != nil {
		return failure(api.CodePrerequisite, "cannot protect capture descriptor inheritance")
	}
	ready := func() error {
		if err := unix.Send(5, []byte(payload.Token), 0); err != nil {
			return failure(api.CodeContainmentUnknown, "capture readiness owner is unavailable")
		}
		if err := waitForGateRelease(payload.Token); err != nil {
			return err
		}
		if err := unix.Close(5); err != nil {
			return failure(api.CodeIntegrity, "cannot close capture startup channel")
		}
		return nil
	}
	return spoolPipesReady(*input, [2]*os.File{os.NewFile(6, "capture-stdout"), os.NewFile(7, "capture-stderr")},
		[2]*os.File{os.NewFile(8, "spool-stdout"), os.NewFile(9, "spool-stderr")}, os.NewFile(10, "spool-marker"), ready)
}

func spoolPipes(input spoolInput, reads, outputs [2]*os.File, marker *os.File) error {
	return spoolPipesReady(input, reads, outputs, marker, nil)
}

func spoolPipesReady(input spoolInput, reads, outputs [2]*os.File, marker *os.File, ready func() error) error {
	defer marker.Close()
	for _, file := range append(reads[:], outputs[:]...) {
		defer file.Close()
	}
	state := spoolMarker{BindingID: input.BindingID}
	for _, stream := range input.Streams {
		state.Positions = append(state.Positions, spoolPosition{StreamID: stream.ID, SHA256: digestBytes(nil)})
	}
	contents := [2][]byte{}
	persistLocked := func() error {
		data, err := json.Marshal(state)
		if err != nil || len(data) > 4096 {
			return failure(api.CodeIntegrity, "capture marker exceeds bound")
		}
		if err := marker.Truncate(0); err != nil {
			return failure(api.CodeIntegrity, "cannot retain capture marker")
		}
		if n, err := marker.WriteAt(data, 0); err != nil || n != len(data) {
			return failure(api.CodeIntegrity, "cannot write exact capture marker")
		}
		if err := marker.Sync(); err != nil {
			return failure(api.CodeIntegrity, "cannot sync capture marker")
		}
		return nil
	}
	persist := func() error { return captureSpoolUpdate(marker, persistLocked) }
	if err := persist(); err != nil {
		return err
	}
	if ready != nil {
		if err := ready(); err != nil {
			return err
		}
	}
	fds := []unix.PollFd{{Fd: int32(reads[0].Fd()), Events: unix.POLLIN}, {Fd: int32(reads[1].Fd()), Events: unix.POLLIN}}
	var used int64
	buffer := make([]byte, 32<<10)
	for !state.Positions[0].PipeEOF || !state.Positions[1].PipeEOF {
		if _, err := unix.Poll(fds, -1); err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			state.Failure = "pipe_poll"
			if saveErr := persist(); saveErr != nil {
				return saveErr
			}
			return failure(api.CodeContainmentUnknown, "capture pipe observation failed")
		}
		for index := range fds {
			if state.Positions[index].PipeEOF || fds[index].Revents == 0 {
				continue
			}
			n, err := unix.Read(int(fds[index].Fd), buffer)
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if err != nil {
				state.Failure = "pipe_read"
				if saveErr := persist(); saveErr != nil {
					return saveErr
				}
				return failure(api.CodeContainmentUnknown, "capture pipe read failed")
			}
			if n == 0 {
				state.Positions[index].PipeEOF = true
				fds[index].Fd = -1
				if err := persist(); err != nil {
					return err
				}
				continue
			}
			if int64(n) > input.MaxBytes-used {
				state.Failure, state.GapStreamID, state.LostBytes = "spool_full", state.Positions[index].StreamID, int64(n)
				if err := persist(); err != nil {
					return err
				}
				return failure(api.CodeUnavailable, "capture spool is full; unacknowledged bytes retained")
			}
			position := &state.Positions[index]
			if err := captureSpoolUpdate(marker, func() error {
				if written, err := outputs[index].WriteAt(buffer[:n], position.Bytes); err != nil || written != n {
					state.Failure = "spool_write"
					if saveErr := persistLocked(); saveErr != nil {
						return saveErr
					}
					return failure(api.CodeIntegrity, "capture exact range write failed")
				}
				if err := outputs[index].Sync(); err != nil {
					return failure(api.CodeIntegrity, "capture range sync failed")
				}
				contents[index] = append(contents[index], buffer[:n]...)
				used += int64(n)
				position.Bytes += int64(n)
				position.SHA256 = digestBytes(contents[index])
				return persistLocked()
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

// A read-back is bounded and compares actual retained bytes with the marker.
// It supplies no authenticated store acknowledgement or EOF event.
func readSpool(root *os.Root, binding api.CaptureBinding) (spoolMarker, error) {
	var marker spoolMarker
	file, err := root.OpenFile("marker", os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return marker, failure(api.CodeContainmentUnknown, "capture marker is unavailable")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, 4097))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(data) > 4096 || decodeStrict(data, &marker) != nil || marker.BindingID != binding.ID || len(marker.Positions) != len(binding.Streams) {
		return marker, failure(api.CodeContainmentUnknown, "capture marker is incomplete or foreign")
	}
	for index, stream := range binding.Streams {
		position := marker.Positions[index]
		if position.StreamID != stream.ID || position.Bytes < 0 || position.Bytes > captureSpoolLimit {
			return marker, failure(api.CodeIntegrity, "capture spool range differs")
		}
		file, err := root.OpenFile(stream.Stream, os.O_RDONLY|unix.O_NOFOLLOW, 0)
		if err != nil {
			return marker, failure(api.CodeContainmentUnknown, "capture range file is unavailable")
		}
		bytes, readErr := io.ReadAll(io.LimitReader(file, captureSpoolLimit+1))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || int64(len(bytes)) != position.Bytes || digestBytes(bytes) != position.SHA256 {
			return marker, failure(api.CodeIntegrity, "capture spool bytes differ from retained range digest")
		}
	}
	return marker, nil
}
