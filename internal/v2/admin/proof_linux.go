//go:build linux

package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func isolationLoopback(ctx context.Context, nonce api.ID) (*net.TCPListener, error) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, failure(api.CodePrerequisite, "isolation host network control cannot listen")
	}
	failed := true
	defer func() {
		if failed {
			listener.Close()
		}
	}()
	deadline := time.Now().Add(time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := listener.SetDeadline(deadline); err != nil {
		return nil, err
	}
	dialer := net.Dialer{Deadline: deadline}
	client, err := dialer.DialContext(ctx, "tcp4", listener.Addr().String())
	if err != nil {
		return nil, failure(api.CodePrerequisite, "isolation host network control cannot connect")
	}
	defer client.Close()
	if err := client.SetDeadline(deadline); err != nil {
		return nil, err
	}
	peer, err := listener.AcceptTCP()
	if err != nil {
		return nil, failure(api.CodePrerequisite, "isolation host network control cannot accept")
	}
	defer peer.Close()
	if err := peer.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if n, err := client.Write([]byte(nonce)); err != nil || n != len(nonce) {
		return nil, failure(api.CodePrerequisite, "isolation host network control cannot send")
	}
	data := make([]byte, len(nonce))
	if _, err := io.ReadFull(peer, data); err != nil || string(data) != string(nonce) {
		return nil, failure(api.CodeIntegrity, "isolation host network control changed its bytes")
	}
	failed = false
	return listener, nil
}

func isolationPool(binding installation, records []leaseRecord) (account, error) {
	used := map[uint32]bool{0: true, binding.Service.UID: true}
	reserveArchiveUIDs(records, used)
	for _, record := range records {
		if record.Phase != "released" && record.Phase != "aborted" {
			used[record.Lease.UID] = true
		}
		for _, job := range record.DataJobs {
			if job.State != "collected" {
				used[job.Lease.UID] = true
			}
		}
		for _, capture := range record.Captures {
			if capture.Native != nil {
				used[capture.Native.Lease.UID] = true
			}
		}
	}
	for _, candidate := range binding.Lanes {
		if !used[candidate.UID] {
			return candidate, nil
		}
	}
	return account{}, failure(api.CodeUnavailable, "independent isolation probe requires a free installed pool account")
}

func isolationPipeEmpty(file *os.File) error {
	raw, err := file.SyscallConn()
	if err != nil {
		return failure(api.CodeContainmentUnknown, "cannot pin isolation output pipe")
	}
	var pollErr error
	if err := raw.Control(func(fd uintptr) {
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		count, err := unix.Poll(fds, 0)
		if err != nil || count != 0 || fds[0].Revents != 0 {
			pollErr = failure(api.CodeIntegrity, "isolation canary produced output before native release")
		}
	}); err != nil {
		return failure(api.CodeContainmentUnknown, "cannot observe isolation output pipe")
	}
	if pollErr != nil {
		return pollErr
	}
	return nil
}

func readIsolationPipe(ctx context.Context, file *os.File) ([]byte, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, failure(api.CodeInvalid, "isolation pipe reader requires a deadline")
	}
	if err := file.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(file, api.MaxFrameBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > api.MaxFrameBytes {
		return nil, failure(api.CodeContainmentUnknown, "isolation output pipe is incomplete or unbounded")
	}
	return raw, nil
}

// This is a helper-owned probe reservation, not an invented lifecycle effect.
// It uses the same native resource, runtime and closed-gate implementations.
func (m *leaseManager) measureIsolation(parent context.Context, runtimeRef api.BlobRef) (_ isolationPacket, resultErr error) {
	// Reserve bounded collection and the outer helper's refusal write time.
	ctx, cancel := context.WithTimeout(parent, 8*time.Second)
	defer cancel()
	store, ok := m.store.(*fileLeaseStore)
	resources, native := m.resources.(*linuxResources)
	if !ok || !native || store.owner != 0 || m.bootID == "" {
		return isolationPacket{}, failure(api.CodePrerequisite, "isolation evidence requires the installed native helper and retained store")
	}
	if runtimeRef.Class != "manifest" || !validID(runtimeRef.ID) || !validDigest(runtimeRef.SHA256) || runtimeRef.Bytes < 1 || runtimeRef.Bytes > api.MaxFrameBytes {
		return isolationPacket{}, failure(api.CodeInvalid, "isolation evidence requires its installed runtime pin")
	}
	// Bind to the protected installation, not an alternate caller-selected pin.
	bootRaw, err := readProtected(filepath.Join("/etc/laneboss-v2/boot", m.binding.Config+".json"), api.MaxFrameBytes)
	if err != nil {
		return isolationPacket{}, err
	}
	var catalog bootCatalog
	if err := decodeStrict(bootRaw, &catalog); err != nil {
		return isolationPacket{}, err
	}
	if catalog.RuntimeManifest != runtimeRef {
		return isolationPacket{}, failure(api.CodeForbidden, "isolation runtime differs from protected installation")
	}
	records, err := m.records()
	if err != nil {
		return isolationPacket{}, err
	}
	selected, err := isolationPool(m.binding, records)
	if err != nil {
		return isolationPacket{}, err
	}
	if err := checkAccount(selected); err != nil {
		return isolationPacket{}, err
	}
	if err := probeAppArmor(); err != nil {
		return isolationPacket{}, err
	}
	if err := unix.Unshare(0); err != nil {
		return isolationPacket{}, failure(api.CodePrerequisite, "outside syscall positive control is unavailable")
	}
	id, err := randomID("probe-")
	if err != nil {
		return isolationPacket{}, err
	}
	nonce, err := randomID("canary-")
	if err != nil {
		return isolationPacket{}, err
	}
	group, err := randomID("probe-cg-")
	if err != nil {
		return isolationPacket{}, err
	}
	if err := store.root.Mkdir("proofs", 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return isolationPacket{}, err
	}
	proofs, err := proofRoot(store.root, "proofs", 0)
	if err != nil {
		return isolationPacket{}, err
	}
	defer proofs.Close()
	if err := proofs.Mkdir(string(id), 0700); err != nil {
		return isolationPacket{}, err
	}
	retained, err := proofRoot(proofs, string(id), 0)
	if err != nil {
		return isolationPacket{}, err
	}
	defer retained.Close()
	lease := api.HelperLease{ID: id, UID: selected.UID, GID: selected.GID, ContainmentID: group, EndpointGeneration: m.binding.Generation}
	held := probeReservation{Schema: "laneboss.isolation-reservation.v1", ID: id, Lease: lease, BootID: m.bootID, Phase: "reserved"}
	if err := proofWrite(retained, "reservation.json", held); err != nil {
		return isolationPacket{}, err
	}
	budget := isolationBudget()
	record := leaseRecord{Lease: lease, Phase: "reserved", BootID: m.bootID, Request: api.HelperLeaseRequest{Budget: budget}, Spec: &specRegistration{Handoff: api.PreparedSpecHandoff{Spec: api.LaunchSpec{RuntimeManifest: runtimeRef}}}}
	var live *nativeGate
	collected := false
	cleanup := func() error {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if live != nil {
			if err := live.Close(); err != nil {
				return err
			}
			if err := m.killContainment(cleanupCtx, record); err != nil {
				return err
			}
			if _, err := live.Stop(cleanupCtx, api.ProcessHandle{}); err != nil {
				return err
			}
			if err := m.waitContainmentEmpty(cleanupCtx, record); err != nil {
				return err
			}
		}
		if err := resources.Quiescent(cleanupCtx, record); err != nil {
			return err
		}
		return resources.Remove(cleanupCtx, record)
	}
	defer func() {
		if !collected {
			if err := cleanup(); err != nil {
				resultErr = errors.Join(resultErr, err)
				return
			}
			held.Phase = "collected"
			if err := proofWrite(retained, "reservation.json", held); err != nil {
				resultErr = errors.Join(resultErr, err)
			}
		}
	}()
	if err := resources.Ensure(ctx, record); err != nil {
		return isolationPacket{}, err
	}
	record.Phase = "active"
	manifest, mounts, err := m.gateMounts(ctx, record)
	if err != nil {
		return isolationPacket{}, err
	}
	defer func() {
		for _, mount := range mounts {
			mount.file.Close()
		}
	}()
	if len(manifest.Bindings) != 0 {
		return isolationPacket{}, failure(api.CodeUnsupported, "isolation probe requires a runtime without unrelated endpoint projections")
	}
	executable := ""
	for _, object := range manifest.Objects {
		if object.ID == manifest.Bootstrap.ID && object.Content.SHA256 == m.binding.Artifact.SHA256 && object.Mode == 0555 {
			executable = nativeRuntimeTarget(object)
		}
	}
	if executable == "" {
		return isolationPacket{}, failure(api.CodeIntegrity, "isolation canary has no pinned installed executable")
	}
	stagePath := laneStagePath(m.binding, id)
	if err := createLaneStage(stagePath, selected.GID); err != nil {
		return isolationPacket{}, err
	}
	stage, err := openStorageRoot(stagePath)
	if err != nil {
		return isolationPacket{}, err
	}
	defer stage.Close()
	if err := stage.Mkdir("work", 0700); err != nil {
		return isolationPacket{}, err
	}
	work, err := stage.Open("work")
	if err != nil {
		return isolationPacket{}, err
	}
	defer work.Close()
	if err := work.Chown(int(selected.UID), int(selected.GID)); err != nil {
		return isolationPacket{}, err
	}
	mounts = append(mounts, &nativeMount{file: work, target: "/work/main", directory: true, writable: true})
	listener, err := isolationLoopback(ctx, nonce)
	if err != nil {
		return isolationPacket{}, err
	}
	defer listener.Close()
	input := isolationInput{Config: m.binding.Config, Nonce: nonce, UID: selected.UID, GID: selected.GID, Port: listener.Addr().(*net.TCPAddr).Port}
	inputBytes, err := json.Marshal(input)
	if err != nil {
		return isolationPacket{}, err
	}
	sealed, err := sealedBootstrap(input)
	if err != nil {
		return isolationPacket{}, err
	}
	if err := sealed.Chmod(0444); err != nil {
		sealed.Close()
		return isolationPacket{}, err
	}
	mounts = append(mounts, &nativeMount{file: sealed, target: isolationDescriptorPath, sealed: true})
	readProbe, err := stage.OpenFile("read-probe", os.O_CREATE|os.O_EXCL|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return isolationPacket{}, err
	}
	defer readProbe.Close()
	if n, err := readProbe.Write(inputBytes); err != nil || n != len(inputBytes) {
		return isolationPacket{}, failure(api.CodeIntegrity, "cannot stage exact canary read probe")
	}
	if err := readProbe.Chmod(0444); err != nil {
		return isolationPacket{}, err
	}
	if err := readProbe.Sync(); err != nil {
		return isolationPacket{}, err
	}
	mounts = append(mounts, &nativeMount{file: readProbe, target: isolationInputPath})
	network, err := newEmptyNetworkNamespace(ctx)
	if err != nil {
		return isolationPacket{}, err
	}
	defer network.Close()
	outRead, outWrite, err := os.Pipe()
	if err != nil {
		return isolationPacket{}, err
	}
	defer outRead.Close()
	defer outWrite.Close()
	errRead, errWrite, err := os.Pipe()
	if err != nil {
		return isolationPacket{}, err
	}
	defer errRead.Close()
	defer errWrite.Close()
	payload := gatePayload{Config: m.binding.Config, Mode: "prepared-gate", GateID: id, Token: string(nonce), UID: selected.UID, GID: selected.GID, Budget: budget,
		Argv: []string{executable, "internal", "helper", "--config", m.binding.Config, "isolation-canary"}, CWD: "/work/main", Environment: []string{"HOME=/work/main", "PATH=/runtime", "TMPDIR=/tmp"}}
	gate, err := startNativeGate(ctx, m.binding, record, payload, mounts, outWrite, errWrite, nil, network, m.bootID)
	if err != nil {
		return isolationPacket{}, err
	}
	live, ok = gate.(*nativeGate)
	if !ok {
		gate.Close()
		return isolationPacket{}, failure(api.CodeContainmentUnknown, "isolation canary has no native wait owner")
	}
	if err := outWrite.Close(); err != nil {
		return isolationPacket{}, err
	}
	if err := errWrite.Close(); err != nil {
		return isolationPacket{}, err
	}
	if err := isolationPipeEmpty(outRead); err != nil {
		return isolationPacket{}, err
	}
	if err := isolationPipeEmpty(errRead); err != nil {
		return isolationPacket{}, err
	}
	var ns, childNS unix.Stat_t
	if unix.Fstat(int(network.Fd()), &ns) != nil || unix.Stat("/proc/"+strconv.Itoa(live.innerPID)+"/ns/net", &childNS) != nil || ns.Dev != childNS.Dev || ns.Ino != childNS.Ino {
		return isolationPacket{}, failure(api.CodeIntegrity, "canary did not inherit the exact helper-owned network namespace")
	}
	groupFile, err := os.Open(filepath.Join(m.binding.cgroupPath(), string(group)))
	if err != nil {
		return isolationPacket{}, err
	}
	identity, identityErr := cgroupIdentity(groupFile)
	closeErr := groupFile.Close()
	if identityErr != nil || closeErr != nil {
		return isolationPacket{}, failure(api.CodeContainmentUnknown, "cannot retain independent canary cgroup identity")
	}
	if err := verifyPrivateNamespaces(live.innerPID); err != nil {
		return isolationPacket{}, err
	}
	limits, err := resources.open(record)
	if err != nil {
		return isolationPacket{}, err
	}
	var measuredLimits [][2]string
	for _, expected := range limitValues(record) {
		actual, err := readControl(limits, expected[0])
		if err != nil || actual != expected[1] {
			limits.Close()
			return isolationPacket{}, failure(api.CodeIntegrity, "isolation cgroup limit changed before release")
		}
		measuredLimits = append(measuredLimits, [2]string{expected[0], actual})
	}
	if err := limits.Close(); err != nil {
		return isolationPacket{}, err
	}
	proof := isolationProof{Schema: "laneboss.isolation-proof.v1", Config: m.binding.Config, BootID: m.bootID, InstallationGeneration: m.binding.Generation, ArtifactSHA256: m.binding.Artifact.SHA256,
		Runtime: runtimeRef, Nonce: nonce, UID: selected.UID, GID: selected.GID, InputSHA256: digestBytes(inputBytes), HostControl: listener != nil,
		ClosedGate: live.release != nil && !live.released, PrivateNamespaces: ns.Ino == childNS.Ino && ns.Dev == childNS.Dev, Limits: measuredLimits,
		CgroupDevice: strconv.FormatUint(uint64(identity.Dev), 10), CgroupInode: strconv.FormatUint(identity.Ino, 10),
		NamespaceDevice: strconv.FormatUint(uint64(ns.Dev), 10), NamespaceInode: strconv.FormatUint(ns.Ino, 10),
		Peer: api.PeerFacts{HostUID: selected.UID, HostGID: selected.GID, HostPID: live.innerPID, ProcessGeneration: live.innerGeneration, ContainmentID: group}}
	if err := live.Release(); err != nil {
		return isolationPacket{}, err
	}
	var typed *api.Error
	proof.SecondReleaseRefused = errors.As(live.Release(), &typed) && typed.Code == api.CodeConflict
	select {
	case <-ctx.Done():
		return isolationPacket{}, contextError(ctx)
	case <-live.done:
	}
	handle := api.ProcessHandle{ID: id, Target: api.LifeRef{LifeID: id, Run: 1}, ContainmentID: group, Generation: live.Generation()}
	proof.Observation, err = live.Observe(ctx, handle)
	if err != nil {
		return isolationPacket{}, err
	}
	if err := resources.Quiescent(ctx, record); err != nil {
		return isolationPacket{}, err
	}
	zero := uint64(0)
	proof.Observation.Survivors = &zero
	stdout, err := readIsolationPipe(ctx, outRead)
	if err != nil {
		return isolationPacket{}, err
	}
	if err := decodeStrict(stdout, &proof.Canary); err != nil {
		return isolationPacket{}, err
	}
	stderr, err := readIsolationPipe(ctx, errRead)
	if err != nil {
		return isolationPacket{}, err
	}
	proof.PipeMarker = string(stderr)
	kernel, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return isolationPacket{}, err
	}
	proof.Kernel = strings.TrimSpace(string(kernel))
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		return isolationPacket{}, failure(api.CodePrerequisite, "cannot measure current Landlock ABI")
	}
	proof.LandlockABI = int(abi)
	if err := cleanup(); err != nil {
		return isolationPacket{}, err
	}
	collected, proof.Collected = true, true
	proof.ObservedAt = gateTimestamp()
	if err := work.Chown(0, 0); err != nil {
		return isolationPacket{}, err
	}
	if err := proofWrite(retained, "proof.json", proof); err != nil {
		return isolationPacket{}, err
	}
	raw, err := proofRead(retained, "proof.json", 0)
	if err != nil {
		return isolationPacket{}, err
	}
	expected, err := json.Marshal(proof)
	if err != nil || string(raw) != string(expected) {
		return isolationPacket{}, failure(api.CodeIntegrity, "isolation proof read-back changed its measured bytes")
	}
	pin := api.BlobRef{ID: id, SHA256: digestBytes(raw), Bytes: int64(len(raw)), Class: "manifest"}
	if _, err := isolationCapabilities(proof, pin, m.binding, runtimeRef, time.Now()); err != nil {
		return isolationPacket{}, err
	}
	held.Phase = "collected"
	if err := proofWrite(retained, "reservation.json", held); err != nil {
		return isolationPacket{}, err
	}
	return isolationPacket{Reference: pin, Bytes: raw}, nil
}
