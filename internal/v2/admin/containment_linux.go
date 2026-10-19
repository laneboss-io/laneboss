//go:build linux

package admin

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func (m *leaseManager) containment(ctx context.Context, request containmentQuery) (containmentTicket, error) {
	defer helperStage(ctx, "containment")()
	if err := contextError(ctx); err != nil {
		return containmentTicket{}, err
	}
	if !validID(request.LeaseID) {
		return containmentTicket{}, failure(api.CodeInvalid, "invalid containment lease query")
	}
	record, parent, err := m.containmentRecord(ctx, request.LeaseID, request.Opened)
	if err != nil {
		return containmentTicket{}, err
	}
	if request.Opened && record.Gate != nil && record.Gate.State == "opening" && !m.releasedForAuthentication(ctx, record) {
		// An attempt without a successful native release must finish before it
		// can authenticate. A released peer instead uses the live cgroup below:
		// its first RPC may precede the exec that open_gate is still awaiting.
		notifier := m.gateOpenNotifier(ctx, request.LeaseID)
		resume := lendHelperOperation(ctx)
		waitErr := m.waitForGateOpen(ctx, notifier)
		resume()
		if waitErr != nil {
			return containmentTicket{}, waitErr
		}
		record, parent, err = m.containmentRecord(ctx, request.LeaseID, request.Opened)
		if err != nil {
			return containmentTicket{}, err
		}
	}
	if record.BootID != m.bootID || record.Phase != "active" || record.Revoked || record.Spec == nil {
		return containmentTicket{}, failure(api.CodeContainmentUnknown, "containment has no current registered spec")
	}
	if request.Opened && !openedContainment(record) && !m.releasedForAuthentication(ctx, record) {
		return containmentTicket{}, failure(api.CodeUnauthenticated, "peer containment has no consumed open gate")
	}
	path := filepath.Join(m.binding.cgroupPath(), string(record.Lease.ContainmentID))
	finishPath := helperStage(ctx, "cgroup_path")
	if err := protectedPath(path, true); err != nil {
		finishPath()
		return containmentTicket{}, err
	}
	finishPath()
	finishOpen := helperStage(ctx, "cgroup_open")
	file, err := os.Open(path)
	finishOpen()
	if err != nil {
		return containmentTicket{}, failure(api.CodeContainmentUnknown, "cannot pin helper-created containment")
	}
	defer file.Close()
	finishIdentity := helperStage(ctx, "cgroup_identity")
	info, err := cgroupIdentity(file)
	finishIdentity()
	if err != nil {
		return containmentTicket{}, err
	}
	ticket := containmentTicket{Kind: api.EndpointLane, Config: m.binding.Config, Lease: record.Lease, Target: record.SpecReceipt.Target,
		LaunchID: record.Spec.Handoff.Spec.LaunchID, BootID: record.BootID, Generation: record.Lease.EndpointGeneration,
		Device: strconv.FormatUint(uint64(info.Dev), 10), Inode: strconv.FormatUint(info.Ino, 10)}
	for _, job := range parent.DataJobs {
		if job.Lease.ID == request.LeaseID {
			ticket.Kind, ticket.WorkerLeaseID, ticket.StageID = api.EndpointWorker, job.Reg.Worker.ID, job.Reg.Request.StageID
			ticket.ParentLeaseID, ticket.ParentContainmentID, ticket.ParentLaunchID = parent.Lease.ID, parent.Lease.ContainmentID, job.Reg.Reservation.LaunchID
			break
		}
	}
	if parent.Archive != nil && parent.Archive.Worker != nil && parent.Archive.Worker.Lease.ID == request.LeaseID {
		w := parent.Archive.Worker
		ticket.Kind, ticket.WorkerLeaseID, ticket.StageID = api.EndpointWorker, w.Reg.Job.Lease.ID, w.Reg.Job.ID
		ticket.ParentLeaseID, ticket.ParentContainmentID, ticket.ParentLaunchID = parent.Lease.ID, parent.Lease.ContainmentID, parent.Archive.LaunchID
	}
	for _, w := range parent.Judges {
		if w.Lease.ID != request.LeaseID {
			continue
		}
		ticket.Kind, ticket.WorkerLeaseID, ticket.StageID = api.EndpointWorker, w.Reg.Lease.ID, w.Reg.Lease.ID
		ticket.ParentLeaseID, ticket.ParentContainmentID = parent.Lease.ID, parent.Lease.ContainmentID
		if parent.Spec != nil {
			ticket.ParentLaunchID = parent.Spec.Handoff.Spec.LaunchID
		}
		break
	}
	for _, w := range parent.Usages {
		if w.Lease.ID != request.LeaseID {
			continue
		}
		ticket.Kind, ticket.WorkerLeaseID, ticket.StageID = api.EndpointWorker, w.Reg.Job.Lease.ID, w.Reg.Job.ID
		ticket.ParentLeaseID, ticket.ParentContainmentID, ticket.ParentLaunchID = parent.Lease.ID, parent.Lease.ContainmentID, w.Reg.Job.Input.Request.LaunchID
		break
	}
	for _, w := range parent.Channels {
		if w.Lease.ID != request.LeaseID {
			continue
		}
		ticket.Kind, ticket.WorkerLeaseID, ticket.StageID = api.EndpointWorker, w.Reg.Job.Lease.ID, w.Reg.Job.Lease.ID
		ticket.ParentLeaseID, ticket.ParentContainmentID = parent.Lease.ID, parent.Lease.ContainmentID
		if parent.Spec != nil {
			ticket.ParentLaunchID = parent.Spec.Handoff.Spec.LaunchID
		} else if len(parent.LaunchAllocations) != 0 {
			ticket.ParentLaunchID = parent.LaunchAllocations[len(parent.LaunchAllocations)-1].Reservation.LaunchID
		}
		break
	}
	return ticket, nil
}

func openedContainment(record leaseRecord) bool {
	return !record.Revoked && record.Gate != nil && record.Gate.State == "opened" && record.Gate.Permit != nil
}

func cgroupIdentity(file *os.File) (unix.Stat_t, error) {
	var info unix.Stat_t
	var filesystem unix.Statfs_t
	if file == nil || unix.Fstat(int(file.Fd()), &info) != nil || unix.Fstatfs(int(file.Fd()), &filesystem) != nil ||
		info.Mode&unix.S_IFMT != unix.S_IFDIR || info.Uid != 0 || info.Mode&0022 != 0 || filesystem.Type != unix.CGROUP2_SUPER_MAGIC {
		return info, failure(api.CodeContainmentUnknown, "containment descriptor is not a protected real cgroup-v2 directory")
	}
	return info, nil
}

func duplicateDirectory(file *os.File) (*os.File, error) {
	descriptor, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, failure(api.CodeContainmentUnknown, "cannot duplicate containment identity")
	}
	return os.NewFile(uintptr(descriptor), "pinned-containment"), nil
}

// The helper has already journaled the lease, spec and closed gate. Pin that
// exact allocation before sending open_gate: registration after the reply can
// lose the race with the agent's first connection to the service.
func (s *Service) bindAgentContainment(ctx context.Context, registration gateOpenRegistration) error {
	if err := validateOpenCommit(registration.Request, registration.Binding, s.deps.Config); err != nil {
		return err
	}
	record := registration.Binding.Record
	if record.Kind != "agent" {
		return failure(api.CodeInvalid, "agent release requires an agent launch binding")
	}
	var ticket containmentTicket
	if err := s.call(ctx, "containment", containmentQuery{LeaseID: record.UIDLeaseID}, &ticket); err != nil {
		return err
	}
	if ticket.Kind != api.EndpointLane || ticket.Lease.ID != record.UIDLeaseID || ticket.Lease.UID != record.HostUID ||
		ticket.Lease.ContainmentID != record.ContainmentID || ticket.Target != record.Target || ticket.LaunchID != record.ID {
		return failure(api.CodeIntegrity, "agent containment differs from its committed launch")
	}
	file, err := os.Open(filepath.Join(s.binding.cgroupPath(), string(ticket.Lease.ContainmentID)))
	if err != nil {
		return failure(api.CodeContainmentUnknown, "cannot open helper-created agent containment")
	}
	defer file.Close()
	return s.RegisterContainment(ctx, api.ContainmentBinding{Config: s.deps.Config, Lease: ticket.Lease, Target: ticket.Target,
		Backend: "linux-bwrap-landlock", BootID: ticket.BootID, Generation: ticket.Generation, Directory: file})
}

func (s *Service) RegisterContainment(ctx context.Context, binding api.ContainmentBinding) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if binding.Config != s.deps.Config || binding.Backend != "linux-bwrap-landlock" || binding.Revoked || binding.Directory == nil ||
		validateLease(binding.Lease, s.binding) != nil || !validID(binding.Target.LifeID) || binding.Target.Run == 0 {
		return failure(api.CodeInvalid, "invalid helper-created containment registration")
	}
	var ticket containmentTicket
	if err := s.call(ctx, "containment", containmentQuery{LeaseID: binding.Lease.ID}, &ticket); err != nil {
		return err
	}
	if ticket.Config != binding.Config || ticket.Lease != binding.Lease || ticket.Target != binding.Target ||
		ticket.BootID != binding.BootID || ticket.Generation != binding.Generation || ticket.Generation != s.binding.Generation {
		return failure(api.CodeIntegrity, "containment registration differs from the helper journal")
	}
	info, err := cgroupIdentity(binding.Directory)
	if err != nil {
		return err
	}
	if strconv.FormatUint(uint64(info.Dev), 10) != ticket.Device || strconv.FormatUint(info.Ino, 10) != ticket.Inode {
		allowAndLog("containment_cgroup_inode")
	}
	owned, err := duplicateDirectory(binding.Directory)
	if err != nil {
		return err
	}
	binding.Directory = owned
	s.registryMu.Lock()
	defer s.registryMu.Unlock()
	if s.containments == nil {
		s.containments = map[api.ID]*containmentEntry{}
	}
	if previous := s.containments[binding.Lease.ContainmentID]; previous != nil {
		closeErr := owned.Close()
		if closeErr != nil {
			return failure(api.CodeIntegrity, "cannot close duplicate registration")
		}
		if previous.Binding.Revoked || previous.Ticket != ticket {
			return failure(api.CodeConflict, "containment identity is already registered or revoked")
		}
		return nil
	}
	s.containments[binding.Lease.ContainmentID] = &containmentEntry{Binding: binding, Ticket: ticket}
	return nil
}

func (s *Service) ResolveContainment(ctx context.Context, facts api.PeerFacts, endpoint api.InstalledBinding) (api.ContainmentBinding, error) {
	if err := contextError(ctx); err != nil {
		return api.ContainmentBinding{}, err
	}
	if err := api.ValidateBinding(endpoint, s.deps.Config, s.binding.Release.Version); err != nil {
		return api.ContainmentBinding{}, err
	}
	id := facts.ContainmentID
	if id == "" {
		// Initial native peer verification has not resolved a containment ID
		// yet. Select only a registered group whose actual kernel membership
		// matches this configuration; all native identity/inode checks below
		// still apply before returning it to the verifier.
		membership, err := cgroupMembership(facts.HostPID)
		if err != nil {
			return api.ContainmentBinding{}, err
		}
		id = api.ID(filepath.Base(membership))
		if membership != strings.TrimPrefix(filepath.Join(s.binding.cgroupPath(), string(id)), "/sys/fs/cgroup") {
			return api.ContainmentBinding{}, failure(api.CodeUnauthenticated, "peer is outside the registered helper containment tree")
		}
	}
	// Worker endpoints and held handoffs keep their original control route.
	// Ordinary lane rechecks can hold a store RLock
	// while stop_gate waits on the broker's store read; they use the metadata
	// reader under the lent operation lock instead of the occupied listener.
	binding, ticket, err := s.refreshContainment(id, func(query containmentQuery) (containmentTicket, error) {
		var current containmentTicket
		if endpoint.Class != api.EndpointLane || s.workerSession(ctx) != nil {
			err := s.call(ctx, "containment", query, &current)
			return current, err
		}
		err := s.call(ctx, "containment_live", query, &current)
		return current, err
	})
	if err != nil {
		return api.ContainmentBinding{}, err
	}
	retained := false
	defer func() {
		if !retained {
			binding.Directory.Close()
		}
	}()
	if endpoint.Backend != binding.Backend || !ticket.endpointMatches(endpoint) || endpoint.Target == nil || *endpoint.Target != binding.Target ||
		endpoint.LaunchID != ticket.LaunchID || endpoint.EndpointGeneration != binding.Lease.EndpointGeneration ||
		endpoint.InstallationGeneration != s.binding.Generation || endpoint.ArtifactSHA256 != s.binding.Artifact.SHA256 ||
		endpoint.ServiceUID != s.binding.Service.UID || endpoint.ServiceGID != s.binding.Service.GID ||
		facts.HostUID != binding.Lease.UID || facts.HostGID != binding.Lease.GID {
		return api.ContainmentBinding{}, failure(api.CodeUnauthenticated, "peer or installed endpoint differs from registered containment")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || strings.TrimSpace(string(boot)) != binding.BootID {
		return api.ContainmentBinding{}, failure(api.CodeContainmentUnknown, "containment is from another kernel boot")
	}
	info, err := cgroupIdentity(binding.Directory)
	if err != nil {
		return api.ContainmentBinding{}, err
	}
	path := filepath.Join(s.binding.cgroupPath(), string(binding.Lease.ContainmentID))
	var current unix.Stat_t
	if err := unix.Lstat(path, &current); err != nil || strconv.FormatUint(uint64(info.Dev), 10) != ticket.Device || strconv.FormatUint(info.Ino, 10) != ticket.Inode ||
		current.Dev != info.Dev || current.Ino != info.Ino {
		return api.ContainmentBinding{}, failure(api.CodeContainmentUnknown, "registered containment was removed or replaced")
	}
	membership := strings.TrimPrefix(path, "/sys/fs/cgroup")
	if err := verifyContainedProcess(ctx, facts, binding.BootID, membership); err != nil {
		return api.ContainmentBinding{}, err
	}
	s.registryMu.Lock()
	entry := s.containments[id]
	currentEntry := entry != nil && !entry.Binding.Revoked && entry.Ticket == ticket
	s.registryMu.Unlock()
	if !currentEntry {
		return api.ContainmentBinding{}, failure(api.CodeUnauthenticated, "containment was revoked during native peer verification")
	}
	retained = true
	return binding, nil
}

// Keep the registry available while the authenticated helper is responding.
// A duplicate is obtained only after checking that the same entry survived.
func (s *Service) refreshContainment(id api.ID, refresh func(containmentQuery) (containmentTicket, error)) (api.ContainmentBinding, containmentTicket, error) {
	s.registryMu.Lock()
	entry := s.containments[id]
	if entry == nil || entry.Binding.Revoked {
		s.registryMu.Unlock()
		return api.ContainmentBinding{}, containmentTicket{}, failure(api.CodeUnauthenticated, "peer containment is absent or revoked")
	}
	ticket := entry.Ticket
	s.registryMu.Unlock()
	current, err := refresh(containmentQuery{LeaseID: ticket.Lease.ID, Opened: true})
	if err != nil {
		return api.ContainmentBinding{}, containmentTicket{}, err
	}
	s.registryMu.Lock()
	defer s.registryMu.Unlock()
	if s.containments[id] != entry || entry.Binding.Revoked || entry.Ticket != ticket || current != ticket {
		return api.ContainmentBinding{}, containmentTicket{}, failure(api.CodeUnauthenticated, "containment changed during helper resolution")
	}
	binding := entry.Binding
	owned, err := duplicateDirectory(binding.Directory)
	if err != nil {
		return api.ContainmentBinding{}, containmentTicket{}, err
	}
	binding.Directory = owned
	return binding, ticket, nil
}

func (s *Service) RevokeContainment(ctx context.Context, id api.ID) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if !validID(id) {
		return failure(api.CodeInvalid, "invalid containment revocation")
	}
	var matched bool
	err := s.call(ctx, "containment_revoke", struct {
		ID api.ID `json:"id"`
	}{id}, &matched)
	return s.finishRevocation(id, matched, err)
}

// This retains the repository's native Linux boot-id:start-ticks convention.
// Each descendant is checked against its own start ticks, never the leader's.
func processGeneration(pid int, bootID string) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", failure(api.CodeUnauthenticated, "cannot observe native process generation")
	}
	open, close := bytes.IndexByte(data, '('), bytes.LastIndexByte(data, ')')
	if open < 1 || close <= open || strings.TrimSpace(string(data[:open])) != strconv.Itoa(pid) {
		return "", failure(api.CodeUnauthenticated, "native process generation has invalid shape")
	}
	fields := strings.Fields(string(data[close+1:]))
	if len(fields) < 20 || fields[0] == "Z" || fields[0] == "X" {
		return "", failure(api.CodeUnauthenticated, "native process is not live")
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || ticks == 0 {
		return "", failure(api.CodeUnauthenticated, "native process start is unknown")
	}
	return bootID + ":" + fields[19], nil
}

func verifyContainedProcess(ctx context.Context, facts api.PeerFacts, bootID, membership string) error {
	return verifyContainedProcessWithPoll(ctx, facts, bootID, membership, unix.Poll)
}

func verifyContainedProcessWithPoll(ctx context.Context, facts api.PeerFacts, bootID, membership string, poll func([]unix.PollFd, int) (int, error)) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if facts.HostPID <= 1 {
		return failure(api.CodeUnauthenticated, "invalid peer kernel PID")
	}
	descriptor, err := unix.PidfdOpen(facts.HostPID, 0)
	if err != nil {
		return failure(api.CodeUnauthenticated, "cannot pin actual containment peer lifetime")
	}
	defer unix.Close(descriptor)
	unix.CloseOnExec(descriptor)
	before, err := processGeneration(facts.HostPID, bootID)
	if err != nil {
		return err
	}
	if before != facts.ProcessGeneration {
		return failure(api.CodeUnauthenticated, "peer process generation changed")
	}
	actual, err := cgroupMembership(facts.HostPID)
	if err != nil {
		return err
	}
	if actual != membership {
		return failure(api.CodeUnauthenticated, "peer is outside its pinned cgroup")
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", facts.HostPID))
	if err != nil {
		return failure(api.CodeUnauthenticated, "peer credential observations are unavailable")
	}
	found := 0
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok || key != "Uid" && key != "Gid" {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) != 4 {
			return failure(api.CodeUnauthenticated, "peer credentials have invalid shape")
		}
		expected := facts.HostUID
		if key == "Gid" {
			expected = facts.HostGID
		}
		for _, field := range fields {
			value, err := strconv.ParseUint(field, 10, 32)
			if err != nil || uint32(value) != expected {
				return failure(api.CodeUnauthenticated, "peer kernel credentials drifted")
			}
		}
		found++
	}
	after, err := processGeneration(facts.HostPID, bootID)
	if err != nil {
		return err
	}
	if found != 2 || after != before {
		return failure(api.CodeUnauthenticated, "peer identity changed during containment resolution")
	}
	fds := []unix.PollFd{{Fd: int32(descriptor), Events: unix.POLLIN}}
	count, err := pollHelperLifetime(fds, poll)
	if err != nil || count != 0 || fds[0].Revents != 0 {
		return failure(api.CodeUnauthenticated, "peer lifetime ended during containment resolution")
	}
	return nil
}
