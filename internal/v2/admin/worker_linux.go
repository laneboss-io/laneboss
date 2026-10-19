//go:build linux

package admin

import (
	"context"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/fdpath"
)

// The host socket is derived from the issued worker lease. Its inaccessible
// service-owned parent permits a distinct UID to use only the pinned namespace
// projection. The service must still authenticate native identity each frame.
func (m *leaseManager) dataSocket(job dataJob) (*nativeMount, error) {
	service, err := workerServiceBinding(m.binding)
	if err != nil {
		return nil, err
	}
	return m.dataSocketAtBinding(job, service)
}

func (m *leaseManager) dataSocketAtBinding(job dataJob, service api.InstalledBinding) (*nativeMount, error) {
	base := filepath.Join(filepath.Dir(service.Socket), "workers")
	return pinWorkerSocket(base, m.binding.Service, job.Reg.Worker.ID)
}

func pinWorkerSocket(base string, service account, worker api.ID) (*nativeMount, error) {
	if !validID(worker) {
		return nil, failure(api.CodeIntegrity, "worker socket requires its issued lease identity")
	}
	if err := workerSocketChain(base, service); err != nil {
		return nil, err
	}
	parent, err := pinNativeMount(base, "", true, false, false, service.UID, service.GID)
	if err != nil {
		return nil, err
	}
	defer parent.file.Close()
	var owner unix.Stat_t
	if unix.Fstat(int(parent.file.Fd()), &owner) != nil || owner.Mode&07777 != 0700 {
		return nil, failure(api.CodeIntegrity, "worker endpoint parent is not private to its service")
	}
	fd, err := fdpath.Open(int(parent.file.Fd()), string(worker)+".sock", &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC | unix.O_NOFOLLOW, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return nil, failure(api.CodePrerequisite, "service has not installed this worker's private endpoint")
	}
	file := os.NewFile(uintptr(fd), "worker-endpoint-inode")
	var info unix.Stat_t
	if unix.Fstat(fd, &info) != nil || info.Mode&unix.S_IFMT != unix.S_IFSOCK {
		file.Close()
		return nil, failure(api.CodeIntegrity, "worker endpoint differs from its protected socket owner or mode")
	}
	if info.Mode&07777 != 0666 || info.Uid != service.UID || info.Gid != service.GID || info.Nlink != 1 {
		allowAndLog("worker_endpoint_owner")
	}
	return &nativeMount{file: file, target: "/runtime/laneboss-worker.sock", socket: true}, nil
}

func workerServiceBinding(binding installation) (api.InstalledBinding, error) {
	var service api.InstalledBinding
	raw, err := readProtected(filepath.Join("/etc/laneboss-v2/bindings", binding.Config+".json"), api.MaxFrameBytes)
	if err != nil {
		return service, err
	}
	if err := decodeStrict(raw, &service); err != nil {
		return service, err
	}
	if err := api.ValidateBinding(service, binding.Config, binding.Release.Version); err != nil {
		return service, err
	}
	if service.Class != api.EndpointHuman || service.ServiceUID != binding.Service.UID || service.ServiceGID != binding.Service.GID ||
		service.InstallationGeneration != binding.Generation || service.ArtifactSHA256 != binding.Artifact.SHA256 {
		return service, failure(api.CodeIntegrity, "worker endpoint installation differs from its helper")
	}
	return service, nil
}

func workerSocketChain(base string, service account) error {
	for path := base; ; path = filepath.Dir(path) {
		fd, err := fdpath.Open(unix.AT_FDCWD, path, &unix.OpenHow{Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
		if path == "/" { // The fixed root is the authority, not a walked component.
			fd, err = unix.Open("/", nativeMountParentFlags, 0)
		}
		if err != nil {
			return failure(api.CodeContainmentUnknown, "worker socket ancestor is missing or linked")
		}
		var info unix.Stat_t
		statErr, closeErr := unix.Fstat(fd, &info), unix.Close(fd)
		uid, gid, mode := uint32(0), uint32(0), uint32(0755)
		if path == base || path == filepath.Dir(base) {
			uid, gid, mode = service.UID, service.GID, 0700
		}
		if statErr != nil || closeErr != nil {
			return failure(api.CodeIntegrity, "worker socket ancestor owner or mode differs")
		}
		if info.Uid != uid || info.Gid != gid || info.Mode&07777 != mode {
			allowAndLog("worker_socket_ancestor")
		}
		if path == "/" {
			return nil
		}
	}
}

func (s *Service) bindDataContainment(ctx context.Context, q api.StorageProjectionRequest) error {
	lease, err := s.DataWorkerLease(ctx, q)
	if err != nil {
		return err
	}
	var ticket containmentTicket
	if err := s.call(ctx, "containment", containmentQuery{LeaseID: lease.ID}, &ticket); err != nil {
		return err
	}
	file, err := os.Open(filepath.Join(s.binding.cgroupPath(), string(lease.ContainmentID)))
	if err != nil {
		return failure(api.CodeContainmentUnknown, "cannot open helper-created worker containment")
	}
	defer file.Close()
	return s.RegisterContainment(ctx, api.ContainmentBinding{Config: s.deps.Config, Lease: lease, Target: ticket.Target, Backend: "linux-bwrap-landlock", BootID: ticket.BootID, Generation: ticket.Generation, Directory: file})
}

func (m *leaseManager) startDataGate(ctx context.Context, parent leaseRecord, job dataJob) (_ ownedGate, resultErr error) {
	defer helperCheck(&resultErr, "gate_prepare")
	pins := m.dataPins[job.Projection.OpenToken]
	if pins == nil {
		return nil, failure(api.CodeContainmentUnknown, "worker root descriptors were lost")
	}
	if err := checkDataPins(ctx, parent, job, pins); err != nil {
		return nil, err
	}
	if job.Spec == nil || job.Endpoint == nil || job.Gate == nil || job.Lease.UID == parent.Lease.UID {
		return nil, failure(api.CodeForbidden, "worker gate lacks its own sealed native job")
	}
	if err := validateDataSeal(dataSeal{Reg: job.Reg, Spec: *job.Spec, Endpoint: *job.Endpoint, Input: job.Input}, m.binding); err != nil {
		return nil, err
	}
	child := dataChild(parent, job)
	manifest, mounts, err := m.gateMounts(ctx, child)
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, mount := range mounts {
			mount.file.Close()
		}
	}()
	if len(manifest.Bindings) != 0 {
		return nil, failure(api.CodeUnsupported, "materialization runtime may project only its own private worker endpoint")
	}
	executable := ""
	for _, object := range manifest.Objects {
		if object.ID == job.Reg.Plan.Executable.ID && object.Content.SHA256 == job.Reg.Plan.Executable.SHA256 && object.Mode == 0555 {
			executable = nativeRuntimeTarget(object)
		}
	}
	if executable == "" || job.Reg.Plan.Executable.SHA256 != m.binding.Artifact.SHA256 || job.Reg.Plan.Executable.Version != m.binding.Release.Version {
		return nil, failure(api.CodeIntegrity, "fixed worker executable is not the enrolled installed release")
	}
	for i, target := range []string{"/job/source", "/job/workspace", "/job/home"} {
		fd, err := unix.FcntlInt(pins.roots[i].Fd(), unix.F_DUPFD_CLOEXEC, 3)
		if err != nil {
			return nil, failure(api.CodeContainmentUnknown, "cannot duplicate held worker root")
		}
		mounts = append(mounts, &nativeMount{file: os.NewFile(uintptr(fd), "worker-root"), target: target, directory: true, writable: i > 0})
	}
	for _, copy := range pins.copies {
		for i, file := range []*os.File{copy.Source, copy.Destination} {
			fd, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 3)
			if err != nil {
				return nil, failure(api.CodeContainmentUnknown, "cannot duplicate pinned copy root")
			}
			target := "/job/source-" + string(copy.Projection.Grant.ID)
			if i == 1 {
				target = "/job/copy-" + string(copy.Projection.Grant.ID)
			}
			mounts = append(mounts, &nativeMount{file: os.NewFile(uintptr(fd), "worker-copy-root"), target: target, directory: true, writable: i == 1})
		}
	}
	endpoint, err := sealedBootstrap(*job.Endpoint)
	if err != nil {
		return nil, err
	}
	if err := endpoint.Chmod(0444); err != nil {
		endpoint.Close()
		return nil, err
	}
	mounts = append(mounts, &nativeMount{file: endpoint, target: "/runtime/laneboss-worker.json", sealed: true})
	input, err := sealWorkerInput(job.Input, job.Reg.Worker.Input)
	if err != nil {
		return nil, err
	}
	mounts = append(mounts, &nativeMount{file: input, target: workerInputPath, sealed: true})
	socket, err := m.dataSocket(job)
	if err != nil {
		return nil, err
	}
	mounts = append(mounts, socket)
	token, err := randomID("release-")
	if err != nil {
		return nil, err
	}
	argv := append([]string{}, job.Reg.Plan.Argv...)
	argv[0] = executable
	// The frozen plan names the fixed worker grammar; the helper supplies its
	// trusted installation context, just as it resolves the executable path.
	argv = append(argv, "--config", m.binding.Config)
	payload := gatePayload{workerJournal: os.Stderr, Config: m.binding.Config, Mode: "prepared-gate", GateID: job.Gate.Prepared.GateID, Token: string(token), UID: job.Lease.UID, GID: job.Lease.GID,
		Argv: argv, CWD: "/job", Budget: job.Reg.Plan.Budget, Environment: []string{"HOME=/job/home", "PATH=/runtime", "TMPDIR=/tmp", "XDG_RUNTIME_DIR=/run/lane", "GOMAXPROCS=1"}}
	payload.beforeSpawn = func() error {
		if !unstartedDataGate(job) {
			return failure(api.CodeContainmentUnknown, "data gate has already crossed its native start barrier")
		}
		for index, retained := range parent.DataJobs {
			if retained.Lease.ID == job.Lease.ID && retained.Reg.Request == job.Reg.Request {
				job.Gate.State = "preparing"
				parent.DataJobs[index] = job
				return m.save(parent)
			}
		}
		return failure(api.CodeIntegrity, "data native start lost its original preparation journal")
	}
	// Output acknowledgement travels through authenticated WorkerResult. No
	// runner stdout string can stand in for that receipt or the wait status.
	output, err := os.OpenFile("/dev/null", os.O_WRONLY, 0)
	if err != nil {
		return nil, err
	}
	defer output.Close()
	live, err := startNativeGate(ctx, m.binding, child, payload, mounts, output, output, nil, nil, m.bootID)
	if err != nil {
		return nil, err
	}
	native, ok := live.(*nativeGate)
	if !ok {
		live.Close()
		return nil, failure(api.CodeContainmentUnknown, "worker gate has no native wait owner")
	}
	if err := native.retainWorkerFiles(input, endpoint); err != nil {
		live.Close()
		return nil, err
	}
	native.wallMS, native.kill = job.Reg.Plan.Budget.WallMS, func() error { return m.killContainment(context.Background(), child) }
	return live, nil
}
