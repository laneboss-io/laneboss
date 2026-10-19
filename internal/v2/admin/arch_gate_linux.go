//go:build linux

package admin

import (
	"context"
	"os"
	"path/filepath"

	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Service) bindArchiveContainment(ctx context.Context, r archiveReg) error {
	var lease api.HelperLease
	if err := s.call(ctx, "archive_lease", r, &lease); err != nil {
		return err
	}
	var ticket containmentTicket
	if err := s.call(ctx, "containment", containmentQuery{LeaseID: lease.ID}, &ticket); err != nil {
		return err
	}
	file, err := os.Open(filepath.Join(s.binding.cgroupPath(), string(lease.ContainmentID)))
	if err != nil {
		return failure(api.CodeContainmentUnknown, "cannot open native archive containment")
	}
	defer file.Close()
	return s.RegisterContainment(ctx, api.ContainmentBinding{Config: s.deps.Config, Lease: lease, Target: ticket.Target, Backend: "linux-bwrap-landlock", BootID: ticket.BootID, Generation: ticket.Generation, Directory: file})
}

// Archive has no projected workspace or credentials. All content travels over
// the fixed worker-only socket and is authorized by the single writer.
func (m *leaseManager) startArchiveGate(ctx context.Context, p leaseRecord, w archiveWorker) (ownedGate, error) {
	if w.Spec == nil || w.Endpoint == nil || w.Gate == nil {
		return nil, failure(api.CodeIntegrity, "archive gate lacks its sealed handoff")
	}
	if err := validateArchiveSeal(archiveSeal{Reg: w.Reg, Spec: *w.Spec, Endpoint: *w.Endpoint, Input: w.Input}, m.binding, true); err != nil {
		return nil, err
	}
	child := archiveChild(p, w)
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
		return nil, failure(api.CodeForbidden, "archive runtime may expose only its private worker endpoint")
	}
	executable := ""
	for _, object := range manifest.Objects {
		if object.ID == w.Reg.Job.Plan.Executable.ID && object.Content.SHA256 == w.Reg.Job.Plan.Executable.SHA256 && object.Mode == 0555 {
			executable = nativeRuntimeTarget(object)
		}
	}
	if executable == "" || w.Reg.Job.Plan.Executable.SHA256 != m.binding.Artifact.SHA256 || w.Reg.Job.Plan.Executable.Version != m.binding.Release.Version {
		return nil, failure(api.CodeIntegrity, "archive executable differs from the enrolled fixed release")
	}
	endpoint, err := sealedBootstrap(*w.Endpoint)
	if err != nil {
		return nil, err
	}
	if err := endpoint.Chmod(0444); err != nil {
		endpoint.Close()
		return nil, err
	}
	mounts = append(mounts, &nativeMount{file: endpoint, target: "/runtime/laneboss-worker.json", sealed: true})
	inputRef := w.Reg.Job.Lease.Input
	if inputRef.Class != "archive_input" && !((w.Reg.Job.Lease.Kind == "export" || w.Reg.Job.Lease.Kind == "test") && inputRef.Class == "manifest") {
		return nil, failure(api.CodeIntegrity, "archive gate has another input class")
	}
	// Reuse the exact-byte memfd implementation after the archive class check.
	input, err := sealWorkerInput(w.Input, inputRef)
	if err != nil {
		return nil, err
	}
	mounts = append(mounts, &nativeMount{file: input, target: workerInputPath, sealed: true})
	socket, err := m.dataSocket(dataJob{Reg: dataReg{Worker: w.Reg.Job.Lease}})
	if err != nil {
		return nil, err
	}
	mounts = append(mounts, socket)
	token, err := randomID("release-")
	if err != nil {
		return nil, err
	}
	argv := append([]string{}, w.Reg.Job.Plan.Argv...)
	argv[0] = executable
	argv = append(argv, "--config", m.binding.Config)
	payload := gatePayload{workerJournal: os.Stderr, Config: m.binding.Config, Mode: "prepared-gate", GateID: w.Gate.Prepared.GateID, Token: string(token), UID: w.Lease.UID, GID: w.Lease.GID, Argv: argv, CWD: "/job", Budget: w.Reg.Job.Plan.Budget, Environment: []string{"HOME=/job", "PATH=/runtime", "TMPDIR=/tmp", "XDG_RUNTIME_DIR=/run/lane", "GOMAXPROCS=1"}}
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
		return nil, failure(api.CodeContainmentUnknown, "archive gate has no native wait owner")
	}
	if err := native.retainWorkerFiles(input, endpoint); err != nil {
		live.Close()
		return nil, err
	}
	native.wallMS, native.kill = w.Reg.Job.Plan.Budget.WallMS, func() error { return m.killContainment(context.Background(), child) }
	return live, nil
}
