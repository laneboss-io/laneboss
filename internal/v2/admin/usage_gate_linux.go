//go:build linux

package admin

import (
	"context"
	"os"
	"path/filepath"

	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Service) bindUsageContainment(ctx context.Context, r usageReg) error {
	var lease api.HelperLease
	if err := s.call(ctx, "usage_lease", r, &lease); err != nil {
		return err
	}
	var ticket containmentTicket
	if err := s.call(ctx, "containment", containmentQuery{LeaseID: lease.ID}, &ticket); err != nil {
		return err
	}
	file, err := os.Open(filepath.Join(s.binding.cgroupPath(), string(lease.ContainmentID)))
	if err != nil {
		return failure(api.CodeContainmentUnknown, "cannot pin native usage containment")
	}
	defer file.Close()
	return s.RegisterContainment(ctx, api.ContainmentBinding{Config: s.deps.Config, Lease: lease, Target: ticket.Target, Backend: "linux-bwrap-landlock",
		BootID: ticket.BootID, Generation: ticket.Generation, Directory: file})
}

func (m *leaseManager) startUsageGate(ctx context.Context, parent leaseRecord, w usageNative) (ownedGate, error) {
	if w.Spec == nil || w.Endpoint == nil || w.Gate == nil {
		return nil, failure(api.CodePrerequisite, "usage native gate has no sealed handoff")
	}
	if err := validateUsageSeal(usageSeal{Reg: w.Reg, Spec: *w.Spec, Endpoint: *w.Endpoint, Input: w.Input}, m.binding, true); err != nil {
		return nil, err
	}
	child := usageChild(parent, w)
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
		return nil, failure(api.CodeForbidden, "usage runtime may expose only its private worker endpoint")
	}
	fixture, err := usageFixtureRuntime(manifest, mounts, w.Reg.Job.Input.Request.Executable, m.binding.Config)
	if err != nil {
		return nil, err
	}
	if !fixture {
		return nil, failure(api.CodePrerequisite, "usage runtime requires protected native worker credential projection")
	}
	if err := usageExecutable(mounts, w.Reg.Job.Input.Request.Executable, w.Lease); err != nil {
		return nil, err
	}
	provider, err := m.watchdogProviderMount(manifest, mounts)
	if err != nil {
		return nil, err
	}
	if provider != nil {
		mounts = append(mounts, provider)
	}
	home, err := m.usageHome(w.Lease)
	if err != nil {
		return nil, err
	}
	mounts = append(mounts, home)
	executable := ""
	for _, object := range manifest.Objects {
		if object.ID == w.Reg.Plan.Executable.ID && object.Content.SHA256 == w.Reg.Plan.Executable.SHA256 && object.Mode == 0555 {
			executable = nativeRuntimeTarget(object)
		}
	}
	if executable == "" || w.Reg.Plan.Executable.SHA256 != m.binding.Artifact.SHA256 || w.Reg.Plan.Executable.Version != m.binding.Release.Version {
		return nil, failure(api.CodeIntegrity, "usage worker differs from its installed fixed release")
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
	input, err := sealWorkerInput(w.Input, w.Reg.Job.Lease.Input)
	if err != nil {
		return nil, err
	}
	mounts = append(mounts, &nativeMount{file: input, target: workerInputPath, sealed: true})
	service, err := workerServiceBinding(m.binding)
	if err != nil {
		return nil, err
	}
	socket, err := pinWorkerSocket(filepath.Join(filepath.Dir(service.Socket), "workers"), m.binding.Service, w.Reg.Job.Lease.ID)
	if err != nil {
		return nil, err
	}
	mounts = append(mounts, socket)
	token, err := randomID("release-")
	if err != nil {
		return nil, err
	}
	argv := append([]string{}, w.Reg.Plan.Argv...)
	argv[0] = executable
	argv = append(argv, "--config", m.binding.Config)
	payload := gatePayload{workerJournal: os.Stderr, Config: m.binding.Config, Mode: "prepared-gate", GateID: w.Gate.Prepared.GateID, Token: string(token),
		UID: w.Lease.UID, GID: w.Lease.GID, Argv: argv, CWD: "/job", Budget: w.Reg.Plan.Budget,
		Environment:        []string{"HOME=/job", "PATH=/runtime", "TMPDIR=/tmp", "XDG_RUNTIME_DIR=/run/lane", "GOMAXPROCS=1"},
		CredentialRequired: !fixture && credentialRequired(w.Spec.Handoff.Spec), PreparedID: w.Gate.Prepared.ID, SpecSHA256: w.Spec.Handoff.SpecSHA256}
	if payload.CredentialRequired && m.credentials == nil {
		return nil, failure(api.CodePrerequisite, "usage native credential receiver is not bound")
	}
	var network *os.File
	if len(w.Spec.Handoff.Spec.Grants.Network) != 0 {
		network, err = m.ownedNetwork(parent)
		if err != nil {
			return nil, err
		}
	}
	output, err := os.OpenFile("/dev/null", os.O_WRONLY, 0)
	if err != nil {
		return nil, err
	}
	defer output.Close()
	live, err := startNativeGate(ctx, m.binding, child, payload, mounts, output, output, nil, network, m.bootID)
	if err != nil {
		return nil, err
	}
	native, ok := live.(*nativeGate)
	if !ok {
		live.Close()
		return nil, failure(api.CodeContainmentUnknown, "usage gate has no actual native wait owner")
	}
	if err := native.retainWorkerFiles(input, endpoint); err != nil {
		live.Close()
		return nil, err
	}
	native.wallMS, native.kill = w.Reg.Plan.Budget.WallMS, func() error { return m.killContainment(context.Background(), child) }
	return live, nil
}
