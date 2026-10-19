//go:build linux && laneboss_root_canary && laneboss_gate_integration

package admin

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// The sealed worker metadata/acknowledgement is a prerequisite fixture. The
// fileLeaseStore, source installer, descriptors, ownership return, real child
// wait, UID/cgroup quiescence, Git, publication and cleanup reads are native.
func workspaceProducerFixture(t *testing.T) (*leaseManager, leaseRecord, int, dataMeasure) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("workspace producer canary requires disposable Linux root")
	}
	nonce, err := randomID("")
	if err != nil {
		t.Fatal(err)
	}
	uidPart, err := strconv.ParseUint(string(nonce[:6]), 16, 32)
	if err != nil {
		t.Fatal(err)
	}
	uid := uint32(1000000 + uidPart*2)
	binding := testBinding()
	lanes := []account{{Name: "lb-lane-a", UID: uid, GID: uid}, {Name: "lb-lane-b", UID: uid + 1, GID: uid + 1}}
	m, reg, cache := dataOpenNativeFixture(t, dataOpenFixtureOptions{Config: "workspace-" + string(nonce[:16]), Service: binding.Service, Lanes: lanes})
	reg.ClaimExpires = api.Timestamp(time.Now().Add(3 * time.Minute).UTC().Format(time.RFC3339Nano))
	command := exec.Command("/usr/bin/python3", "-I", "-B", "testdata/source_cache_canary.py", cache, m.binding.statePath())
	command.Env = []string{}
	if raw, err := command.CombinedOutput(); err != nil || string(raw) != "source-cache:changed\n" {
		t.Fatal("workspace source-cache setup failed", err)
	}
	projection, err := m.openData(context.Background(), reg)
	if err != nil {
		t.Fatal(err)
	}
	p, index, err := m.findData(reg.Request)
	if err != nil {
		t.Fatal(err)
	}
	job := p.DataJobs[index]
	pins := m.dataPins[projection.OpenToken]
	t.Cleanup(func() {
		if err := pins.close(); err != nil {
			t.Error(err)
		}
	})
	manifest, err := dataManifest(pins.manifest, reg.Plan.Budget.DiskBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := dataStage(context.Background(), pins.roots[0], pins.roots[1], manifest, job.Lease.UID, job.Lease.GID); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(dataFD(pins.roots[2]), projection.Storage.Home.Home.VendorDirectory)
	if err := errors.Join(os.Mkdir(home, 0700), os.Chown(home, int(job.Lease.UID), int(job.Lease.GID))); err != nil {
		t.Fatal(err)
	}
	output := reg.Inputs.Sources.Project.Object
	output.ID = "workspace-output"
	input := mustCanaryJSON(t, dataInput{Schema: "laneboss.materialize-input.v2", StageID: reg.Request.StageID, Reservation: reg.Reservation,
		Source: reg.Inputs.Sources.Project, Storage: projection, Grants: reg.Grants, Budget: reg.Plan.Budget, Output: output})
	reg.Worker.Input = api.BlobRef{ID: "workspace-input", Class: "materialize_input", SHA256: digestBytes(input), Bytes: int64(len(input))}
	reg.Worker.ConsumedBy, reg.Plan.Input = reg.LaunchID, reg.Worker.Input
	job.Reg = reg
	spec := api.LaunchSpec{ID: "workspace-spec", Kind: "worker", PlanID: reg.Reservation.ID, Worker: &reg.Plan, LaunchID: reg.LaunchID, Target: reg.Worker.Target,
		UIDLeaseID: job.Lease.ID, Backend: "linux-bwrap-landlock", EndpointGeneration: job.Lease.EndpointGeneration, PolicyGeneration: reg.Reservation.PolicyGeneration,
		RuntimeManifest: reg.Worker.RuntimeManifest, Budget: reg.Plan.Budget, Grants: reg.Grants, Materialization: api.Materialization{GrantSetID: reg.Grants.ID, Objects: []api.MaterializedObject{}},
		Injection: api.Injection{Target: reg.Worker.Target, Outcome: "prepared", SlotIDs: []api.ID{}, GrantIDs: []api.ID{}, SourceVersions: []string{}, TaskSecretNames: []string{}, TaskSecretFileNames: []string{}}}
	original := mustCanaryJSON(t, spec)
	cause := p.Request.Cause
	cause.Kind, cause.EffectID = api.InternalHelperRegister, reg.Worker.EffectID
	job.Spec = &specRegistration{Handoff: api.PreparedSpecHandoff{Cause: cause, Config: m.binding.Config, Spec: spec, SpecSHA256: digestBytes(original), OperationID: reg.Reservation.OperationID, RequestID: reg.Reservation.RequestID,
		Original: api.BlobRef{ID: "workspace-spec-bytes", Class: "launch_spec", Bytes: int64(len(original)), SHA256: digestBytes(original)}}, Original: original}
	job.Endpoint = &api.InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision, Protocol: api.Protocol, APISchema: api.SchemaVersion,
		Config: m.binding.Config, Class: api.EndpointWorker, ServiceUID: m.binding.Service.UID, ServiceGID: m.binding.Service.GID, Socket: "/runtime/laneboss-worker.sock",
		Backend: spec.Backend, ServiceVersion: m.binding.Release.Version, ArtifactSHA256: m.binding.Artifact.SHA256, InstallationGeneration: m.binding.Generation, EndpointGeneration: m.binding.Generation,
		LaunchID: reg.LaunchID, Target: &reg.Worker.Target, WorkerLeaseID: reg.Worker.ID}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	m.bootID, p.BootID = strings.TrimSpace(string(boot)), strings.TrimSpace(string(boot))
	cleanupCgroup(t, m.binding, p.Lease.ContainmentID)
	group := cleanupCgroup(t, m.binding, job.Lease.ContainmentID)
	child, hold, generation := cleanupHolder(t, group, job.Lease, p.BootID)
	if err := hold.Close(); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	close(done)
	gate := &nativeGate{command: child, state: child.ProcessState, generation: generation, done: done, released: true, pidfd: -1, innerFD: -1}
	m.gates = map[api.ID]ownedGate{job.Lease.ID: gate}
	m.resources = &linuxResources{binding: m.binding, manager: m}
	prepared := api.PreparedLaunch{ID: "workspace-prepared", GateID: "workspace-gate", Target: reg.Worker.Target, ContainmentID: job.Lease.ContainmentID,
		EndpointGeneration: job.Lease.EndpointGeneration, ProcessGeneration: generation, SpecSHA256: job.Spec.Handoff.SpecSHA256}
	record := api.LaunchRecord{Kind: "worker", ID: reg.LaunchID, Config: m.binding.Config, Actor: api.Actor{Kind: "worker", ID: "workspace-principal"}, Target: reg.Worker.Target,
		StarterChain: append([]api.ID{}, reg.Reservation.StarterChain...),
		UIDLeaseID:   job.Lease.ID, HostUID: job.Lease.UID, ContainmentID: job.Lease.ContainmentID, ProcessGeneration: prepared.ProcessGeneration,
		GrantSetID: reg.Grants.ID, GrantsSHA256: reg.Grants.SHA256, PolicyGeneration: reg.Reservation.PolicyGeneration, EndpointGeneration: prepared.EndpointGeneration}
	identity := api.IdentityCommit{LaunchID: record.ID, EventID: "workspace-bound", RecordSHA256: digestBytes(mustCanaryJSON(t, record)), CommittedSeq: 7}
	job.Gate = &dataGate{Prepared: prepared, PID: child.Process.Pid, State: "opened", Record: &record, Identity: &identity,
		Permit: &api.LaunchPermit{LaunchID: record.ID, PreparedID: prepared.ID, RecordSHA256: identity.RecordSHA256, CommittedSeq: identity.CommittedSeq}}
	job.Input, job.State = input, "opened"
	data := api.LaunchData{ReservationID: reg.Reservation.ID, Target: reg.Reservation.Target, LeaseID: p.Lease.ID, Source: reg.Inputs.Sources.Project, Home: projection.Storage.Home,
		Workspace:       api.Workspace{ID: projection.Storage.WorkspaceID, ProjectID: reg.Inputs.Sources.Project.ProjectID, Base: reg.Inputs.Sources.Project.Base, Branch: "lane/" + string(reg.Reservation.Target.LifeID), LogicalCWD: "/work/main", Snapshot: output},
		Materialization: api.Materialization{GrantSetID: reg.Reservation.GrantSetID, Manifest: output, Objects: []api.MaterializedObject{{GrantID: reg.Inputs.Sources.Project.GrantID, WorkspaceID: projection.Storage.WorkspaceID, SourceIdentity: projection.SourceIdentity, DestinationIdentity: projection.WorkspaceIdentity, SnapshotSHA256: output.SHA256}}}}
	raw := mustCanaryJSON(t, data)
	q := dataMeasure{Reg: reg, Output: raw, Manifest: pins.manifest, Receipt: api.WorkerResultReceipt{LeaseID: reg.Worker.ID, StageID: reg.Request.StageID, Generation: reg.Worker.Generation + 1, CommittedSeq: 11,
		Result: api.BlobRef{ID: "workspace-ack", Class: "worker_result", Bytes: int64(len(raw)), SHA256: digestBytes(raw)}}}
	observation, err := gate.Observe(context.Background(), dataHandle(job))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.resources.Quiescent(context.Background(), dataChild(p, job)); err != nil {
		t.Fatal(err)
	}
	zero := uint64(0)
	observation.Survivors = &zero
	result, err := m.readDataResult(context.Background(), p, job, q, observation)
	if err != nil {
		t.Fatal("workspace fixture did not measure real source and destination bytes", err)
	}
	if err := m.returnData(context.Background(), p, job, q.Manifest); err != nil {
		t.Fatal(err)
	}
	job.State, job.Result = "measured", &result
	p.DataJobs[index] = job
	if err := m.save(p); err != nil {
		t.Fatal("workspace fixture did not retain its measured prerequisite", err)
	}
	t.Cleanup(func() {
		path := workspaceRegistryDirectory(m.binding.Config)
		if err := os.RemoveAll(path); err != nil {
			t.Error(err)
		}
	})
	return m, p, index, q
}

func TestNativeWorkspaceProducer(t *testing.T) {
	m, p, index, q := workspaceProducerFixture(t)
	ctx := context.Background()
	before := p.Storage.Directories[0]
	if err := m.ensureNativeWorkspace(ctx, &p, index, q); err != nil {
		t.Fatal("native workspace producer did not reach protected enrollment", err)
	}
	first := *p.Storage.Workspace
	if first.Phase != "published" || before != p.Storage.Directories[0] {
		t.Fatal("native workspace producer changed the allocated workspace inode")
	}
	if err := m.ensureNativeWorkspace(ctx, &p, index, q); err != nil || !reflect.DeepEqual(first, *p.Storage.Workspace) {
		t.Fatal("native workspace exact retry changed its pins or result", err)
	}
	reloaded, err := m.find(p.Lease.ID)
	if err != nil || !reflect.DeepEqual(reloaded.Storage.Workspace, p.Storage.Workspace) {
		t.Fatal("native workspace enrollment did not survive a real journal reload", err)
	}
	e := first.Enrollment
	root := m.dataPins[p.DataJobs[index].Projection.OpenToken].roots[1]
	if err := unix.Fchown(int(root.Fd()), 0, 0); err != nil {
		t.Fatal(err)
	}
	actual, err := m.dispatchCleanup(ctx, "cleanup_resolve", mustCanaryJSON(t, cleanupQuery{Target: e.Workspace.Target, WorkspaceID: e.Workspace.ID}))
	if err != nil || actual.(api.CleanupWorkspace) != e.Workspace {
		t.Fatal("cleanup did not consume the dynamically produced workspace enrollment", err)
	}
	read, err := inspectNativeWorkspace(ctx, e)
	if err != nil || read.WorktreeState != "present" || read.BranchState != "present" || read.Dirty == nil || *read.Dirty {
		t.Fatal("native workspace has no independently measured clean Git state", err)
	}
	if raw, err := gitSuccess(ctx, e, true, "show", "HEAD:README.md"); err != nil || string(raw) != "retained native source cache bytes\n" {
		t.Fatal("native Git did not import the actual granted source bytes", err)
	}
	if err := os.WriteFile(filepath.Join(dataFD(root), "lane.txt"), []byte("reviewed lane change\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := gitSuccess(ctx, e, true, "add", "--", "lane.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := gitSuccess(ctx, e, true, "-c", "user.name=fixture", "-c", "user.email=fixture", "commit", "--quiet", "-m", "lane change"); err != nil {
		t.Fatal(err)
	}
	actual, err = m.dispatchCleanup(ctx, "cleanup_resolve", mustCanaryJSON(t, cleanupQuery{Target: e.Workspace.Target, WorkspaceID: e.Workspace.ID}))
	if err != nil || actual.(api.CleanupWorkspace).Head == e.Workspace.Head {
		t.Fatal("cleanup did not measure the current lane tip independently of its imported base", err)
	}
}

func TestNativeWorkspaceMeasuredHook(t *testing.T) {
	for _, phase := range []string{"opened", "measured"} {
		t.Run(phase, func(t *testing.T) {
			m, p, index, q := workspaceProducerFixture(t)
			ctx := context.Background()
			if phase == "opened" {
				job := &p.DataJobs[index]
				pins := m.dataPins[job.Projection.OpenToken]
				manifest, err := dataManifest(q.Manifest, q.Reg.Plan.Budget.DiskBytes)
				if err != nil {
					t.Fatal(err)
				}
				if err := dataReturn(ctx, pins.roots[1], manifest, job.Lease.UID, job.Lease.GID); err != nil {
					t.Fatal(err)
				}
				if err := dataReturn(ctx, pins.roots[2], dataHome(*job), job.Lease.UID, job.Lease.GID); err != nil {
					t.Fatal(err)
				}
				if err := setDataParentGroup(pins.parents[1], p.Lease.GID, job.Lease.GID); err != nil {
					t.Fatal(err)
				}
				job.State, job.Result = "opened", nil
				if err := m.save(p); err != nil {
					t.Fatal(err)
				}
			}
			result, err := m.measureData(ctx, q)
			if err != nil {
				t.Fatal("real native measurement did not finish workspace enrollment", err)
			}
			retained, err := m.find(p.Lease.ID)
			if err != nil || retained.Storage.Workspace == nil || retained.Storage.Workspace.Phase != "published" || retained.Storage.Workspace.Result != result.ResultReceipt {
				t.Fatal("successful materialization returned before protected workspace enrollment", err)
			}
			replay, err := m.measureData(ctx, q)
			if err != nil || !reflect.DeepEqual(result, replay) {
				t.Fatal("measured workspace replay changed its original result", err)
			}
		})
	}
}

type workspaceFaultStore struct {
	leaseStorage
	phase  string
	failed bool
}

func (s *workspaceFaultStore) Save(p leaseRecord) error {
	if j := p.Storage.Workspace; j != nil && j.Phase == s.phase && !s.failed {
		s.failed = true
		return errors.New("injected workspace journal write failure")
	}
	return s.leaseStorage.Save(p)
}

func TestNativeWorkspaceRetry(t *testing.T) {
	for _, phase := range []string{"repository", "imported", "linked", "published"} {
		t.Run(phase, func(t *testing.T) {
			m, p, index, q := workspaceProducerFixture(t)
			fault := &workspaceFaultStore{leaseStorage: m.store, phase: phase}
			m.store = fault
			if err := m.ensureNativeWorkspace(context.Background(), &p, index, q); err == nil || !fault.failed {
				t.Fatal("producer crossed a failed durable journal write")
			}
			retained, err := m.find(p.Lease.ID)
			if err != nil {
				t.Fatal(err)
			}
			original := retained.Storage.Workspace.Enrollment
			q.Reg.ClaimID, q.Reg.ClaimGeneration = "workspace-retry-claim", q.Reg.ClaimGeneration+1
			if err := m.ensureNativeWorkspace(context.Background(), &retained, index, q); err != nil {
				t.Fatal("producer did not continue its retained native attempt", err)
			}
			actual := retained.Storage.Workspace
			if actual.Phase != "published" || actual.Enrollment.Workspace.ID != original.Workspace.ID || actual.Enrollment.Workspace.RootID != original.Workspace.RootID || actual.Enrollment.Workspace.RepositoryID != original.Workspace.RepositoryID || actual.ClaimID != q.Reg.ClaimID {
				t.Fatal("producer retry replaced its stable allocation or adopted a stale claim")
			}
		})
	}
}

func TestNativeWorkspaceRefusals(t *testing.T) {
	for _, mode := range []string{"foreign", "stale", "expired", "changed-result", "missing-handles", "replaced", "registry", "git-pin"} {
		t.Run(mode, func(t *testing.T) {
			m, p, index, q := workspaceProducerFixture(t)
			if err := m.ensureNativeWorkspace(context.Background(), &p, index, q); err != nil {
				t.Fatal(err)
			}
			e := p.Storage.Workspace.Enrollment
			pins := m.dataPins[p.DataJobs[index].Projection.OpenToken]
			switch mode {
			case "foreign":
				q.Reg.Reservation.Target.LifeID = "foreign-life"
			case "stale":
				q.Reg.ClaimID = "foreign-claim"
			case "expired":
				q.Reg.ClaimExpires = api.Timestamp(time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano))
			case "changed-result":
				q.Receipt.Result.SHA256 = testDigest("changed-result")
			case "missing-handles":
				delete(m.dataPins, p.DataJobs[index].Projection.OpenToken)
			case "replaced":
				old := filepath.Join(e.Parent, string(e.Workspace.ID))
				if err := os.Rename(old, old+"-old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(old, 0700); err != nil {
					t.Fatal(err)
				}
			case "registry":
				changed := e
				changed.Workspace.RepositoryID = "foreign-repository"
				workerCanaryJSON(t, workspaceEnrollmentPath(e), changed, 0444)
			case "git-pin":
				p.Storage.Workspace.Enrollment.GitArtifact.SHA256 = testDigest("foreign-git")
			}
			if err := m.ensureNativeWorkspace(context.Background(), &p, index, q); err == nil {
				t.Fatalf("native workspace producer accepted %s", mode)
			}
			if raw, err := os.ReadFile(filepath.Join(dataFD(pins.roots[1]), "README.md")); err != nil || string(raw) != "retained native source cache bytes\n" {
				t.Fatal("refused workspace producer changed retained source bytes")
			}
		})
	}
}

func TestNativeWorkspacePrerequisites(t *testing.T) {
	for _, mode := range []string{"unmeasured", "missing-result", "missing-handles", "missing-claim"} {
		t.Run(mode, func(t *testing.T) {
			m, p, index, q := workspaceProducerFixture(t)
			switch mode {
			case "unmeasured":
				p.DataJobs[index].State = "opened"
			case "missing-result":
				p.DataJobs[index].Result = nil
			case "missing-handles":
				delete(m.dataPins, p.DataJobs[index].Projection.OpenToken)
			case "missing-claim":
				q.Reg.ClaimID = ""
			}
			var typed *api.Error
			if err := m.ensureNativeWorkspace(context.Background(), &p, index, q); !errors.As(err, &typed) {
				t.Fatal("missing workspace prerequisite did not return a typed refusal", err)
			}
			if p.Storage.Workspace != nil {
				t.Fatal("missing prerequisite published a workspace journal")
			}
			if _, err := os.Lstat(filepath.Join(storageBase(m.binding, p), "repository-"+string(p.Storage.Binding.WorkspaceID))); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("missing prerequisite started native Git creation")
			}
		})
	}
}
