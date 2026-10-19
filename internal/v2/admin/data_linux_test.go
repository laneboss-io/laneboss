//go:build linux

package admin

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// These tests measure temporary filesystem bytes. Stage/receipt/observation
// values below are explicit component inputs, never native launch evidence.
func dataTestRoots(t *testing.T) (*dataPins, api.StorageProjection) {
	t.Helper()
	base := privateTestDir(t)
	if err := os.Chmod(base, 0710); err != nil {
		t.Fatal(err)
	}
	parent, err := os.Open(base)
	if err != nil {
		t.Fatal(err)
	}
	other, err := os.Open(base)
	if err != nil {
		t.Fatal(err)
	}
	pins := &dataPins{parents: [2]*os.File{parent, other}, names: [3]string{"source", "workspace", "home"}}
	projection := api.StorageProjection{StageID: "data-stage", WorkerLeaseID: "worker-lease", OpenToken: "open-token", Generation: 1}
	identities := []*string{&projection.SourceIdentity, &projection.WorkspaceIdentity, &projection.HomeIdentity}
	for i, name := range pins.names {
		if err := os.Mkdir(filepath.Join(base, name), 0700); err != nil {
			t.Fatal(err)
		}
		pins.roots[i], err = os.Open(filepath.Join(base, name))
		if err != nil {
			t.Fatal(err)
		}
		identity, _, err := dataIdentity(pins.roots[i])
		if err != nil {
			t.Fatal(err)
		}
		*identities[i] = identity
	}
	t.Cleanup(func() {
		if err := pins.close(); err != nil {
			t.Error(err)
		}
	})
	return pins, projection
}

func dataTestResult(t *testing.T) (*leaseManager, leaseRecord, dataJob, dataMeasure, api.ProcessObservation) {
	t.Helper()
	pins, projection := dataTestRoots(t)
	target := api.LifeRef{LifeID: "data-life", Run: 1}
	content := []byte("granted file bytes\n")
	ref := api.BlobRef{ID: "file-object", Class: "data", Bytes: int64(len(content)), SHA256: digestBytes(content)}
	manifest := api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{{Path: "file.txt", Kind: "file", Mode: 0600, Content: &ref}}}
	raw, err := canonicalValue(manifest)
	if err != nil {
		t.Fatal(err)
	}
	pins.manifest = append([]byte{}, raw...)
	source := api.ProjectLaunchSource{ProjectID: "data-project", GrantID: "source-grant", Object: api.BlobRef{ID: "source-object", Class: "manifest", SHA256: digestBytes(raw), Bytes: int64(len(raw))}, Base: string(digestBytes(raw)), HistoryScope: "tree"}
	output := source.Object
	output.ID = "output-object"
	for _, file := range pins.roots[:2] {
		if err := os.WriteFile(filepath.Join(dataFD(file), "file.txt"), content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dataFD(pins.roots[2]), ".vendor"), 0700); err != nil {
		t.Fatal(err)
	}
	parent := leaseRecord{Lease: api.HelperLease{ID: "agent-lease", UID: uint32(os.Geteuid()) + 1, GID: uint32(os.Getegid()) + 1}}
	projection.Storage = api.LaunchStorage{ReservationID: "reservation", Target: target, LeaseID: parent.Lease.ID, WorkspaceID: "workspace", Home: api.PrivateHomeBinding{LifeID: target.LifeID, RootID: "home", Generation: 1, Home: api.PrivateHome{ID: "private-home", WorkspaceID: "workspace", VendorDirectory: ".vendor", HistoryID: "history"}}}
	reg := dataReg{Request: api.StorageProjectionRequest{StageID: projection.StageID, ReservationID: "reservation", AgentLeaseID: parent.Lease.ID, WorkerLeaseID: projection.WorkerLeaseID},
		Reservation: api.LaunchReservation{ID: "reservation", Target: target, OperationID: "operation", GrantSetID: "agent-grants", StarterChain: []api.ID{}}, Inputs: api.LaunchInputs{Sources: api.LaunchSources{Project: source}},
		Grants: api.GrantSet{Resources: []api.ResourceGrant{}, Data: []api.DataGrant{}, Profiles: []api.ProfileGrant{}, Secrets: []api.SecretGrant{}, Network: []api.NetworkGrant{}, Channels: []api.ChannelGrant{}},
		Worker: api.WorkerLease{ID: projection.WorkerLeaseID, EffectID: "worker-effect", Generation: 1, Input: api.BlobRef{ID: "input", SHA256: testDigest("input")}}, LaunchID: "worker-launch", Plan: api.WorkerPlan{Budget: api.Budget{DiskBytes: 1024}}}
	input, err := canonicalValue(dataInput{Schema: "laneboss.materialize-input.v2", StageID: reg.Request.StageID, Reservation: reg.Reservation, Source: source, Storage: projection, Grants: reg.Grants, Output: output})
	if err != nil {
		t.Fatal(err)
	}
	job := dataJob{Reg: reg, State: "opened", Projection: projection, Lease: api.HelperLease{ID: "native-worker", UID: uint32(os.Geteuid()), GID: uint32(os.Getegid()), ContainmentID: "worker-cgroup"}, Input: input,
		Gate: &dataGate{Prepared: api.PreparedLaunch{ProcessGeneration: "component-generation"}, Record: &api.LaunchRecord{HostUID: uint32(os.Geteuid())}}}
	data := api.LaunchData{ReservationID: reg.Reservation.ID, Target: target, LeaseID: parent.Lease.ID, Source: source, Home: projection.Storage.Home,
		Workspace:       api.Workspace{ID: "workspace", ProjectID: source.ProjectID, Base: source.Base, Branch: "lane/" + string(target.LifeID), LogicalCWD: "/work/main", Snapshot: output},
		Materialization: api.Materialization{GrantSetID: "agent-grants", Manifest: output, Objects: []api.MaterializedObject{{GrantID: source.GrantID, WorkspaceID: "workspace", SourceIdentity: projection.SourceIdentity, DestinationIdentity: projection.WorkspaceIdentity, SnapshotSHA256: output.SHA256}}}}
	encoded, err := canonicalValue(data)
	if err != nil {
		t.Fatal(err)
	}
	query := dataMeasure{Reg: reg, Output: encoded, Manifest: raw, Receipt: api.WorkerResultReceipt{LeaseID: projection.WorkerLeaseID, StageID: projection.StageID, Generation: 2, CommittedSeq: 11, Result: api.BlobRef{ID: "acknowledged", Class: "worker_result", Bytes: int64(len(encoded)), SHA256: digestBytes(encoded)}}}
	zero := 0
	survivors := uint64(0)
	observation := api.ProcessObservation{Handle: dataHandle(job), State: "exited", ExitCode: &zero, Survivors: &survivors, ObservedAt: gateTimestamp()}
	return &leaseManager{dataPins: map[api.ID]*dataPins{projection.OpenToken: pins}}, parent, job, query, observation
}

func TestDataReadBack(t *testing.T) {
	for _, fault := range []string{"valid", "changed-file", "extra-output", "source-file", "wrong-ack", "foreign-root", "no-exit", "unknown-survivors", "running"} {
		t.Run(fault, func(t *testing.T) {
			m, parent, job, query, observation := dataTestResult(t)
			if _, err := m.readDataResult(context.Background(), parent, job, query, observation); err != nil {
				t.Fatalf("read-back baseline: %v", err)
			}
			pins := m.dataPins[job.Projection.OpenToken]
			switch fault {
			case "valid":
				result, err := m.readDataResult(context.Background(), parent, job, query, observation)
				if err != nil || result.ReadBackSHA256 != digestBytes(query.Manifest) || result.ResultReceipt != query.Receipt {
					t.Fatalf("acceptance: actual data read-back missing: %v", err)
				}
				return
			case "changed-file":
				if err := os.WriteFile(filepath.Join(dataFD(pins.roots[1]), "file.txt"), []byte("changed file bytes\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "extra-output":
				if err := os.WriteFile(filepath.Join(dataFD(pins.roots[1]), "extra"), []byte("ungranted"), 0600); err != nil {
					t.Fatal(err)
				}
			case "source-file":
				if err := os.WriteFile(filepath.Join(dataFD(pins.roots[0]), "file.txt"), []byte("changed file bytes\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "wrong-ack":
				query.Receipt.Result.SHA256 = testDigest("foreign acknowledgement")
			case "foreign-root":
				var data api.LaunchData
				if err := api.DecodeObject(query.Output, &data); err != nil {
					t.Fatal(err)
				}
				data.Materialization.Objects[0].SourceIdentity = "another:inode"
				var err error
				query.Output, err = canonicalValue(data)
				if err != nil {
					t.Fatal(err)
				}
				query.Receipt.Result.SHA256 = digestBytes(query.Output)
				query.Receipt.Result.Bytes = int64(len(query.Output))
			case "no-exit":
				observation.ExitCode = nil
			case "unknown-survivors":
				observation.Survivors = nil
			case "running":
				observation.State = "running"
			}
			if _, err := m.readDataResult(context.Background(), parent, job, query, observation); err == nil {
				t.Fatalf("acceptance: data read-back accepted %s", fault)
			}
		})
	}
}

func TestDataPrincipal(t *testing.T) {
	r := dataReg{LaunchID: "worker-launch", ParentActor: api.Actor{Kind: "service", ID: "service"}, Reservation: api.LaunchReservation{Config: "admin-case", RequestedBy: api.Actor{Kind: "lane", ID: "requester"}, PolicyGeneration: 1}, Worker: api.WorkerLease{Target: api.LifeRef{LifeID: "life", Run: 1}}, Grants: api.GrantSet{ID: "job-grants", SHA256: testDigest("narrow")}}
	for _, fault := range []string{"agent", "level", "role", "requester"} {
		t.Run(fault, func(t *testing.T) {
			record := api.LaunchRecord{Kind: "worker", ID: r.LaunchID, Config: r.Reservation.Config, Target: r.Worker.Target, Actor: api.Actor{Kind: "worker", ID: "own-worker"}, GrantSetID: r.Grants.ID, GrantsSHA256: r.Grants.SHA256, PolicyGeneration: 1}
			if err := validateWorkerRecord(r, record); err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "agent":
				record.Actor.Kind = "lane"
			case "level":
				record.Actor.Level = 3
			case "role":
				record.Actor.Role = "executor"
			case "requester":
				record.Actor.ID = r.Reservation.RequestedBy.ID
			}
			if err := validateWorkerRecord(r, record); err == nil {
				t.Fatalf("acceptance: worker borrowed %s", fault)
			}
		})
	}
}

func TestDataInputFreeze(t *testing.T) {
	a := dataReg{Worker: api.WorkerLease{Generation: 1, Input: api.BlobRef{ID: "input", Class: "materialize_input", SHA256: testDigest("original"), Bytes: 8}}}
	a.Plan.Input = a.Worker.Input
	b := a
	if !sameDataReg(a, b) {
		t.Fatal("unchanged registration refused")
	}
	b.Worker.Input.SHA256 = testDigest("changed")
	b.Plan.Input = b.Worker.Input
	if sameDataReg(a, b) {
		t.Fatal("acceptance: data input changed after assignment")
	}
	a.Worker.Input = api.BlobRef{}
	a.Plan.Input = api.BlobRef{}
	if !sameDataReg(a, b) {
		t.Fatal("first input assignment refused")
	}
}

func TestDataManifest(t *testing.T) {
	for _, fault := range []string{"escape", "admin", "symlink-parent", "external-link", "writable", "disk"} {
		t.Run(fault, func(t *testing.T) {
			ref := api.BlobRef{ID: "content", Class: "data", Bytes: 4, SHA256: testDigest("data")}
			manifest := api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{{Path: "file", Kind: "file", Mode: 0600, Content: &ref}}}
			raw, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := dataManifest(raw, 16); err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "escape":
				manifest.Entries[0].Path = "../file"
			case "admin":
				manifest.Entries[0].Path = ".GiT/config"
			case "symlink-parent":
				manifest.Entries[0].Path = "link/file"
				manifest.Entries = append(manifest.Entries, api.ObjectEntry{Path: "link", Kind: "symlink", Mode: 0777, LinkTarget: "."})
			case "external-link":
				manifest.Entries = []api.ObjectEntry{{Path: "link", Kind: "symlink", Mode: 0777, LinkTarget: "../outside"}}
			case "writable":
				manifest.Entries[0].Mode = 0666
			case "disk":
				manifest.Entries[0].Content.Bytes = 17
			}
			raw, err = json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := dataManifest(raw, 16); err == nil {
				t.Fatalf("acceptance: data manifest accepted %s", fault)
			}
		})
	}
}

func TestDataTerminal(t *testing.T) {
	zero, one := 0, 1
	empty, live := uint64(0), uint64(1)
	handle := api.ProcessHandle{ID: "worker", Generation: "observed"}
	baseline := api.ProcessObservation{Handle: handle, State: "exited", ExitCode: &zero, Survivors: &empty, ObservedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}
	if err := dataTerminal(baseline, handle); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"exit", "unknown", "survivor", "signal"} {
		t.Run(fault, func(t *testing.T) {
			o := baseline
			switch fault {
			case "exit":
				o.ExitCode = &one
			case "unknown":
				o.ExitCode = nil
			case "survivor":
				o.Survivors = &live
			case "signal":
				o.Signal = &one
			}
			if err := dataTerminal(o, handle); err == nil {
				t.Fatalf("acceptance: data terminal accepted %s", fault)
			}
		})
	}
}

func dataTestReg(t *testing.T) (leaseRecord, dataJob, installation) {
	t.Helper()
	_, parent, r := storageFixture(t)
	binding := testBinding()
	parent.Lease.UID, parent.Lease.GID = binding.Lanes[0].UID, binding.Lanes[0].GID
	inputs := parent.LaunchAllocations[0].Inputs
	expires := api.Timestamp(time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339Nano))
	grants := api.GrantSet{ID: "job-grants", LifeID: r.Target.LifeID, ParentLifeID: r.Target.LifeID, PolicyGeneration: r.PolicyGeneration, Generation: 1, ExpiresAt: expires,
		Resources: []api.ResourceGrant{}, Secrets: []api.SecretGrant{}, Profiles: []api.ProfileGrant{}, Network: []api.NetworkGrant{}, Channels: []api.ChannelGrant{},
		Data: []api.DataGrant{{ID: "job-source", ParentGrantID: inputs.Sources.Project.GrantID, SourceObjectID: inputs.Sources.Project.Object.ID, SourceSHA256: inputs.Sources.Project.Object.SHA256, RelativePath: ".", Access: "ro", Delivery: "bind_ro", Destination: "/job/source", HistoryScope: inputs.Sources.Project.HistoryScope, ExpiresAt: expires}}}
	raw, err := canonicalValue(grants)
	if err != nil {
		t.Fatal(err)
	}
	grants.SHA256 = digestBytes(raw)
	worker := api.WorkerLease{ID: "job-lease", EffectID: "job-effect", Kind: "materialize", Target: r.Target, OperationID: r.OperationID, GrantSetID: grants.ID, RuntimeManifest: inputs.Sources.Runtime.Manifest, Generation: 1, ExpiresAt: expires}
	plan := api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: "materialize", Executable: api.Executable{ID: "artifact", SHA256: binding.Artifact.SHA256, Version: binding.Release.Version}, GrantSetID: grants.ID, Budget: parent.Request.Budget,
		Argv: []string{"laneboss", "internal", "worker", "--binding", "/runtime/laneboss-worker.json", "--lease", string(worker.ID)}}
	reg := dataReg{Request: api.StorageProjectionRequest{StageID: "job-stage", ReservationID: r.ID, AgentLeaseID: parent.Lease.ID, WorkerLeaseID: worker.ID}, Reservation: r, Inputs: inputs, Grants: grants, Worker: worker, Plan: plan,
		ParentEffect: parent.Request.Cause.EffectID, ParentActor: parent.Request.Cause.Actor, LaunchID: "job-launch", ClaimID: "job-claim", ClaimGeneration: 1, ClaimExpires: api.Timestamp(time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano))}
	job := dataJob{Reg: reg, State: "reserved", Created: gateTimestamp(), Evidence: []byte{}, Lease: api.HelperLease{ID: "native-job", UID: binding.Lanes[1].UID, GID: binding.Lanes[1].GID, ContainmentID: "job-cgroup", EndpointGeneration: 1}}
	if err := validateDataJob(parent, job, binding); err != nil {
		t.Fatalf("data journal baseline: %v", err)
	}
	return parent, job, binding
}

func TestDataUID(t *testing.T) {
	parent, job, binding := dataTestReg(t)
	parent.Lease.UID = job.Lease.UID
	if err := validateDataJob(parent, job, binding); err == nil {
		t.Fatal("acceptance: data worker shares agent UID")
	}
}

func TestDataReg(t *testing.T) {
	for _, fault := range []string{"argv", "credential", "parent", "source"} {
		t.Run(fault, func(t *testing.T) {
			_, job, binding := dataTestReg(t)
			reg := job.Reg
			switch fault {
			case "argv":
				reg.Plan.Argv[0] = "caller-program"
			case "credential":
				reg.Grants.Secrets = append(reg.Grants.Secrets, api.SecretGrant{ID: "foreign-slot"})
				sealed := reg.Grants
				sealed.SHA256 = ""
				raw, err := canonicalValue(sealed)
				if err != nil {
					t.Fatal(err)
				}
				reg.Grants.SHA256 = digestBytes(raw)
			case "parent":
				reg.ParentEffect = reg.Worker.EffectID
			case "source":
				reg.Grants.Data[0].SourceSHA256 = testDigest("foreign source")
				sealed := reg.Grants
				sealed.SHA256 = ""
				raw, err := canonicalValue(sealed)
				if err != nil {
					t.Fatal(err)
				}
				reg.Grants.SHA256 = digestBytes(raw)
			}
			if err := validateDataReg(reg, binding.Config); err == nil {
				t.Fatalf("acceptance: data registration accepted %s", fault)
			}
		})
	}
}
