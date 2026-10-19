//go:build linux

package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	linux "laneboss.io/laneboss/internal/v2/isolation/linux"
)

var errSpecValidated = errors.New("complete Linux spec validation reached the nonexecuting handoff boundary")

// Prepare calls Handoff only after every check in validate.go has succeeded.
// This observer refuses further preparation; it cannot fabricate a native launch.
type specValidationBoundary struct {
	api.LaunchControlSource
	want  api.LaunchSpec
	calls int
}

func (b *specValidationBoundary) Handoff(_ context.Context, spec api.LaunchSpec) (api.PreparedSpecHandoff, error) {
	b.calls++
	if !reflect.DeepEqual(spec, b.want) {
		return api.PreparedSpecHandoff{}, errors.New("Linux validation changed the original full spec")
	}
	return api.PreparedSpecHandoff{}, errSpecValidated
}

// Match case_grants.py's installed parent: all six grant families, an rw main
// project, two independent ro copies, both profiles, one enrolled resource and
// the imported file secret whose source name differs from its delivery target.
// Only opaque identities, expiry and synthetic contents vary from an install.
// The rich twin additionally retains the native-copy proof's rw subtree, file
// view, symlink and multipart assembly, without replacing the installed shape.
func installedGrantsFullSpec(t *testing.T, driver api.Driver, rich bool) (*launchCase, api.LaunchSpec) {
	t.Helper()
	c := newLaunchCaseRuntimeAt(t, "helper", false, nil, time.Now().UTC(), driver)
	record := c.plan(t)
	r := record.Reservation
	expiry := c.store.grants.ExpiresAt
	var storage api.LaunchStorage
	if err := c.store.read("storage.json", &storage); err != nil {
		t.Fatal(err)
	}
	if driver == api.DriverClaudock {
		storage.Home.Home.VendorDirectory = ".claude"
		if err := c.store.save("storage.json", storage); err != nil {
			t.Fatal(err)
		}
	}
	input := c.store.putRawObject(t, "grants-input", "artifact", []byte("installed input\n"), r.OperationID)
	canary := c.store.putRawObject(t, "grants-canary", "artifact", []byte("synthetic canary\n"), r.OperationID)
	fixed := c.store.putRawObject(t, "grants-fixed", "artifact", []byte("fixed input\n"), r.OperationID)
	main := api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{{Path: "input.txt", Kind: "file", Mode: 0444, Content: &input}}}
	mainRef := c.store.putObject(t, "grants-main-tree", "manifest", main, r.OperationID)
	project := &record.Inputs.Sources.Project
	project.Object, project.Base, project.HistoryScope = mainRef, string(mainRef.SHA256), "tree"
	c.store.grants.Data[0].SourceObjectID, c.store.grants.Data[0].SourceSHA256 = mainRef.ID, mainRef.SHA256
	var enrollment api.LaunchEnrollment
	if err := c.store.read("enrollment.json", &enrollment); err != nil {
		t.Fatal(err)
	}
	enrollment.Projects[0].Object, enrollment.Projects[0].Base = mainRef, project.Base
	if err := c.store.save("enrollment.json", enrollment); err != nil {
		t.Fatal(err)
	}
	parent := api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{
		{Path: "child/input.txt", Kind: "file", Mode: 0444, Content: &input},
		{Path: "private/canary", Kind: "file", Mode: 0444, Content: &canary},
		{Path: "alias", Kind: "symlink", Mode: 0777, LinkTarget: "private/canary"},
	}}
	fixedTree := api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{{Path: "fixed.txt", Kind: "file", Mode: 0444, Content: &fixed}}}
	views := []struct {
		name, relative, access, destination, file string
		delegate                                  bool
		manifest                                  api.ObjectManifest
	}{
		{"parent", ".", "ro", "/data/parent", "", true, parent},
		{"fixed", ".", "ro", "/data/fixed", "", false, fixedTree},
	}
	if rich {
		partA := c.store.putRawObject(t, "assembly-a", "artifact", []byte("assembly first part\n"), r.OperationID)
		partB := c.store.putRawObject(t, "assembly-b", "artifact", []byte("assembly second part\n"), r.OperationID)
		assembly := api.ObjectAssembly{SHA256: digestFixture("assembly first part\nassembly second part\n"), Bytes: partA.Bytes + partB.Bytes, Parts: []api.BlobRef{partA, partB}}
		tree := api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{
			{Path: "bundle", Kind: "directory", Mode: 0700},
			{Path: "bundle/nested", Kind: "directory", Mode: 0700},
			{Path: "bundle/nested/input.bin", Kind: "file", Mode: 0600, Assembly: &assembly},
			{Path: "bundle/link", Kind: "symlink", Mode: 0777, LinkTarget: "nested/input.bin"},
		}}
		views = append(views, struct {
			name, relative, access, destination, file string
			delegate                                  bool
			manifest                                  api.ObjectManifest
		}{"writable", "bundle", "rw", "/data/writable", "", false, tree}, struct {
			name, relative, access, destination, file string
			delegate                                  bool
			manifest                                  api.ObjectManifest
		}{"file", "bundle/nested/input.bin", "ro", "/data/file", "file", false, tree})
	}
	var copies []api.DataCopyProjection
	for _, view := range views {
		ref := c.store.putObject(t, api.ID("grants-"+view.name+"-tree"), "manifest", view.manifest, r.OperationID)
		grant := api.DataGrant{ID: api.ID(view.name + "-data"), SourceObjectID: ref.ID, SourceSHA256: ref.SHA256, RelativePath: view.relative,
			Access: view.access, Delivery: "copy", Destination: view.destination, Delegate: view.delegate, ExpiresAt: expiry, HistoryScope: "snapshot"}
		copies = append(copies, api.DataCopyProjection{Grant: grant, Source: ref, Manifest: view.manifest, File: view.file,
			WorkspaceID: api.ID("copy-" + view.name), SourceIdentity: view.name + "-source", DestinationIdentity: view.name + "-destination"})
		c.store.grants.Data = append(c.store.grants.Data, grant)
	}
	c.store.grants.Resources = []api.ResourceGrant{{ID: "resource-grant", SourceHandle: "resource-enrollment", Provider: "gcp", Regions: []string{"region-a"},
		ImageIDs: []string{"image-a"}, MachineTypes: []string{"small"}, MaxActive: 1, Delegate: true, ExpiresAt: expiry}}
	c.store.grants.Profiles[0].Delegate = true
	other := c.store.grants.Profiles[0]
	other.ID, other.ProfileID, other.Driver = "other-profile-grant", "other-profile", api.DriverClaudock
	if driver == api.DriverClaudock {
		other.Driver = api.DriverCodex
	}
	if driver == api.DriverClaudock {
		c.store.grants.Profiles = append(c.store.grants.Profiles, other)
	} else {
		c.store.grants.Profiles = append([]api.ProfileGrant{other}, c.store.grants.Profiles...)
	}
	record.Inputs.Grants = c.store.grants
	c.setPlan(t, record)
	c.addSecret(t, "grants-canary-source", "file", "grants-canary")
	if rich {
		// Deliberately interleave deliveries and oppose source-name sorting.
		c.addSecret(t, "Z_SOURCE", "env", "TASK_Z")
		c.addSecret(t, "a-source", "file", "a/token")
		c.addSecret(t, "M_SOURCE", "env", "TASK_A")
	}
	record = c.plan(t)
	dataCount, secretCount := 3, 1
	if rich {
		dataCount, secretCount = 5, 4
	}
	grants := record.Inputs.Grants
	if len(grants.Resources) != 1 || len(grants.Data) != dataCount || len(grants.Secrets) != secretCount ||
		len(grants.Profiles) != 2 || len(grants.Network) != 0 || len(grants.Channels) != 0 {
		t.Fatal("full installed grant inventory was reduced")
	}
	// AcquireLaunch independently reloads the original request and verifies the
	// entire profile inventory and its issuance order, including the other driver.
	blob, err := c.store.Blob(context.Background(), api.Scope{}, api.BlobReadRequest{ObjectID: r.OriginalRequest.ID})
	if err != nil {
		t.Fatal(err)
	}
	var original api.Request
	if err := api.DecodeObject(blob.Data, &original); err != nil {
		t.Fatal(err)
	}
	var start api.StartRequest
	if err := api.DecodeObject(original.Params, &start); err != nil {
		t.Fatal(err)
	}
	start.Level, start.Role = 5, "supervisor"
	start.Budget = api.Budget{WallMS: 300000, CPUSeconds: 120, MemoryBytes: 512 << 20, Processes: 32, DiskBytes: 64 << 20, Currency: "USD"}
	start.Grants.Profiles = []api.ProfileDelegation{}
	for _, member := range record.Inputs.Grants.Resources {
		start.Grants.Resources = append(start.Grants.Resources, api.ResourceDelegation{ParentGrantID: api.ID("template-" + string(member.ID)), Regions: member.Regions,
			ImageIDs: member.ImageIDs, MachineTypes: member.MachineTypes, MaxActive: member.MaxActive, MaxHourlyMicros: member.MaxHourlyMicros,
			TotalBudgetMicros: member.TotalBudgetMicros, Delegate: member.Delegate, ExpiresAt: member.ExpiresAt})
	}
	for _, member := range record.Inputs.Grants.Profiles {
		start.Grants.Profiles = append(start.Grants.Profiles, api.ProfileDelegation{ParentGrantID: api.ID("template-" + string(member.ID)),
			ProfileID: member.ProfileID, Delegate: member.Delegate, ExpiresAt: member.ExpiresAt})
	}
	for _, member := range record.Inputs.Grants.Data {
		start.Grants.Data = append(start.Grants.Data, api.DataGrantRequest{ParentGrantID: api.ID("template-" + string(member.ID)), RelativePath: member.RelativePath,
			Access: member.Access, Delivery: member.Delivery, Destination: member.Destination, Delegate: member.Delegate, ExpiresAt: member.ExpiresAt})
	}
	for _, member := range record.Inputs.Grants.Secrets {
		start.Grants.Secrets = append(start.Grants.Secrets, api.SecretDelegation{ParentGrantID: api.ID("template-" + string(member.ID)), Name: member.Name,
			Version: member.Version, Delivery: member.Delivery, Target: member.Target, Delegate: member.Delegate, ExpiresAt: member.ExpiresAt})
	}
	original.Params, err = json.Marshal(start)
	if err != nil {
		t.Fatal(err)
	}
	original.RequestSHA256, err = api.RequestDigest(original)
	if err != nil {
		t.Fatal(err)
	}
	r.Level, r.Role, r.RequestSHA256 = start.Level, start.Role, original.RequestSHA256
	r.OriginalRequest = c.store.putObject(t, "installed-original-request", "launch_request", original, r.OperationID)
	record.Reservation = r
	c.setPlan(t, record)
	// Profile request selection is by the retained original request, not list order.
	selected := c.store.grants.Profiles[0]
	if driver == api.DriverCodex {
		selected = c.store.grants.Profiles[1]
	}
	slot, err := c.acquire(context.Background(), c.target, selected)
	if err != nil {
		t.Fatal("installed profile acquisition", err)
	}
	injection, err := c.inject(context.Background(), c.target, record.Inputs.Grants.Secrets)
	if err != nil {
		t.Fatal("installed production injection", err)
	}
	if len(injection.SlotIDs) != len(record.Inputs.Grants.Secrets)+1 || injection.SlotIDs[0] != slot.ID {
		t.Fatal("production injection omitted its complete profile and task slot inventory")
	}
	for i, grant := range record.Inputs.Grants.Secrets {
		// Preserve the installed broker's existing canonical ID algorithm.
		if injection.SlotIDs[i+1] != credentialID("task", r.ID, grant.ID) {
			t.Fatal("task slot identity or issued request order changed")
		}
	}
	encodedCopies, err := api.EncodeDataCopyProjections(copies)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.ValidateDataCopyProjections(*record.Inputs, api.StorageProjection{Copies: encodedCopies,
		SourceIdentity: "main-source", WorkspaceIdentity: "main-destination", HomeIdentity: "home-root"}); err != nil {
		t.Fatal("complete installed copy projections differ from issued grants", err)
	}
	workspace := api.Workspace{ID: storage.WorkspaceID, ProjectID: project.ProjectID, Base: project.Base, Branch: "lane/" + string(r.Target.LifeID),
		LogicalCWD: "/work/main", Snapshot: mainRef}
	materialized := api.Materialization{GrantSetID: c.store.grants.ID, Objects: []api.MaterializedObject{{GrantID: project.GrantID,
		SourceIdentity: "main-source", DestinationIdentity: "main-destination", WorkspaceID: workspace.ID, SnapshotSHA256: workspace.Snapshot.SHA256}}}
	for _, copy := range copies {
		receipt, err := copy.Receipt(workspace.ID)
		if err != nil {
			t.Fatal(err)
		}
		materialized.Objects = append(materialized.Objects, receipt)
	}
	materialized.Manifest = c.store.putObject(t, "materialization", "manifest", materialized.Objects, r.OperationID)
	runner := api.RunnerPlan{Driver: driver, Executable: c.profile.Runtime, Argv: []string{"/usr/bin/claudock", "fixture"}, CWD: workspace.LogicalCWD,
		Home: storage.Home.Home, Slot: slot, Prompt: c.store.putObject(t, "prompt", "prompt", main, r.OperationID), EnvironmentNames: []string{}, InnerSandbox: "off", AdapterVersion: "fixture-v1",
		Session: api.Session{ID: "session", Driver: driver, VendorVersion: "fixture-v1", HomeID: storage.Home.Home.ID, HistoryID: storage.Home.Home.HistoryID, LogicalCWD: workspace.LogicalCWD}}
	if driver == api.DriverCodex {
		runner.Argv[0] = "/usr/bin/codex"
	}
	lease := api.HelperLease{ID: storage.LeaseID, UID: 12001, GID: 12001, ContainmentID: "containment", EndpointGeneration: 1}
	capture := api.CaptureBinding{ID: "capture", Config: r.Config, ReservationID: r.ID, Target: r.Target, LaunchID: r.LaunchID, HelperLeaseID: lease.ID,
		OperationID: r.OperationID, RequestID: r.RequestID, RequestedBy: r.RequestedBy, Generation: 1, Status: "registered", WorkerLeaseID: "capture-worker", EffectID: "capture-effect",
		ProducerID: "capture-producer", ProducerGeneration: "capture-generation", BootID: "boot", Supervisor: &c.profile.Runtime,
		Streams: []api.CaptureStreamBinding{{ID: "stdout", Stream: "stdout", PipeID: "stdout-pipe"}, {ID: "stderr", Stream: "stderr", PipeID: "stderr-pipe"}}}
	plan := api.LaunchPlan{Reservation: r, Inputs: *record.Inputs, Lease: lease, Data: api.LaunchData{ReservationID: r.ID, Target: r.Target, LeaseID: lease.ID,
		Source: *project, Workspace: workspace, Home: storage.Home, Materialization: materialized}, Runner: runner, Injection: injection,
		Budget: start.Budget, Capture: capture}
	// These are the same complete fields lifecycle.planExecution.seal retains.
	spec := api.LaunchSpec{Kind: "agent", PlanID: r.ID, ID: r.SpecID, LaunchID: r.LaunchID, Target: r.Target, Backend: plan.Inputs.Sources.Runtime.Backend,
		UIDLeaseID: lease.ID, Workspace: workspace, Materialization: materialized, Grants: plan.Inputs.Grants, Runner: &plan.Runner, Injection: injection, Budget: plan.Budget,
		Capture: &plan.Capture, EndpointGeneration: lease.EndpointGeneration, PolicyGeneration: r.PolicyGeneration, RuntimeManifest: plan.Inputs.Sources.Runtime.Manifest}
	if err := api.ValidateAgentLaunchSpec(spec, plan); err != nil {
		t.Fatal("full installed spec differs from PlanLaunch", err)
	}
	return c, spec
}

func TestInstalledGrantsFullLinuxSpec(t *testing.T) {
	for _, driver := range []api.Driver{api.DriverClaudock, api.DriverCodex} {
		for _, rich := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/rich=%t", driver, rich), func(t *testing.T) {
				c, spec := installedGrantsFullSpec(t, driver, rich)
				boundary := &specValidationBoundary{want: spec}
				launcher, err := linux.New(linux.Dependencies{Helper: c.helper, RuntimeManifest: spec.RuntimeManifest, Controls: boundary})
				if err != nil {
					t.Fatal(err)
				}
				_, err = launcher.Prepare(context.Background(), spec)
				if !errors.Is(err, errSpecValidated) || boundary.calls != 1 {
					t.Fatal("full installed spec failed complete Linux validation", err)
				}
				faults := []string{"source-name", "extra-file", "missing-task-slot", "foreign-task-slot", "foreign-reservation", "missing-reservation", "duplicate-task-slot", "slot-order"}
				if rich {
					faults = append(faults, "env-order", "file-order", "task-slot-order")
				}
				for _, fault := range faults {
					t.Run(fault, func(t *testing.T) {
						changed := spec
						changed.Injection.TaskSecretFileNames = append([]string{}, spec.Injection.TaskSecretFileNames...)
						changed.Injection.TaskSecretNames = append([]string{}, spec.Injection.TaskSecretNames...)
						changed.Injection.SlotIDs = append([]api.ID{}, spec.Injection.SlotIDs...)
						message := "injection credential slots differ from the runner plan"
						switch fault {
						case "source-name":
							changed.Injection.TaskSecretFileNames[0] = spec.Grants.Secrets[0].Name
							message = "injection delivery names differ from granted request order"
						case "extra-file":
							changed.Injection.TaskSecretFileNames = append(changed.Injection.TaskSecretFileNames, "foreign-file")
							message = "injection delivery names differ from granted request order"
						case "env-order":
							changed.Injection.TaskSecretNames[0], changed.Injection.TaskSecretNames[1] = changed.Injection.TaskSecretNames[1], changed.Injection.TaskSecretNames[0]
							message = "injection delivery names differ from granted request order"
						case "file-order":
							changed.Injection.TaskSecretFileNames[0], changed.Injection.TaskSecretFileNames[1] = changed.Injection.TaskSecretFileNames[1], changed.Injection.TaskSecretFileNames[0]
							message = "injection delivery names differ from granted request order"
						case "missing-task-slot":
							changed.Injection.SlotIDs = changed.Injection.SlotIDs[:1]
						case "foreign-task-slot":
							changed.Injection.SlotIDs[1] = api.AgentTaskSlotID(spec.PlanID, "foreign-grant")
						case "foreign-reservation":
							changed.Injection.SlotIDs[1] = api.AgentTaskSlotID("foreign-reservation", spec.Grants.Secrets[0].ID)
						case "missing-reservation":
							changed.PlanID = ""
						case "duplicate-task-slot":
							changed.Injection.SlotIDs = append(changed.Injection.SlotIDs, changed.Injection.SlotIDs[1])
						case "slot-order":
							changed.Injection.SlotIDs[0], changed.Injection.SlotIDs[1] = changed.Injection.SlotIDs[1], changed.Injection.SlotIDs[0]
						case "task-slot-order":
							changed.Injection.SlotIDs[1], changed.Injection.SlotIDs[2] = changed.Injection.SlotIDs[2], changed.Injection.SlotIDs[1]
						}
						boundary.calls = 0
						_, err := launcher.Prepare(context.Background(), changed)
						var typed *api.Error
						if !errors.As(err, &typed) || typed.Code != api.CodeIntegrity || typed.Message != message || boundary.calls != 0 {
							t.Fatal("invalid full-spec twin escaped strict Linux validation", err)
						}
					})
				}
			})
		}
	}
}

func TestWorkerInjectionDeliveryTargets(t *testing.T) {
	c, lease, credentials, _ := newWorkerCase(t)
	injection, err := c.service.InjectWorker(context.Background(), lease, credentials)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(injection.TaskSecretNames, []string{credentials[0].Target}) {
		t.Fatal("worker injection did not retain the actual environment delivery target")
	}
}
