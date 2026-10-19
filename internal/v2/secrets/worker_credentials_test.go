package secrets

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func newWorkerCase(t *testing.T, kinds ...string) (*launchCase, api.WorkerLease, []api.WorkerCredential, []byte) {
	t.Helper()
	kind := "test"
	if len(kinds) > 1 {
		t.Fatal("fixed worker fixture requires one kind")
	}
	if len(kinds) == 1 {
		kind = kinds[0]
	}
	c := newLaunchCase(t, "helper")
	grant, value := c.addSecret(t, "worker-canary", "env", "WORKER_TOKEN")
	record := c.plan(t)
	input := c.store.putObject(t, "worker-input", "worker_input", struct {
		Schema string `json:"schema"`
		Task   string `json:"task"`
	}{"fixture.worker.v2", "synthetic job"}, "worker-operation")
	lease := api.WorkerLease{ID: "worker-lease", Kind: kind, Target: c.target, OperationID: "worker-operation", EffectID: "worker-effect", Input: input, RuntimeManifest: record.Inputs.Sources.Runtime.Manifest,
		GrantSetID: c.store.grants.ID, Generation: 1, ExpiresAt: api.Timestamp(c.clock.now.Add(time.Minute).Format(time.RFC3339Nano))}
	plan := api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: lease.Kind, Executable: c.profile.Runtime, Argv: []string{"runtime-a", "fixed-job"}, Input: input, GrantSetID: c.store.grants.ID,
		Budget: api.Budget{WallMS: 1000, CPUSeconds: 1, MemoryBytes: 1 << 20, Processes: 10, DiskBytes: 1 << 20}}
	cause := api.InternalIntent{ID: "worker-intent", Kind: api.InternalLifecycleEffect, Config: "service-case", Actor: api.Actor{Kind: "service", ID: "service-a"}, RequestedBy: record.Reservation.RequestedBy,
		CauseOperationID: lease.OperationID, CauseRequestID: "worker-request", EffectID: lease.EffectID, Target: lease.Target, CancellationEpoch: record.Reservation.CancellationEpoch}
	effect := api.EffectRecord{Effect: api.Effect{ID: lease.EffectID, OperationID: lease.OperationID, Context: &cause, Worker: &plan}, Generation: 1, State: api.EffectClaimed, ClaimID: "worker-claim", ClaimantID: "worker-owner", ClaimExpiresAt: lease.ExpiresAt}
	if err := c.store.save("worker-effect.json", effect); err != nil {
		t.Fatal("cannot retain the claimed fixed worker job")
	}
	c.store.lease = lease
	return c, lease, []api.WorkerCredential{{Name: grant.Name, SourceHandle: grant.SourceHandle, Version: grant.Version, Delivery: grant.Delivery, Target: grant.Target}}, value
}

func (c *launchCase) retainWorkerSpec(t *testing.T, lease api.WorkerLease, injection api.Injection) api.LaunchSpec {
	t.Helper()
	var effect api.EffectRecord
	if err := c.store.read("worker-effect.json", &effect); err != nil {
		t.Fatal("cannot read the fixed worker job")
	}
	var storage api.LaunchStorage
	if err := c.store.read("storage.json", &storage); err != nil {
		t.Fatal("cannot read allocated worker storage")
	}
	grants, err := c.store.Grants(context.Background(), lease.GrantSetID)
	if err != nil {
		t.Fatal("cannot read the worker's exact retained grant set")
	}
	workspace := api.Workspace{ID: storage.WorkspaceID, ProjectID: "project-a", Base: c.plan(t).Inputs.Sources.Project.Base, Branch: "lane/" + string(c.target.LifeID), LogicalCWD: "/work/main",
		Snapshot: c.store.putObject(t, "worker-workspace", "manifest", struct {
			Schema string `json:"schema"`
		}{"fixture.workspace.v2"}, lease.OperationID)}
	materialized := api.Materialization{GrantSetID: grants.ID, Manifest: c.store.putObject(t, "worker-materialized", "manifest", struct {
		Schema string `json:"schema"`
	}{"fixture.materialization.v2"}, lease.OperationID), Objects: []api.MaterializedObject{}}
	spec := api.LaunchSpec{Kind: "worker", Worker: effect.Effect.Worker, ID: "worker-spec", LaunchID: "worker-launch", Target: lease.Target, Backend: "linux-bwrap-landlock", UIDLeaseID: storage.LeaseID, Workspace: workspace,
		Materialization: materialized, Grants: grants, Injection: injection, Budget: effect.Effect.Worker.Budget, EndpointGeneration: 1, RuntimeManifest: lease.RuntimeManifest, PolicyGeneration: grants.PolicyGeneration}
	c.saveWorkerHandoff(t, spec)
	return spec
}

func (c *launchCase) saveWorkerHandoff(t *testing.T, spec api.LaunchSpec) {
	t.Helper()
	ref := c.store.putObject(t, "worker-spec-object", "launch_spec", spec, c.store.lease.OperationID)
	digest, err := valueDigest(spec)
	if err != nil {
		t.Fatal("cannot hash exact worker spec")
	}
	handoff := api.PreparedSpecHandoff{Config: "service-case", Spec: spec, Original: ref, SpecSHA256: digest, OperationID: c.store.lease.OperationID, RequestID: "worker-request",
		Cause: api.InternalIntent{ID: "worker-register-intent", Kind: api.InternalHelperRegister, Config: "service-case", Actor: api.Actor{Kind: "service", ID: "service-a"}, RequestedBy: c.plan(t).Reservation.RequestedBy,
			CauseOperationID: c.store.lease.OperationID, CauseRequestID: "worker-request", EffectID: "worker-register-effect", Target: spec.Target, CancellationEpoch: 1}}
	if err := c.store.save("handoff.json", handoff); err != nil {
		t.Fatal("cannot retain complete worker handoff")
	}
}

func (c *launchCase) bindWorker(t *testing.T, spec api.LaunchSpec) api.ProcessObservation {
	t.Helper()
	generation := c.startOwnedProcess(t)
	digest, err := valueDigest(spec)
	if err != nil {
		t.Fatal("cannot hash bound worker spec")
	}
	record := api.LaunchRecord{Kind: "worker", ID: spec.LaunchID, Config: "service-case", Target: spec.Target, RootLifeID: spec.Target.LifeID, StarterChain: []api.ID{}, Actor: api.Actor{Kind: "worker", ID: "worker-principal"},
		UIDLeaseID: spec.UIDLeaseID, HostUID: 12001, ProcessGeneration: generation, ContainmentID: "containment-a", GrantSetID: spec.Grants.ID, GrantsSHA256: spec.Grants.SHA256, PolicyGeneration: spec.PolicyGeneration, EndpointGeneration: spec.EndpointGeneration}
	recordDigest, err := valueDigest(record)
	if err != nil {
		t.Fatal("cannot hash actual worker process identity")
	}
	binding := api.LaunchBindingRequest{Record: record, Prepared: api.PreparedLaunch{ID: "worker-prepared", SpecSHA256: digest, Target: spec.Target, ContainmentID: record.ContainmentID, ProcessGeneration: generation, EndpointGeneration: spec.EndpointGeneration, GateID: "worker-gate"},
		Identity: api.IdentityCommit{LaunchID: spec.LaunchID, EventID: "worker-identity", CommittedSeq: 2, RecordSHA256: recordDigest}}
	if err := c.store.save("binding.json", binding); err != nil {
		t.Fatal("cannot retain actual worker process binding")
	}
	return api.ProcessObservation{Handle: api.ProcessHandle{ID: "worker-process", Target: spec.Target, ContainmentID: record.ContainmentID, Generation: generation}, State: "running", PromptStatus: "done"}
}

func TestFixedWorkerCredentialLifecycle(t *testing.T) {
	c, lease, credentials, value := newWorkerCase(t)
	ctx := context.Background()
	injection, err := c.service.InjectWorker(ctx, lease, credentials)
	if err != nil || len(injection.SlotIDs) != 1 || injection.Target != lease.Target {
		t.Fatal("claimed fixed worker did not prepare its selected real credential")
	}
	id := injection.SlotIDs[0]
	slot := readCaseSlot(t, c, id)
	if slot.LaunchID != "" || slot.Handoff != nil || !bytes.Equal(slot.Material, value) {
		t.Fatal("worker credential staging depended on a fabricated complete spec")
	}
	clear(slot.Material)
	path := filepath.Join(c.directory, ".broker-slot-"+string(id)+".json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("cannot retain worker slot ciphertext")
	}
	again, err := c.service.InjectWorker(ctx, lease, credentials)
	if err != nil || !reflect.DeepEqual(injection, again) {
		t.Fatal("worker credential selection did not replay")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("worker credential retry rewrote ciphertext")
	}
	spec := c.retainWorkerSpec(t, lease, injection)
	material, err := c.service.PreparedSlotMaterial(ctx, spec, id)
	if err != nil || !bytes.Equal(material.Bytes, value) {
		t.Fatal("retained fixed worker spec did not receive the exact selected bytes")
	}
	clear(material.Bytes)
	observation := c.bindWorker(t, spec)
	material, err = c.service.SlotMaterial(ctx, spec.LaunchID, id)
	if err != nil || !bytes.Equal(material.Bytes, value) {
		t.Fatal("bound fixed worker material lost its exact retained selection")
	}
	clear(material.Bytes)
	stageCode(t, c.service.RevokeInjection(ctx, injection, observation), api.CodeContainmentUnknown)
	observation = c.finish(t, observation)
	if err := c.service.RevokeInjection(ctx, injection, observation); err != nil {
		t.Fatal("measured worker cleanup did not release its retained slot")
	}
	slot = readCaseSlot(t, c, id)
	if !slot.Released || len(slot.Material) != 0 || c.helper.releases != 1 {
		t.Fatal("worker cleanup retained material or skipped the actual helper release")
	}
}

func TestWorkerGuards(t *testing.T) {
	for _, fault := range []string{"claim", "foreign", "input", "executable", "manifest", "policy", "grants", "changed-retry", "changed-subset"} {
		t.Run(fault, func(t *testing.T) {
			c, lease, credentials, _ := newWorkerCase(t)
			var effect api.EffectRecord
			if err := c.store.read("worker-effect.json", &effect); err != nil {
				t.Fatal("cannot read worker authority control")
			}
			code := api.CodeForbidden
			if fault == "changed-retry" || fault == "changed-subset" {
				if _, err := c.service.InjectWorker(context.Background(), lease, credentials); err != nil {
					t.Fatal("cannot establish worker replay control")
				}
			}
			switch fault {
			case "claim":
				effect.ClaimExpiresAt = api.Timestamp(c.clock.now.Format(time.RFC3339Nano))
				code = api.CodeConflict
			case "foreign":
				effect.Effect.Context.Target.LifeID = "foreign-life"
				code = api.CodeConflict
			case "input":
				effect.Effect.Worker.Input.ID = "foreign-input"
			case "executable":
				effect.Effect.Worker.Executable.ID = "/caller/worker"
			case "manifest":
				effect.Effect.Worker.Executable.SHA256 = digestFixture("different worker executable")
			case "policy":
				c.store.policy.Generation++
				code = api.CodeConflict
			case "grants":
				c.store.grants.Revoked = true
			case "changed-retry":
				effect.Effect.Worker.Argv = append(effect.Effect.Worker.Argv, "changed")
				code = api.CodeConflict
			case "changed-subset":
				credentials = []api.WorkerCredential{}
				code = api.CodeConflict
			}
			if err := c.store.save("worker-effect.json", effect); err != nil {
				t.Fatal("cannot retain changed worker authority control")
			}
			_, err := c.service.InjectWorker(context.Background(), lease, credentials)
			stageCode(t, err, code)
		})
	}
}

func TestFixedWorkerMaterialGuards(t *testing.T) {
	for _, fault := range []string{"foreign", "executable", "path", "selection", "runtime", "handoff", "restart-binding", "claim"} {
		t.Run(fault, func(t *testing.T) {
			c, lease, credentials, _ := newWorkerCase(t)
			injection, err := c.service.InjectWorker(context.Background(), lease, credentials)
			if err != nil {
				t.Fatal("cannot prepare worker material refusal control")
			}
			spec := c.retainWorkerSpec(t, lease, injection)
			code := api.CodeForbidden
			switch fault {
			case "foreign":
				spec.Target.LifeID = "foreign-life"
				c.saveWorkerHandoff(t, spec)
			case "executable":
				copy := *spec.Worker
				copy.Executable.ID = "foreign-executable"
				spec.Worker = &copy
				c.saveWorkerHandoff(t, spec)
			case "path":
				spec.Workspace.ID = "/caller/work"
				c.saveWorkerHandoff(t, spec)
			case "selection":
				spec.Injection.TaskSecretNames = []string{"different-selected-name"}
				c.saveWorkerHandoff(t, spec)
			case "runtime":
				failure := api.NotImplemented("lb-v2-admin", "admin.ResolveRuntime")
				c.helper.fail["runtime"] = failure
				code = api.CodeNotImplemented
			case "handoff":
				c.helper.fail["handoff"] = api.NotImplemented("lb-v2-service", "service.Handoff")
				code = api.CodeNotImplemented
			case "claim":
				var effect api.EffectRecord
				if err := c.store.read("worker-effect.json", &effect); err != nil {
					t.Fatal("cannot read worker claim control")
				}
				effect.State = api.EffectCompleted
				if err := c.store.save("worker-effect.json", effect); err != nil {
					t.Fatal("cannot expire worker claim control")
				}
				code = api.CodeConflict
			case "restart-binding":
				material, err := c.service.PrepareWorkerMaterial(context.Background(), spec, injection.SlotIDs[0])
				clear(material.Bytes)
				if err != nil {
					t.Fatal("cannot establish retained worker delivery control")
				}
				if err := c.backend.Close(); err != nil {
					t.Fatal("cannot restart worker broker")
				}
				c.backend = openMutationBackend(t, c.directory, c.clock, c.key)
				c.service = reopenLaunchService(t, c)
				_, err = c.service.SlotMaterial(context.Background(), spec.LaunchID, injection.SlotIDs[0])
				stageCode(t, err, api.CodeNotFound)
				return
			}
			_, err = c.service.PrepareWorkerMaterial(context.Background(), spec, injection.SlotIDs[0])
			stageCode(t, err, code)
		})
	}
}

func TestFixedWorkerDeliveryReplay(t *testing.T) {
	c, lease, credentials, _ := newWorkerCase(t)
	injection, err := c.service.InjectWorker(context.Background(), lease, credentials)
	if err != nil {
		t.Fatal("cannot prepare worker delivery replay control")
	}
	spec := c.retainWorkerSpec(t, lease, injection)
	material, err := c.service.PrepareWorkerMaterial(context.Background(), spec, injection.SlotIDs[0])
	clear(material.Bytes)
	if err != nil {
		t.Fatal("cannot establish worker delivery replay control")
	}
	spec.ID = "changed-worker-spec"
	c.saveWorkerHandoff(t, spec)
	material, err = c.service.PrepareWorkerMaterial(context.Background(), spec, injection.SlotIDs[0])
	clear(material.Bytes)
	stageCode(t, err, api.CodeConflict)
}

func reopenLaunchService(t *testing.T, c *launchCase) *Service {
	t.Helper()
	service, err := New(Dependencies{ProjectionIdentity: deniedProjection{}, Backend: c.backend, Store: c.store, Human: &humanFixture{}, Clock: c.clock, Config: "service-case", Grants: &launchCaseResolver{store: c.store, clock: c.clock}, Helper: c.helper, Control: c.control})
	if err != nil {
		t.Fatal("cannot reopen the protected launch broker")
	}
	return service
}

func TestPreparedAgentMaterial(t *testing.T) {
	c := newLaunchCase(t, "headless_token")
	grant, value := c.addSecret(t, "prepared-canary", "file", "task/token")
	slot, err := c.acquire(context.Background(), c.target, c.grant)
	if err != nil {
		t.Fatal("cannot prepare original agent profile")
	}
	injection, err := c.inject(context.Background(), c.target, []api.SecretGrant{grant})
	if err != nil {
		t.Fatal("cannot prepare original agent injection")
	}
	c.beforeBind = func(t *testing.T, spec api.LaunchSpec) {
		for index, want := range [][]byte{c.material, value} {
			material, err := c.service.PreparedSlotMaterial(context.Background(), spec, injection.SlotIDs[index])
			if err != nil || !bytes.Equal(material.Bytes, want) {
				t.Fatal("nonexecuting retained agent spec did not receive its exact selected material")
			}
			clear(material.Bytes)
		}
		if c.helper.process != nil {
			t.Fatal("prepared agent material lookup executed an agent")
		}
	}
	c.bind(t, slot, injection)
}
