//go:build linux && laneboss_root_canary

package admin

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// This measures a distinct-UID native prepared gate, not a provider delivery.
// The source claim/enrollment is a component input. No D6 approval is asserted.
func TestChannelGateNative(t *testing.T) {
	workerLaunchCanary(t, false, channelGateCanary)
}

func channelGateCanary(t *testing.T, ctx context.Context, m *leaseManager, data dataReg, runtime api.BlobRef, executable api.Executable) {
	t.Helper()
	parent, err := m.find(data.Request.AgentLeaseID)
	if err != nil {
		t.Fatal(err)
	}
	closeProc, err := mountHelperProc(m.binding.runtimePath())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := closeProc(); err != nil {
			t.Error(err)
		}
	}()
	ref := func(id api.ID, class string, raw []byte) api.BlobRef {
		return api.BlobRef{ID: id, Class: class, Bytes: int64(len(raw)), SHA256: digestBytes(raw)}
	}
	job := api.ChannelJob{ChannelID: "canary-channel", ChannelGeneration: 1, DestinationID: "canary-sink", MailID: "canary-mail", ProviderIdempotencyKey: "canary-key",
		Content: ref("channel-content", "report", []byte("native channel bytes")), Payload: ref("channel-payload", "channel_payload", []byte(`{"content":"native channel bytes"}`)), Artifacts: []api.BlobRef{},
		Runtime: &api.ChannelRuntime{Executable: executable, Manifest: runtime, Reconcile: "provider_key"},
		Lease: api.WorkerLease{ID: "channel-worker", Kind: "channel", Target: data.Worker.Target, OperationID: "channel-operation", EffectID: "channel-effect", GrantSetID: data.Worker.GrantSetID,
			RuntimeManifest: runtime, Generation: 1, ExpiresAt: api.Timestamp(time.Now().Add(2 * time.Minute).UTC().Format(time.RFC3339Nano))}}
	input, err := canonicalValue(api.ChannelSendInput{Schema: "laneboss.channel-input.v2", LeaseID: job.Lease.ID, MailID: job.MailID, ChannelID: job.ChannelID, ChannelGeneration: 1,
		DestinationID: job.DestinationID, ProviderIdempotencyKey: job.ProviderIdempotencyKey, Payload: job.Payload, Content: job.Content, Artifacts: job.Artifacts})
	if err != nil {
		t.Fatal(err)
	}
	job.Lease.Input = ref("channel-input", "channel_input", input)
	cause := parent.Request.Cause
	cause.Kind, cause.CauseOperationID, cause.EffectID, cause.Target = api.InternalMailDeliver, job.Lease.OperationID, job.Lease.EffectID, job.Lease.Target
	deadline := api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))
	r := channelReg{Job: job, LaunchID: "channel-launch", ParentLeaseID: parent.Lease.ID,
		Plan: api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: "channel", Input: job.Lease.Input, GrantSetID: job.Lease.GrantSetID, Executable: executable, Budget: parent.Request.Budget,
			Argv: []string{"laneboss", "internal", "channel", "--binding", "/runtime/laneboss-worker.json", "--lease", string(job.Lease.ID)}},
		Claim: api.EffectLease{ClaimID: "channel-claim", ExpiresAt: deadline, Record: api.EffectRecord{State: api.EffectClaimed, Generation: 2, ClaimID: "channel-claim", ClaimantID: cause.Actor.ID,
			ClaimExpiresAt: deadline, Effect: api.Effect{ID: job.Lease.EffectID, OperationID: job.Lease.OperationID, Context: &cause, Channel: &job}}}}
	allocation, err := m.allocateChannel(ctx, r)
	if err != nil {
		t.Fatal("channel native allocation unavailable", err)
	}
	if allocation.UID == parent.Lease.UID || allocation.UID == m.binding.Service.UID || allocation.UID == 0 {
		t.Fatal("channel did not receive its own native UID")
	}
	again, err := m.allocateChannel(ctx, r)
	if err != nil || again != allocation {
		t.Fatal("channel allocation replay replaced its original UID", err)
	}
	base := filepath.Join("/run/laneboss-v2/services", m.binding.Config)
	for _, directory := range []string{filepath.Dir(base), base, filepath.Join(base, "workers")} {
		if err := os.MkdirAll(directory, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Dir(base), 0755); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{base, filepath.Join(base, "workers")} {
		if err := os.Chown(directory, int(m.binding.Service.UID), int(m.binding.Service.GID)); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	service := api.InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision, Protocol: api.Protocol, APISchema: api.SchemaVersion,
		Config: m.binding.Config, Class: api.EndpointHuman, ServiceUID: m.binding.Service.UID, ServiceGID: m.binding.Service.GID,
		Socket: filepath.Join(base, "human.sock"), Backend: "linux-bwrap-landlock", ServiceVersion: m.binding.Release.Version, ArtifactSHA256: m.binding.Artifact.SHA256,
		InstallationGeneration: m.binding.Generation, EndpointGeneration: m.binding.Generation}
	service.MappedServiceUID, service.MappedServiceGID, err = wire.NamespaceServiceIDs()
	if err != nil {
		t.Fatal(err)
	}
	workerCanaryJSON(t, filepath.Join("/etc/laneboss-v2/bindings", m.binding.Config+".json"), service, 0444)
	endpoint := service
	endpoint.Class, endpoint.LaunchID, endpoint.WorkerLeaseID, endpoint.Target, endpoint.Socket = api.EndpointWorker, r.LaunchID, job.Lease.ID, &job.Lease.Target, "/runtime/laneboss-worker.sock"
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(base, "workers", string(job.Lease.ID)+".sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chown(listener.Addr().String(), int(service.ServiceUID), int(service.ServiceGID)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(listener.Addr().String(), 0666); err != nil {
		t.Fatal(err)
	}
	grants := data.Grants
	grants.ID, grants.LifeID = job.Lease.GrantSetID, job.Lease.Target.LifeID
	spec := api.LaunchSpec{ID: "channel-spec", Kind: "worker", LaunchID: r.LaunchID, Target: job.Lease.Target, Worker: &r.Plan, UIDLeaseID: allocation.ID,
		RuntimeManifest: runtime, Grants: grants, Budget: r.Plan.Budget, Backend: endpoint.Backend, EndpointGeneration: allocation.EndpointGeneration, PolicyGeneration: grants.PolicyGeneration,
		Materialization: api.Materialization{GrantSetID: grants.ID, Objects: []api.MaterializedObject{}},
		Injection:       api.Injection{Target: job.Lease.Target, Outcome: "prepared", SlotIDs: []api.ID{}, TaskSecretNames: []string{}, TaskSecretFileNames: []string{}, GrantIDs: []api.ID{}, SourceVersions: []string{}}}
	raw, err := canonicalValue(spec)
	if err != nil {
		t.Fatal(err)
	}
	register := cause
	register.Kind = api.InternalHelperRegister
	original := ref("channel-spec-object", "launch_spec", raw)
	handoff := api.PreparedSpecHandoff{Config: m.binding.Config, Cause: register, Spec: spec, Original: original, SpecSHA256: original.SHA256, OperationID: job.Lease.OperationID, RequestID: cause.CauseRequestID}
	if _, err := m.registerChannel(ctx, channelSeal{Reg: r, Spec: specRegistration{Handoff: handoff, Original: raw}, Endpoint: endpoint, Input: input}); err != nil {
		t.Fatal("channel native registration unavailable", err)
	}
	prepared, err := m.prepareChannel(ctx, r)
	if err != nil {
		t.Fatal("channel native gate unavailable", err)
	}
	live, ok := m.gates[allocation.ID].(*nativeGate)
	if !ok || prepared.ProcessGeneration == "" || live.innerPID <= 1 || live.released {
		t.Fatal("channel preparation did not retain an actual closed native gate")
	}
	collected := false
	defer func() {
		if collected {
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := live.Close(); err != nil {
			t.Error(err)
		}
		if err := m.waitContainmentEmpty(cleanup, channelChild(parent, channelNative{Reg: r, Lease: allocation})); err != nil {
			t.Error(err)
		}
	}()
	if _, err := workerDescriptor(live.workerFiles[0]); err != nil {
		t.Fatal("channel input was not retained as an actual sealed descriptor", err)
	}
	if _, err := workerDescriptor(live.workerFiles[1]); err != nil {
		t.Fatal("channel endpoint was not retained as an actual sealed descriptor", err)
	}
	if err := live.innerLifetime(m.bootID); err != nil {
		t.Fatal("channel native lifetime is unavailable", err)
	}
	if err := verifyPrivateNamespaces(live.innerPID); err != nil {
		t.Fatal(err)
	}
	snapshot, held, found, err := m.channelLaunchSnapshot(ctx, prepared.ID)
	if err != nil || !found || held != live || snapshot.Channel == nil || snapshot.Native.Lease != allocation || snapshot.Native.Peer.HostUID != allocation.UID ||
		snapshot.workerRegistration().Worker.ConsumedBy != r.LaunchID {
		t.Fatal("channel did not join its original native descriptor and identity tuple", err)
	}
	ticket, err := m.containment(ctx, containmentQuery{LeaseID: allocation.ID})
	if err != nil || ticket.Kind != api.EndpointWorker || ticket.WorkerLeaseID != job.Lease.ID || ticket.Lease != allocation {
		t.Fatal("channel containment did not resolve its actual worker lease", err)
	}
	replayed, err := m.prepareChannel(ctx, r)
	if err != nil || replayed != prepared {
		t.Fatal("channel prepare replay changed its actual native gate", err)
	}
	actual, err := m.reconcileChannel(ctx, r)
	if err != nil || actual.Prepared == nil || *actual.Prepared != prepared || actual.GateState != "prepared" || actual.Observation.State != "prepared" || actual.Process != nil || actual.ConsumedPermit != nil {
		t.Fatal("channel prepared recovery changed its original unopened gate", err)
	}
	lost := newLeaseManager(m.binding, m.bootID, m.store, m.resources)
	_, err = lost.prepareChannel(ctx, r)
	requireCode(t, err, api.CodeContainmentUnknown)
	if err := live.innerLifetime(m.bootID); err != nil {
		t.Fatal("lost-owner control replaced the original native lifetime", err)
	}
	if err := m.collectChannel(ctx, r); err != nil {
		t.Fatal("channel native preparation was not collected", err)
	}
	collected = true
	if err := m.collectChannel(ctx, r); err != nil {
		t.Fatal("channel native collection did not replay", err)
	}
	retained, err := m.find(parent.Lease.ID)
	if err != nil || len(retained.Channels) != 1 || !retained.Channels[0].Collected || retained.Channels[0].Observation == nil ||
		retained.Channels[0].Observation.State != "exited" || m.gates[allocation.ID] != nil {
		t.Fatal("channel native collection lost its measured retained record", err)
	}
}
