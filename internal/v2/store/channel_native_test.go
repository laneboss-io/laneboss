//go:build linux

package store_test

import (
	"context"
	"os"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/messaging"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

type channelNativeStore interface {
	ChannelWorkerID(context.Context, api.Scope, api.EffectLease) (api.ID, error)
	ChannelPlan(context.Context, api.Scope, api.EffectLease) (api.WorkerPlan, error)
	ChannelHandoff(context.Context, api.Scope, api.EffectLease, api.HelperLease, api.InstalledBinding, api.Injection) (api.PreparedSpecHandoff, error)
	BindChannelWorker(context.Context, api.Scope, api.EffectLease, api.PreparedLaunch) (api.LaunchBindingRequest, error)
}

// Native allocation/prepared facts are component inputs. All plan, spec,
// lease assignment, identity events and exact replays use the real writer.
func TestChannelNativeStage(t *testing.T) {
	f, _ := channelReady(t)
	var input api.MailSendRequest
	if err := api.DecodeObject(f.Human.Request.Params, &input); err != nil {
		t.Fatal(err)
	}
	f.Human.Connection.(*fx.Connection).Endpoint.ContractRevision = api.ContractRevision
	ctx := item3Admit(t, f, "mail.send", input)
	mail, err := messaging.New(messaging.Dependencies{Store: f.State, Clock: f.Deps.Clock, Preparer: channelPrep{f}})
	if err != nil {
		t.Fatal(err)
	}
	queued, err := mail.MailSend(ctx, f.Human, input)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := f.State.PendingEffects(ctx, api.CursorRequest{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	var job api.ChannelJob
	for _, effect := range pending {
		if effect.Channel != nil && effect.Channel.MailID == queued.ID {
			job = *effect.Channel
		}
	}
	claim, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: job.Lease.EffectID, ExpectedGeneration: 1,
		ClaimantID: f.Execution.Actor.ID, Deadline: job.Lease.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	native, ok := any(f.State).(channelNativeStore)
	if !ok {
		t.Fatal("channel native writer ports are unavailable")
	}
	id, err := native.ChannelWorkerID(ctx, f.Execution, claim)
	if err != nil {
		t.Fatal("channel native worker reservation failed", err)
	}
	repeated, err := native.ChannelWorkerID(ctx, f.Execution, claim)
	if err != nil || id == "" || repeated != id {
		t.Fatal("channel native worker reservation changed on replay", err)
	}
	plan, err := native.ChannelPlan(ctx, f.Execution, claim)
	if err != nil || plan.Input != job.Lease.Input || plan.Kind != "channel" || plan.Executable != job.Runtime.Executable {
		t.Fatal("channel native plan changed its fixed source", err)
	}
	allocation := api.HelperLease{ID: fx.ID(t), UID: uint32(os.Geteuid()) + 1, GID: uint32(os.Getegid()) + 1, ContainmentID: fx.ID(t), EndpointGeneration: 1}
	endpoint := api.InstalledBinding{Schema: "laneboss.binding.v2", Protocol: api.Protocol, APISchema: api.SchemaVersion, ContractRevision: api.ContractRevision,
		Config: f.Deps.Config, Class: api.EndpointWorker, InstallationGeneration: 1, EndpointGeneration: 1, ServiceUID: uint32(os.Geteuid()), ServiceGID: uint32(os.Getegid()),
		Socket: "/runtime/laneboss-worker.sock", Backend: "linux-bwrap-landlock", ArtifactSHA256: job.Runtime.Executable.SHA256, ServiceVersion: job.Runtime.Executable.Version,
		LaunchID: id, Target: &job.Lease.Target, WorkerLeaseID: job.Lease.ID}
	injection := api.Injection{Target: job.Lease.Target, Outcome: "prepared", SlotIDs: []api.ID{}, TaskSecretNames: []string{}, TaskSecretFileNames: []string{}, GrantIDs: []api.ID{}, SourceVersions: []string{}}
	handoff, err := native.ChannelHandoff(ctx, f.Execution, claim, allocation, endpoint, injection)
	if err != nil {
		t.Fatal("channel native handoff failed", err)
	}
	again, err := native.ChannelHandoff(ctx, f.Execution, claim, allocation, endpoint, injection)
	if err != nil || !reflect.DeepEqual(handoff, again) || !reflect.DeepEqual(*handoff.Spec.Worker, plan) {
		t.Fatal("channel native spec bytes changed on replay", err)
	}
	prepared := api.PreparedLaunch{ID: fx.ID(t), GateID: fx.ID(t), Target: job.Lease.Target, ContainmentID: allocation.ContainmentID,
		EndpointGeneration: 1, SpecSHA256: handoff.SpecSHA256, ProcessGeneration: "component:channel"}
	binding, err := native.BindChannelWorker(ctx, f.Execution, claim, prepared)
	if err != nil {
		t.Fatal("channel native identity did not commit", err)
	}
	replay, err := native.BindChannelWorker(ctx, f.Execution, claim, prepared)
	if err != nil || !reflect.DeepEqual(binding, replay) {
		t.Fatal("channel native identity replay changed its receipt", err)
	}
	if err := api.ValidateChannelExecution(api.ChannelExecution{Job: job, Handoff: handoff, Binding: binding}); err != nil {
		t.Fatal("channel native execution lost its actual committed identity", err)
	}
	lease, err := f.State.WorkerLease(ctx, f.Execution, job.Lease.ID)
	if err != nil || lease.ConsumedBy != id || lease.Generation != job.Lease.Generation+1 {
		t.Fatal("channel native handoff did not assign its original lease", err)
	}
	verification, err := f.State.Verify(ctx, api.VerifyRequest{Scope: "all"})
	if err != nil || !verification.OK {
		t.Fatal("channel native writer damaged retained store integrity", err)
	}
}
