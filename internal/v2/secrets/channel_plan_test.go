package secrets

import (
	"context"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// The plan source is explicit component metadata. The broker journal,
// selected source fetch, encryption and injection receipt are real.
type channelPlanCase struct {
	api.StateStore
	read func() (api.WorkerPlan, error)
}

func (s channelPlanCase) ChannelPlan(ctx context.Context, scope api.Scope, lease api.EffectLease) (api.WorkerPlan, error) {
	current, err := s.StateStore.Effect(ctx, scope, lease.Record.Effect.ID)
	if err != nil {
		return api.WorkerPlan{}, err
	}
	if !reflect.DeepEqual(current, lease.Record) {
		return api.WorkerPlan{}, &api.Error{Code: api.CodeConflict, Message: "component channel plan lost its actual effect"}
	}
	return s.read()
}

func TestChannelEffectInjection(t *testing.T) {
	c, lease, requested, _ := newWorkerCase(t, "channel")
	var effect api.EffectRecord
	if err := c.store.read("worker-effect.json", &effect); err != nil {
		t.Fatal(err)
	}
	plan := *effect.Effect.Worker
	plan.Argv = []string{"laneboss", "internal", "channel", "--binding", "/runtime/laneboss-worker.json", "--lease", string(lease.ID)}
	job := api.ChannelJob{Lease: lease, ChannelID: "channel", ChannelGeneration: 1, DestinationID: "destination", MailID: "mail", ProviderIdempotencyKey: "provider-key",
		Runtime: &api.ChannelRuntime{Executable: plan.Executable, Manifest: lease.RuntimeManifest, Reconcile: "provider_key"}, Artifacts: []api.BlobRef{},
		Payload: c.store.putObject(t, "channel-payload", "channel_payload", map[string]string{"content": "channel input"}, lease.OperationID),
		Content: c.store.putObject(t, "channel-content", "report", "channel input", lease.OperationID)}
	input := api.ChannelSendInput{Schema: "laneboss.channel-input.v2", LeaseID: lease.ID, MailID: job.MailID, ChannelID: job.ChannelID, ChannelGeneration: job.ChannelGeneration,
		DestinationID: job.DestinationID, ProviderIdempotencyKey: job.ProviderIdempotencyKey, Payload: job.Payload, Content: job.Content, Artifacts: job.Artifacts}
	lease.Input = c.store.putObject(t, "channel-fixed-input", "channel_input", input, lease.OperationID)
	job.Lease, plan.Input = lease, lease.Input
	effect.Effect.Worker, effect.Effect.Channel = nil, &job
	if err := api.ValidateChannelJob(job); err != nil {
		t.Fatal(err)
	}
	if err := c.store.save("worker-effect.json", effect); err != nil {
		t.Fatal(err)
	}
	if err := c.store.save("channel-plan.json", plan); err != nil {
		t.Fatal(err)
	}
	c.store.lease = lease
	c.service.deps.Store = channelPlanCase{StateStore: c.store, read: func() (api.WorkerPlan, error) {
		var retained api.WorkerPlan
		err := c.store.read("channel-plan.json", &retained)
		return retained, err
	}}
	injection, err := c.service.InjectWorker(context.Background(), lease, requested)
	if err != nil || len(injection.SlotIDs) != 1 {
		t.Fatal("actual Channel effect did not prepare its selected worker credential", err)
	}
	slot := readCaseSlot(t, c, injection.SlotIDs[0])
	defer clear(slot.Material)
	defer clear(slot.Returned)
	if slot.WorkerPlan == nil || !reflect.DeepEqual(*slot.WorkerPlan, plan) || slot.WorkerLease == nil || *slot.WorkerLease != lease || slot.Grant.SourceHandle != requested[0].SourceHandle {
		t.Fatal("channel injection lost its frozen plan, original lease or selected source")
	}
}
