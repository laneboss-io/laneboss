package lifecycle

import (
	"context"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// InputControl is a protected service/helper port. Planning retains immutable
// input and a fixed channel-worker plan but performs no write or resize. The
// public transaction persists the lease/effect and consumes its real authority.
// WriteInput rechecks the current native channel, requester rights and original
// claim under the channel lock, journals exact accepted bytes/dimensions by
// effect ID, and reconciles uncertain writes instead of repeating them.
type InputControl interface {
	PlanInput(context.Context, api.Scope, InputIntent) (InputJob, error)
	InputJob(context.Context, api.Scope, api.ID) (InputJob, error)
	InputChannel(context.Context, api.Scope, api.ID) (InputChannel, error)
	WriteInput(context.Context, api.Scope, api.EffectLease, InputJob) (InputReceipt, error)
}

type InputChannel struct {
	ID                api.ID
	LaunchID          api.ID
	Process           api.ProcessHandle
	Generation        api.Generation
	CancellationEpoch api.Generation
	ExpiresAt         api.Timestamp
	Closed            bool
}

type InputIntent struct {
	Request            api.AttachInputRequest
	OperationID        api.ID
	RequestID          api.ID
	RequestSHA256      api.Digest
	RequestedBy        api.Actor
	LaunchID           api.ID
	ExpectedGeneration api.Generation
	CancellationEpoch  api.Generation
}

type InputJob struct {
	Intent          InputIntent
	OriginalRequest api.BlobRef
	Channel         InputChannel
	Lease           api.WorkerLease
	Plan            api.WorkerPlan
}

type InputWrite struct {
	OperationID       api.ID         `json:"operation_id"`
	EffectID          api.ID         `json:"effect_id"`
	ChannelID         api.ID         `json:"channel_id"`
	ChannelGeneration api.Generation `json:"channel_generation"`
	LaunchID          api.ID         `json:"launch_id"`
	InputSHA256       api.Digest     `json:"input_sha256"`
	AcceptedBytes     int64          `json:"accepted_bytes"`
	Columns           uint16         `json:"columns"`
	Rows              uint16         `json:"rows"`
	ObservedAt        api.Timestamp  `json:"observed_at"`
}

type InputReceipt struct {
	Write       InputWrite
	Observation api.ProcessObservation
	Evidence    api.BlobRef
}

type inputEvidence struct {
	Write       InputWrite
	Observation api.ProcessObservation
}

func (s *Service) inputControl() (InputControl, error) {
	control := s.deps.Input
	if absent(control) {
		control, _ = s.deps.Store.(InputControl)
	}
	if absent(control) {
		return nil, api.NotImplemented("lb-v2-service", "leased input channel worker control")
	}
	return control, nil
}

func (s *Service) validateInputJob(ctx context.Context, scope api.Scope, control InputControl, lane api.Lane,
	handle api.ProcessHandle, intent InputIntent, job InputJob) error {
	if !reflect.DeepEqual(job.Intent, intent) || job.Channel.ID != intent.Request.ChannelID || job.Channel.LaunchID != lane.LaunchID ||
		job.Channel.Process != handle || job.Channel.CancellationEpoch != lane.CancellationEpoch || !validGeneration(job.Channel.Generation) || job.Channel.Closed {
		return integrity("input job changed its current native channel or intent")
	}
	channel, err := control.InputChannel(ctx, scope, job.Channel.ID)
	if err != nil {
		return failure(err)
	}
	if channel != job.Channel {
		return integrity("input channel lease changed before its effect")
	}
	expires, err := time.Parse(time.RFC3339Nano, string(channel.ExpiresAt))
	if err != nil || !s.deps.Clock.Now().Before(expires) {
		return problem(api.CodeConflict, "input channel lease expired", "Attach to the current run and obtain its live channel.")
	}
	retained, err := control.InputJob(ctx, scope, intent.OperationID)
	if err != nil {
		return failure(err)
	}
	if !reflect.DeepEqual(retained, job) || job.Lease.Kind != "channel" || job.Plan.Kind != "channel" ||
		job.Plan.Schema != "laneboss.worker-plan.v2" || !validID(job.Lease.ID) || !validID(job.Lease.EffectID) ||
		job.Lease.Target != intent.Request.Target || job.Lease.OperationID != intent.OperationID || !validGeneration(job.Lease.Generation) ||
		job.Plan.Input != job.Lease.Input || job.Plan.GrantSetID != job.Lease.GrantSetID || !validBudget(job.Plan.Budget) {
		return integrity("input has no exact retained channel worker plan")
	}
	raw, err := s.operationBlob(ctx, scope, job.OriginalRequest, intent.OperationID)
	if err != nil {
		return err
	}
	var original api.Request
	var originalInput api.AttachInputRequest
	if api.DecodeObject(raw, &original) != nil || original.Config != scope.Config || original.Method != "lane.input" ||
		original.RequestID != intent.RequestID || original.RequestSHA256 != intent.RequestSHA256 ||
		api.DecodeObject(original.Params, &originalInput) != nil || !reflect.DeepEqual(originalInput, intent.Request) {
		return integrity("input job changed its original authenticated request")
	}
	digest, err := api.RequestDigest(original)
	if err != nil || digest != intent.RequestSHA256 {
		return integrity("input original request digest changed")
	}
	raw, err = s.operationBlob(ctx, scope, job.Lease.Input, intent.OperationID)
	if err != nil {
		return err
	}
	var actual InputIntent
	if api.DecodeObject(raw, &actual) != nil || !reflect.DeepEqual(actual, intent) {
		return integrity("input worker lost its exact bounded request bytes")
	}
	raw, err = s.readBlob(ctx, scope, job.Lease.RuntimeManifest)
	if err != nil {
		return err
	}
	var runtime api.RuntimeManifest
	if api.DecodeObject(raw, &runtime) != nil || job.Plan.Executable != runtime.Bootstrap ||
		!reflect.DeepEqual(job.Plan.Argv, []string{"laneboss", "internal", "worker", "--binding", "/runtime/laneboss-worker.json", "--lease", string(job.Lease.ID)}) {
		return integrity("input worker differs from its installed bootstrap")
	}
	grants, err := s.deps.Store.Grants(ctx, job.Lease.GrantSetID)
	if err != nil {
		return failure(err)
	}
	policy, err := s.deps.Store.Policy(ctx, scope)
	if err != nil {
		return failure(err)
	}
	if grants.ID != job.Lease.GrantSetID || grants.LifeID != lane.LifeID || grants.Revoked || grants.PolicyGeneration != policy.Generation ||
		scope.PolicyGeneration != policy.Generation || len(grants.Resources)+len(grants.Data)+len(grants.Secrets)+len(grants.Profiles)+len(grants.Network) != 0 ||
		len(grants.Channels) != 1 || grants.Channels[0].ChannelID != channel.ID || grants.Channels[0].Delegate {
		return integrity("input worker exceeds its current single channel authority")
	}
	for _, expiry := range []api.Timestamp{job.Lease.ExpiresAt, grants.ExpiresAt, grants.Channels[0].ExpiresAt} {
		end, err := time.Parse(time.RFC3339Nano, string(expiry))
		if err != nil || !s.deps.Clock.Now().Before(end) {
			return problem(api.CodeConflict, "input worker authority expired", "Reconcile the original input job under current authority.")
		}
	}
	return nil
}

// ApplyInput is the original service outbox's leased IO stage. The returned
// receipt is measured completion for that same worker operation, not an RPC
// that accepts a caller-selected process, file descriptor or terminal path.
func (s *Service) ApplyInput(ctx context.Context, scope api.Scope, lease api.EffectLease) (InputReceipt, error) {
	cause, err := s.lifecycleClaim(ctx, scope, lease)
	if err != nil {
		return InputReceipt{}, err
	}
	control, err := s.inputControl()
	if err != nil {
		return InputReceipt{}, err
	}
	job, err := control.InputJob(ctx, scope, cause.CauseOperationID)
	if err != nil {
		return InputReceipt{}, failure(err)
	}
	if job.Intent.OperationID != cause.CauseOperationID || job.Intent.RequestID != cause.CauseRequestID || job.Intent.RequestedBy != cause.RequestedBy ||
		job.Intent.Request.Target != cause.Target || job.Intent.CancellationEpoch != cause.CancellationEpoch ||
		!reflect.DeepEqual(lease.Record.Effect, api.Effect{ID: job.Lease.EffectID, OperationID: cause.CauseOperationID, Context: lease.Record.Effect.Context, Worker: &job.Plan}) {
		return InputReceipt{}, integrity("input effect differs from its original channel job")
	}
	unlock, err := s.lockLife(ctx, cause.Target.LifeID)
	if err != nil {
		return InputReceipt{}, err
	}
	defer unlock()
	lane, err := s.lane(ctx, scope, cause.Target, true)
	if err != nil {
		return InputReceipt{}, err
	}
	if lane.State != "running" || lane.Cleaned || lane.LaunchID != job.Intent.LaunchID || lane.Generation != job.Intent.ExpectedGeneration || lane.CancellationEpoch != cause.CancellationEpoch {
		return InputReceipt{}, problem(api.CodeConflict, "input effect was superseded", "Preserve its receipt and attach to the current run.")
	}
	observation, facts, err := s.observe(ctx, scope, lane, cause.Target)
	if err != nil {
		return InputReceipt{}, err
	}
	if observation.State != "running" || observation.Survivors == nil || *observation.Survivors == 0 {
		return InputReceipt{}, problem(api.CodeConflict, "input process exited before delivery", "Preserve its original receipt and current run outcome.")
	}
	if err := s.validateInputJob(ctx, scope, control, lane, facts.handle, job.Intent, job); err != nil {
		return InputReceipt{}, err
	}
	// The original current authorization is rechecked by InputControl under
	// its native channel lock; an internal service actor is never relabelled.
	current, err := control.InputChannel(ctx, scope, job.Channel.ID)
	if err != nil {
		return InputReceipt{}, failure(err)
	}
	if current != job.Channel || current.Closed || current.Process != facts.handle {
		return InputReceipt{}, problem(api.CodeConflict, "input channel is no longer current", "Reconcile the original IO job without writing a replacement channel.")
	}
	worker, err := s.deps.Store.WorkerLease(ctx, scope, job.Lease.ID)
	if err != nil {
		return InputReceipt{}, failure(err)
	}
	want := job.Lease
	want.Generation, want.ConsumedBy = worker.Generation, worker.ConsumedBy
	if worker.Generation < job.Lease.Generation || worker.Generation > job.Lease.Generation+1 || !reflect.DeepEqual(worker, want) {
		return InputReceipt{}, integrity("input effect lost its retained worker lease")
	}
	principal, err := s.deps.Store.Launch(ctx, worker.ConsumedBy)
	if err != nil {
		return InputReceipt{}, failure(err)
	}
	if principal.ID != worker.ConsumedBy || principal.Kind != "worker" || principal.Actor.Kind != "worker" || principal.Actor.Level != 0 || principal.Actor.Role != "" ||
		principal.HostUID == 0 || principal.Config != scope.Config || principal.Target != cause.Target || principal.GrantSetID != worker.GrantSetID ||
		!validID(principal.ContainmentID) || principal.ProcessGeneration == "" || principal.Revoked {
		return InputReceipt{}, integrity("input has no current confined worker principal")
	}
	agent, err := s.deps.Store.Launch(ctx, lane.LaunchID)
	if err != nil {
		return InputReceipt{}, failure(err)
	}
	if principal.HostUID == agent.HostUID {
		return InputReceipt{}, integrity("input worker reused the agent principal")
	}
	if _, err := s.lifecycleClaim(ctx, scope, lease); err != nil {
		return InputReceipt{}, err
	}
	result, err := control.WriteInput(ctx, scope, lease, job)
	if err != nil {
		return InputReceipt{}, failure(err)
	}
	write, request := result.Write, job.Intent.Request
	if write.OperationID != cause.CauseOperationID || write.EffectID != lease.Record.Effect.ID || write.ChannelID != job.Channel.ID ||
		write.ChannelGeneration != job.Channel.Generation || write.LaunchID != lane.LaunchID || write.InputSHA256 != digestOfBytes(request.Input) ||
		write.AcceptedBytes != int64(len(request.Input)) || write.Columns != request.Columns || write.Rows != request.Rows || !validTime(write.ObservedAt) {
		return InputReceipt{}, integrity("input receipt does not prove the exact write and resize")
	}
	observation = result.Observation
	if validateObservation(observation.Handle, observation) != nil || requireQuiescence(observation) != nil ||
		observation.ExitCode == nil || *observation.ExitCode != 0 || observation.Handle.Target != cause.Target ||
		observation.Handle.ContainmentID != principal.ContainmentID || observation.Handle.Generation != principal.ProcessGeneration {
		return InputReceipt{}, integrity("input worker has no successful measured completion")
	}
	raw, err := s.operationBlob(ctx, scope, result.Evidence, cause.CauseOperationID)
	if err != nil {
		return InputReceipt{}, err
	}
	var actual inputEvidence
	if api.DecodeObject(raw, &actual) != nil || actual.Write != write || !reflect.DeepEqual(actual.Observation, result.Observation) {
		return InputReceipt{}, integrity("input receipt differs from its retained native evidence")
	}
	if _, err := s.lifecycleClaim(ctx, scope, lease); err != nil {
		return InputReceipt{}, err
	}
	return result, nil
}
