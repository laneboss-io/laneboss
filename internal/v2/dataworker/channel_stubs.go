package dataworker

import (
	"context"
	"errors"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/lstate"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

var _ api.ChannelWorker = (*Service)(nil)

func (s *Service) PrepareChannel(ctx context.Context, scope api.Scope, job api.ChannelJob) (api.ChannelExecution, error) {
	if err := s.channelPreflight(ctx, scope, job, ""); err != nil {
		return api.ChannelExecution{}, err
	}
	return api.ChannelExecution{}, api.NotImplemented("lb-v2-grants", "channel fixed-worker registration, committed identity permit and authenticated input/result handoff")
}
func (s *Service) SendChannel(ctx context.Context, scope api.Scope, execution api.ChannelExecution) (api.ChannelSendEvidence, error) {
	if err := s.channelExecution(ctx, scope, execution); err != nil {
		return api.ChannelSendEvidence{}, err
	}
	return api.ChannelSendEvidence{}, api.NotImplemented("lb-v2-grants", "channel authenticated fixed-worker credential injection, provider acknowledgement and measured read-back")
}
func (s *Service) ReadBackChannel(ctx context.Context, scope api.Scope, execution api.ChannelExecution) (api.ChannelSendEvidence, error) {
	if err := s.channelExecution(ctx, scope, execution); err != nil {
		return api.ChannelSendEvidence{}, err
	}
	return api.ChannelSendEvidence{}, api.NotImplemented("lb-v2-grants", "channel retained fixed-worker provider-key or receipt read-back without resending")
}

func (s *Service) channelExecution(ctx context.Context, scope api.Scope, execution api.ChannelExecution) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if err := api.ValidateChannelExecution(execution); err != nil {
		return err
	}
	if execution.Handoff.Config != scope.Config {
		return lstate.Error(api.CodeForbidden, "channel execution belongs to another configuration")
	}
	if err := s.channelPreflight(ctx, scope, execution.Job, execution.Binding.Record.ID); err != nil {
		return err
	}
	bound, err := s.deps.Store.LaunchBinding(ctx, execution.Binding.Record.ID)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(bound, execution.Binding) {
		return lstate.Error(api.CodeIntegrity, "channel worker binding differs from its committed identity")
	}
	return nil
}

func (s *Service) channelPreflight(ctx context.Context, caller api.Scope, job api.ChannelJob, consumer api.ID) (resultErr error) {
	scope, view, err := s.jobScope(ctx, caller)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, view.Close()) }()
	if err := api.ValidateChannelJob(job); err != nil {
		return err
	}
	effect, err := s.currentJob(ctx, scope, job.Lease, consumer)
	if err != nil {
		return err
	}
	if effect.Effect.Channel == nil || !reflect.DeepEqual(*effect.Effect.Channel, job) {
		return lstate.Error(api.CodeForbidden, "channel job differs from its retained outbox effect")
	}
	channel, err := s.deps.Store.Channel(ctx, scope, job.ChannelID)
	if err != nil {
		return err
	}
	if channel.ID != job.ChannelID || channel.Config != scope.Config || channel.Generation != job.ChannelGeneration ||
		channel.Revoked || channel.Runtime == nil || !reflect.DeepEqual(channel.Runtime, job.Runtime) {
		return lstate.Error(api.CodeForbidden, "channel job differs from its current protected runtime enrollment")
	}
	if _, err := manifest.Expiry(channel.ExpiresAt, s.deps.Clock.Now()); err != nil {
		return err
	}
	selected := false
	for _, destination := range channel.Destinations {
		selected = selected || destination.ID == job.DestinationID
	}
	if !selected {
		return lstate.Error(api.CodeForbidden, "channel job destination is no longer enrolled")
	}
	raw, err := s.jobObject(ctx, scope, job.Lease, job.Lease.Input)
	if err != nil {
		return err
	}
	var input api.ChannelSendInput
	if err := api.DecodeObject(raw, &input); err != nil {
		return err
	}
	if err := api.ValidateChannelInput(job, input); err != nil {
		return err
	}
	if _, err := s.jobObject(ctx, scope, job.Lease, job.Payload); err != nil {
		return err
	}
	return nil
}
