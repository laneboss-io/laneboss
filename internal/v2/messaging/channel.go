package messaging

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Service) enrolledChannel(ctx context.Context, scope api.Scope, id api.ID) (api.EnrolledChannel, error) {
	channel, err := s.deps.Store.Channel(ctx, scope, id)
	if err != nil {
		return api.EnrolledChannel{}, err
	}
	if channel.ID != id || channel.Config != scope.Config || channel.Generation == 0 || !validID(channel.Source.ID) || !validDigest(channel.Source.SHA256) || channel.Source.Generation == 0 || len(channel.Destinations) == 0 || len(channel.Destinations) > 200 {
		return api.EnrolledChannel{}, problem(api.CodeIntegrity, "channel enrollment has invalid retained source or destinations")
	}
	if channel.Revoked || !future(channel.ExpiresAt, s.deps.Clock.Now()) {
		return api.EnrolledChannel{}, problem(api.CodeForbidden, "channel enrollment is revoked or expired")
	}
	seen := make(map[api.ID]bool)
	for _, destination := range channel.Destinations {
		if !validID(destination.ID) || seen[destination.ID] || destination.Transport == "" || !validID(destination.EndpointID) || !validID(destination.CredentialHandle) || destination.DeliverySemantics == "" {
			return api.EnrolledChannel{}, problem(api.CodeIntegrity, "channel destination has invalid identity or delivery semantics")
		}
		seen[destination.ID] = true
	}
	return channel, nil
}

func (s *Service) channelJob(ctx context.Context, scope api.Scope, job api.ChannelJob) error {
	if err := internalScope(ctx, scope); err != nil {
		return err
	}
	lease, err := s.deps.Store.WorkerLease(ctx, scope, job.Lease.ID)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(lease, job.Lease) || lease.Kind != "channel" || !validID(lease.ID) || lease.Generation == 0 || !validID(lease.EffectID) || !validID(lease.OperationID) || !future(lease.ExpiresAt, s.deps.Clock.Now()) || lease.ConsumedBy != "" {
		return problem(api.CodeForbidden, "channel job requires its current unconsumed worker lease")
	}
	channel, err := s.enrolledChannel(ctx, scope, job.ChannelID)
	if err != nil {
		return err
	}
	if channel.Generation != job.ChannelGeneration || !validID(job.MailID) || !validID(job.ProviderIdempotencyKey) {
		return problem(api.CodeConflict, "channel job differs from the current enrollment generation")
	}
	selected := false
	for _, destination := range channel.Destinations {
		if destination.ID == job.DestinationID {
			selected = true
		}
	}
	if !selected {
		return problem(api.CodeForbidden, "channel job selects no enrolled destination")
	}
	effect, err := s.deps.Store.Effect(ctx, scope, lease.EffectID)
	if err != nil {
		return err
	}
	if effect.Effect.OperationID != lease.OperationID || effect.Effect.Channel == nil || !reflect.DeepEqual(*effect.Effect.Channel, job) {
		return problem(api.CodeForbidden, "channel job differs from the immutable outbox job")
	}
	return nil
}

func (s *Service) DeliverChannel(ctx context.Context, scope api.Scope, job api.ChannelJob) (api.Delivery, error) {
	if err := s.channelJob(ctx, scope, job); err != nil {
		return api.Delivery{}, err
	}
	if s.deps.Launcher == nil || s.deps.Credentials == nil {
		return api.Delivery{}, problem(api.CodePrerequisite, "channel execution requires the contracted launcher and credential broker")
	}
	// The lease/enrollment objects do not supply an atomic worker-claim port
	// or fixed transport/result/read-back contract. Do not send as service UID
	// or turn process success text into a provider receipt. See CONTRACTS.md.
	return api.Delivery{}, api.NotImplemented(owner, "channel.worker.transport")
}

func (s *Service) ReconcileChannel(ctx context.Context, scope api.Scope, job api.ChannelJob) (api.Delivery, error) {
	if err := s.channelJob(ctx, scope, job); err != nil {
		return api.Delivery{}, err
	}
	// A missing read-back capability cannot authorize another external send.
	return api.Delivery{}, api.NotImplemented(owner, "channel.worker.readback")
}
