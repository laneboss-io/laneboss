package store

import (
	"context"
	"slices"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func (s *Service) channelRead(ctx context.Context, scope api.Scope, id api.ID) (result api.EnrolledChannel, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return result, err
	}
	if err := s.readScope(ctx, scope); err != nil {
		return result, err
	}
	db, err := s.reader(scope)
	if err != nil {
		return result, err
	}
	if !internalScope(scope) {
		var lane api.Lane
		if scope.Actor.Kind != "lane" || scope.Actor.Level < 5 {
			return result, fault(api.CodeForbidden, "channel metadata requires an enrolled channel grant")
		}
		if err := storedProjection(ctx, db, "lane", scope.Actor.LifeID, &lane); err != nil {
			return result, err
		}
		var grants api.GrantSet
		if err := storedProjection(ctx, db, "grants", lane.GrantSetID, &grants); err != nil {
			return result, err
		}
		found := false
		for _, grant := range grants.Channels {
			found = found || grant.ChannelID == id && future(grant.ExpiresAt, s.deps.Clock.Now())
		}
		if !found || grants.Revoked {
			return result, fault(api.CodePrerequisite, "D6 channel enrollment and grant are required")
		}
	}
	if err := storedProjection(ctx, db, "channel", id, &result); err != nil {
		return result, err
	}
	if result.Revoked || result.Config != scope.Config || !future(result.ExpiresAt, s.deps.Clock.Now()) {
		return api.EnrolledChannel{}, fault(api.CodePrerequisite, "current D6 channel enrollment is required")
	}
	return result, nil
}

func (s *Service) publicChannel(ctx context.Context, db queryer, input api.Transaction, from api.Lane, mail api.Mail, request api.MailSendRequest) error {
	effect := input.Effects[0]
	if effect.Channel == nil || effect.Deliver != nil || len(input.Writes.WorkerLeases) != 1 || from.Level < 5 || effect.Context == nil {
		return fault(api.CodeForbidden, "channel publication requires its staged lease and channel effect")
	}
	job := *effect.Channel
	var stage channelStage
	if err := storedProjection(ctx, db, "channel_stage", channelKey(job.Lease.OperationID, job.DestinationID), &stage); err != nil {
		return err
	}
	if stage.Actor != input.Scope.Actor || !sameValue(stage.Frame, input.Scope.Request) || !sameValue(stage.Job, job) ||
		stage.Request.ChannelGrantID != request.ChannelGrantID || !sameValue(input.Writes.WorkerLeases[0], job.Lease) || job.Lease.GrantSetID != from.GrantSetID ||
		mail.ID != job.MailID || mail.Sender != input.Scope.Actor || mail.ChannelGrantID != request.ChannelGrantID || mail.RecipientLifeID != "" ||
		mail.Content != request.Content || mail.Content != job.Content || !slices.Equal(mail.Artifacts, job.Artifacts) || mail.Ask != request.Ask ||
		mail.ReplyTo != request.ReplyTo || mail.Source != input.Scope.Source || mail.Status != "queued" || mail.Generation != 1 || mail.QueuedSeq != 0 {
		return fault(api.CodeConflict, "channel publication differs from its exact staged request")
	}
	var channel api.EnrolledChannel
	if err := storedProjection(ctx, db, "channel", job.ChannelID, &channel); err != nil {
		return err
	}
	if channel.Revoked || channel.Generation != job.ChannelGeneration || !sameValue(channel.Runtime, job.Runtime) || !future(channel.ExpiresAt, s.deps.Clock.Now()) {
		return fault(api.CodeConflict, "channel enrollment changed before queue publication")
	}
	expected := 1
	if input.Scope.Request.Method == "report.submit" {
		expected = 2
	}
	if len(input.Events) != expected || effect.ID != job.Lease.EffectID || effect.Context.Target != job.Lease.Target || effect.Context.CancellationEpoch != from.CancellationEpoch {
		return fault(api.CodeConflict, "channel queue lost its original effect or cancellation fence")
	}
	for _, event := range input.Events {
		var payload api.Mail
		if wire.Decode(event.Payload, &payload) != nil || !sameValue(payload, mail) {
			return fault(api.CodeIntegrity, "channel queue event differs from the staged mail")
		}
	}
	return nil
}

func (s *Service) channelJob(ctx context.Context, scope api.Scope, request api.ChannelJobRequest) (result api.ChannelJob, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return result, err
	}
	if err := s.scope(ctx, s.db, scope); err != nil {
		return result, err
	}
	if scope.Actor.Kind != "service" || scope.Connection != nil {
		return result, fault(api.CodeForbidden, "channel execution requires its claimed service job")
	}
	claim, err := effectRow(ctx, s.db, request.Lease.Record.Effect.ID)
	if err != nil {
		return result, err
	}
	if !sameValue(claim, request.Lease.Record) || claim.ClaimantID != scope.Actor.ID || claim.Outcome != nil || claim.Effect.Channel == nil || !future(claim.ClaimExpiresAt, s.deps.Clock.Now()) {
		return result, fault(api.CodeConflict, "channel job claim changed or expired")
	}
	result = *claim.Effect.Channel
	var stage channelStage
	if err := storedProjection(ctx, s.db, "channel_stage", channelKey(result.Lease.OperationID, result.DestinationID), &stage); err != nil {
		return result, err
	}
	if request.MailID != result.MailID || request.ChannelGrantID != stage.Request.ChannelGrantID || request.DestinationID != result.DestinationID || !sameValue(stage.Job, result) {
		return api.ChannelJob{}, fault(api.CodeConflict, "channel job selector changed its original request")
	}
	return result, nil
}
