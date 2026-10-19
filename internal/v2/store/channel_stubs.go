package store

import (
	"context"
	"database/sql"
	"strings"
	"time"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

type channelStage struct {
	Request api.ChannelPrepareRequest
	Job     api.ChannelJob
	Actor   api.Actor
	Frame   api.Request
	Native  *channelLaunch `json:",omitempty"`
}

func channelKey(operation, destination api.ID) api.ID {
	return api.ID(hash([]byte(string(operation) + "\x00" + string(destination))))
}

func channelMail(config string, actor api.Actor, request api.Request) api.ID {
	parts := []string{"laneboss.mail.v2", config, actor.Kind, string(actor.ID), string(actor.LifeID), string(request.Method), string(request.IdempotencyKey)}
	return api.ID("mail-" + hash([]byte(strings.Join(parts, "\x00"))))
}

func (s *Service) PrepareChannelJob(ctx context.Context, scope api.Scope, request api.ChannelPrepareRequest) (result api.ChannelJob, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return result, err
	}
	if err := s.scope(ctx, s.db, scope); err != nil {
		return result, err
	}
	if scope.Actor.Kind != "service" || scope.Connection != nil || scope.Frame != nil || scope.Request.Method != "" {
		return result, fault(api.CodeForbidden, "channel preparation requires its service coordinator")
	}
	var raw []byte
	if err := s.db.QueryRowContext(ctx, "SELECT request FROM reservations WHERE operation_id=?", string(request.OperationID)).Scan(&raw); err != nil {
		if err == sql.ErrNoRows {
			return result, fault(api.CodePrerequisite, "channel preparation needs its original pending public request")
		}
		return result, err
	}
	frame, err := wire.DecodeRequest(raw)
	if err != nil {
		return result, err
	}
	var actor api.Actor
	if err := storedProjection(ctx, s.db, "reservation_actor", request.OperationID, &actor); err != nil {
		return result, err
	}
	var content api.BlobRef
	artifacts := []api.BlobRef{}
	var selected api.ID
	switch frame.Method {
	case "mail.send":
		var input api.MailSendRequest
		if err := api.DecodeObject(frame.Params, &input); err != nil {
			return result, err
		}
		content, selected = input.Content, input.ChannelGrantID
	case "report.submit":
		var input api.ReportRequest
		if err := api.DecodeObject(frame.Params, &input); err != nil {
			return result, err
		}
		content, selected, artifacts = input.Content, input.ChannelGrantID, append(artifacts, input.Artifacts...)
	default:
		return result, fault(api.CodeInvalid, "channel preparation requires a mail or report request")
	}
	if frame.Config != scope.Config || selected == "" || selected != request.ChannelGrantID || actor.Kind != "lane" {
		return result, fault(api.CodeForbidden, "channel selection differs from its original requester")
	}
	var lane api.Lane
	if err := storedProjection(ctx, s.db, "lane", actor.LifeID, &lane); err != nil {
		return result, err
	}
	if lane.Cleaned || lane.Level < 5 || lane.Level != actor.Level || lane.Role != actor.Role {
		return result, fault(api.CodeForbidden, "channel requires its current L5 or L6 sender")
	}
	var grants api.GrantSet
	if err := storedProjection(ctx, s.db, "grants", lane.GrantSetID, &grants); err != nil {
		return result, err
	}
	if grants.Revoked || !future(grants.ExpiresAt, s.deps.Clock.Now()) {
		return result, fault(api.CodeForbidden, "channel sender grants are revoked or expired")
	}
	var channelID api.ID
	for _, grant := range grants.Channels {
		if grant.ID == selected && future(grant.ExpiresAt, s.deps.Clock.Now()) {
			channelID = grant.ChannelID
		}
	}
	var channel api.EnrolledChannel
	if channelID == "" {
		return result, fault(api.CodePrerequisite, "D6 channel enrollment and grant are required")
	}
	if err := storedProjection(ctx, s.db, "channel", channelID, &channel); err != nil {
		if absent(err) {
			return result, fault(api.CodePrerequisite, "D6 channel enrollment is required")
		}
		return result, err
	}
	if channel.Runtime == nil || channel.Revoked || channel.Config != scope.Config || !future(channel.ExpiresAt, s.deps.Clock.Now()) {
		return result, fault(api.CodePrerequisite, "current D6 channel runtime enrollment is required")
	}
	found := false
	for _, destination := range channel.Destinations {
		found = found || destination.ID == request.DestinationID
	}
	if !found {
		return result, fault(api.CodePrerequisite, "channel destination is not enrolled")
	}
	id := channelKey(request.OperationID, request.DestinationID)
	var prior channelStage
	err = storedProjection(ctx, s.db, "channel_stage", id, &prior)
	if err == nil {
		if prior.Request != request || prior.Actor != actor || !sameValue(prior.Frame, frame) || prior.Job.ChannelGeneration != channel.Generation {
			return result, fault(api.CodeConflict, "channel preparation changed its original selection")
		}
		return prior.Job, nil
	}
	if !absent(err) {
		return result, err
	}
	meta, text, err := objectRow(ctx, s.db, content.ID)
	if err != nil {
		return result, err
	}
	if meta.Ref != content || content.Class != "report" || content.Bytes > api.MaxChunkBytes || !utf8.Valid(text) || !loopTaskVisible(actor, meta.ACL) {
		return result, fault(api.CodeInvalid, "channel content is not the exact authorized report bytes")
	}
	for _, artifact := range artifacts {
		meta, _, err := objectRow(ctx, s.db, artifact.ID)
		if err != nil {
			return result, err
		}
		if meta.Ref != artifact || !loopTaskVisible(actor, meta.ACL) {
			return result, fault(api.CodeForbidden, "channel artifact is not authorized")
		}
	}
	result = api.ChannelJob{Runtime: channel.Runtime, ChannelID: channel.ID, ChannelGeneration: channel.Generation, DestinationID: request.DestinationID,
		MailID: channelMail(scope.Config, actor, frame), Content: content, Artifacts: artifacts,
		Lease: api.WorkerLease{Kind: "channel", Target: api.LifeRef{LifeID: lane.LifeID, Run: lane.Run}, OperationID: request.OperationID, GrantSetID: grants.ID,
			Generation: 1, RuntimeManifest: channel.Runtime.Manifest, ExpiresAt: grants.ExpiresAt}}
	for _, target := range []*api.ID{&result.Lease.ID, &result.Lease.EffectID, &result.ProviderIdempotencyKey} {
		*target, err = wire.NewID()
		if err != nil {
			return result, err
		}
	}
	if end, e := time.Parse(time.RFC3339Nano, string(channel.ExpiresAt)); e != nil {
		return result, e
	} else if grantEnd, e := time.Parse(time.RFC3339Nano, string(grants.ExpiresAt)); e != nil {
		return result, e
	} else if end.Before(grantEnd) {
		result.Lease.ExpiresAt = channel.ExpiresAt
	}
	payload, err := canonicalValue(struct {
		Content   string        `json:"content"`
		Artifacts []api.BlobRef `json:"artifacts"`
	}{string(text), artifacts})
	if err != nil {
		return result, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer finish(tx, &resultErr)
	now := api.Timestamp(s.deps.Clock.Now().UTC().Format(time.RFC3339Nano))
	keep := func(class string, data []byte) (api.BlobRef, error) {
		id, err := wire.NewID()
		if err != nil {
			return api.BlobRef{}, err
		}
		private := context.WithValue(ctx, dataObjectKey{}, s)
		return s.retain(private, tx, scope, api.ObjectWrite{ObjectKey: id, Class: class, Bytes: data, SHA256: api.Digest(hash(data)), Origin: "service",
			ACL: api.ObjectACL{Config: scope.Config, Owner: scope.Actor, LifeID: lane.LifeID, Audience: "private", Generation: 1}}, request.OperationID, now)
	}
	result.Payload, err = keep("channel_payload", payload)
	if err != nil {
		return result, err
	}
	input := api.ChannelSendInput{Schema: "laneboss.channel-input.v2", LeaseID: result.Lease.ID, MailID: result.MailID, ChannelID: result.ChannelID,
		ChannelGeneration: result.ChannelGeneration, DestinationID: result.DestinationID, ProviderIdempotencyKey: result.ProviderIdempotencyKey,
		Payload: result.Payload, Content: result.Content, Artifacts: result.Artifacts}
	inputRaw, err := canonicalValue(input)
	if err != nil {
		return result, err
	}
	result.Lease.Input, err = keep("channel_input", inputRaw)
	if err != nil {
		return result, err
	}
	if err := api.ValidateChannelJob(result); err != nil {
		return result, err
	}
	if err := put(ctx, tx, "channel_stage", id, 1, channelStage{Request: request, Job: result, Actor: actor, Frame: frame}); err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	return result, nil
}
