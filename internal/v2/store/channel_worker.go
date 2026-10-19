package store

import (
	"context"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func channelStageFor(ctx context.Context, db queryer, id api.ID) (result channelStage, err error) {
	var raw []byte
	if err := db.QueryRowContext(ctx, "SELECT data FROM projections WHERE kind='channel_stage' AND json_extract(data,'$.Job.Lease.ID')=?", string(id)).Scan(&raw); err != nil {
		return result, err
	}
	err = decodeStored(raw, &result)
	return result, err
}

func (s *Service) channelPrincipal(ctx context.Context, db queryer, endpoint api.InstalledBinding, peer api.PeerFacts, operation api.WorkerOperation) (result api.WorkerPrincipal, err error) {
	var lease api.WorkerLease
	err = storedProjection(ctx, db, "worker_lease", endpoint.WorkerLeaseID, &lease)
	if absent(err) || err == nil && lease.Kind != "channel" {
		if err == nil && (lease.Kind == "export" || lease.Kind == "test") {
			return s.reviewPrincipal(ctx, db, endpoint, peer, operation)
		}
		return s.archivePrincipal(ctx, db, endpoint, peer, operation)
	}
	if err != nil {
		return result, err
	}
	stage, err := channelStageFor(ctx, db, lease.ID)
	if err != nil {
		return result, err
	}
	if lease.ConsumedBy == "" {
		return result, fault(api.CodePrerequisite, "channel worker has not been prepared by its native owner")
	}
	expected := stage.Job.Lease
	expected.ConsumedBy = lease.ConsumedBy
	expected.Generation++
	assigned := expected
	var ack dataAcknowledgement
	ackErr := storedProjection(ctx, db, "channel_ack", lease.ID, &ack)
	if ackErr == nil {
		expected.Generation = ack.Receipt.Generation
	} else if !absent(ackErr) {
		return result, ackErr
	}
	if !sameValue(expected, lease) {
		return result, fault(api.CodeConflict, "channel worker lease differs from its staged job")
	}
	binding, err := s.launchBinding(ctx, db, lease.ConsumedBy)
	if err != nil {
		return result, err
	}
	var installed api.EndpointProjection
	if err := storedProjection(ctx, db, "endpoint", lease.ConsumedBy, &installed); err != nil {
		return result, err
	}
	if installed.Revoked || !sameValue(installed.Binding, endpoint) || binding.Record.Revoked || binding.Record.HostUID != peer.HostUID || binding.Record.ContainmentID != peer.ContainmentID {
		return result, fault(api.CodeConflict, "channel worker differs from its committed endpoint")
	}
	claim, err := effectRow(ctx, db, lease.EffectID)
	if err != nil {
		return result, err
	}
	if claim.Effect.Channel == nil || !sameValue(*claim.Effect.Channel, stage.Job) || claim.Outcome != nil {
		return result, fault(api.CodeConflict, "channel worker no longer has its original active job")
	}
	boot, _, found := strings.Cut(peer.ProcessGeneration, ":")
	if !found {
		return result, fault(api.CodeContainmentUnknown, "channel worker has no native boot lifetime")
	}
	result = api.WorkerPrincipal{StageID: lease.ID, Lease: assigned, Record: binding.Record, Endpoint: endpoint, Peer: peer, BootID: boot,
		AllocationGeneration: endpoint.InstallationGeneration, CancellationEpoch: claim.Effect.Context.CancellationEpoch,
		Claim: api.EffectLease{Record: claim, ClaimID: claim.ClaimID, ExpiresAt: claim.ClaimExpiresAt}}
	if err := api.ValidateWorkerPrincipal(result, endpoint, peer, operation, s.deps.Clock.Now()); err != nil {
		return result, err
	}
	if ackErr == nil {
		return result, api.ValidateWorkerResult(result, ack.Submission, ack.Receipt, s.deps.Clock.Now())
	}
	return result, nil
}

func (s *Service) channelInput(ctx context.Context, db queryer, p api.WorkerPrincipal) (api.WorkerJobInput, error) {
	meta, raw, err := objectRow(ctx, db, p.Lease.Input.ID)
	if err != nil {
		return api.WorkerJobInput{}, err
	}
	if meta.Ref != p.Lease.Input || meta.SourceOperationID != p.Lease.OperationID {
		return api.WorkerJobInput{}, fault(api.CodeIntegrity, "channel input lost its original operation bytes")
	}
	input := api.WorkerJobInput{Schema: "laneboss.worker-input.v2", StageID: p.StageID, LeaseID: p.Lease.ID, Kind: "channel", OperationID: p.Lease.OperationID,
		EffectID: p.Lease.EffectID, Input: p.Lease.Input, Bytes: raw}
	return input, api.ValidateWorkerInput(p, input, s.deps.Clock.Now())
}

func (s *Service) ChannelContext(ctx context.Context, scope api.Scope, request api.WorkerInputRequest) (result api.ChannelContext, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, err := s.dataWorkerScope(ctx, s.db, scope, api.WorkerChannelContext)
	if err != nil {
		return result, err
	}
	if request.LeaseID != p.Lease.ID {
		return result, fault(api.CodeForbidden, "channel context selected another worker lease")
	}
	stage, err := channelStageFor(ctx, s.db, p.Lease.ID)
	if err != nil {
		return result, err
	}
	var channel api.EnrolledChannel
	if err := storedProjection(ctx, s.db, "channel", stage.Job.ChannelID, &channel); err != nil {
		return result, err
	}
	if channel.Revoked || channel.Generation != stage.Job.ChannelGeneration || !future(channel.ExpiresAt, s.deps.Clock.Now()) {
		return result, fault(api.CodePrerequisite, "current D6 channel enrollment is required")
	}
	var grants api.GrantSet
	if err := storedProjection(ctx, s.db, "grants", p.Lease.GrantSetID, &grants); err != nil {
		return result, err
	}
	// A reclaimed claim can only read the original provider outcome. It may
	// never infer that the previous worker failed before sending.
	result.Job, result.ReadOnly = stage.Job, p.Claim.Record.Generation > 2
	for _, destination := range channel.Destinations {
		if destination.ID == stage.Job.DestinationID {
			result.Destination = destination
		}
	}
	for _, secret := range grants.Secrets {
		if secret.SourceHandle == result.Destination.CredentialHandle && future(secret.ExpiresAt, s.deps.Clock.Now()) {
			result.Credential = api.WorkerCredential{Name: secret.Name, SourceHandle: secret.SourceHandle, Version: secret.Version, Delivery: secret.Delivery, Target: secret.Target}
		}
	}
	if result.Credential.SourceHandle == "" {
		return result, fault(api.CodePrerequisite, "channel selected credential has not been enrolled")
	}
	return result, nil
}

func (s *Service) ChannelReceipt(ctx context.Context, scope api.Scope, request api.ChannelReceiptRequest) (result api.BlobRef, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, err := s.dataWorkerScope(ctx, s.db, scope, api.WorkerChannelReceipt)
	if err != nil {
		return result, err
	}
	if request.LeaseID != p.Lease.ID || len(request.Bytes) == 0 || len(request.Bytes) > api.MaxChunkBytes {
		return result, fault(api.CodeInvalid, "channel receipt exceeds its leased bounded input")
	}
	id := api.ID("receipt-" + hash(append([]byte(p.Lease.ID), request.Bytes...)))
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer finish(tx, &resultErr)
	result, err = s.retain(ctx, tx, scope, api.ObjectWrite{ObjectKey: id, Class: "channel_receipt", Bytes: request.Bytes, SHA256: api.Digest(hash(request.Bytes)), Origin: "observation",
		ACL: api.ObjectACL{Config: scope.Config, Owner: scope.Actor, LifeID: p.Lease.Target.LifeID, Audience: "owner", Generation: 1}}, p.Lease.OperationID,
		api.Timestamp(s.deps.Clock.Now().UTC().Format(time.RFC3339Nano)))
	if err != nil {
		return result, err
	}
	return result, tx.Commit()
}

func (s *Service) channelObject(ctx context.Context, db queryer, p api.WorkerPrincipal, request api.BlobReadRequest) (api.BlobChunk, error) {
	stage, err := channelStageFor(ctx, db, p.Lease.ID)
	if err != nil {
		return api.BlobChunk{}, err
	}
	refs := append([]api.BlobRef{stage.Job.Lease.Input, stage.Job.Payload, stage.Job.Content}, stage.Job.Artifacts...)
	for _, ref := range refs {
		if ref.ID != request.ObjectID {
			continue
		}
		meta, raw, err := objectRow(ctx, db, ref.ID)
		if err != nil {
			return api.BlobChunk{}, err
		}
		if meta.Ref != ref || request.Offset < 0 || request.Offset > int64(len(raw)) || request.Limit < 1 || request.Limit > api.MaxChunkBytes {
			return api.BlobChunk{}, fault(api.CodeInvalid, "channel object differs from its exact sealed range")
		}
		part := append([]byte{}, raw[request.Offset:min(int64(len(raw)), request.Offset+int64(request.Limit))]...)
		return api.BlobChunk{ObjectID: ref.ID, Offset: request.Offset, Data: part, SHA256: api.Digest(hash(part))}, nil
	}
	return api.BlobChunk{}, fault(api.CodeNotFound, "channel object is outside its sealed inputs")
}

func (s *Service) channelResult(ctx context.Context, p api.WorkerPrincipal, submission api.WorkerResultSubmission) (receipt api.WorkerResultReceipt, resultErr error) {
	if submission.LeaseID != p.Lease.ID || submission.ExpectedGeneration != p.Lease.Generation || submission.InputSHA256 != p.Lease.Input.SHA256 || len(submission.Result) == 0 || len(submission.Result) > api.MaxFrameBytes {
		return receipt, fault(api.CodeConflict, "channel result changed its exact lease or input bytes")
	}
	stage, err := channelStageFor(ctx, s.db, p.Lease.ID)
	if err != nil {
		return receipt, err
	}
	var evidence api.ChannelSendEvidence
	if err := api.DecodeObject(submission.Result, &evidence); err != nil {
		return receipt, err
	}
	if err := api.ValidateChannelSendEvidence(stage.Job, evidence); err != nil {
		return receipt, err
	}
	refs := []*api.BlobRef{evidence.Response}
	if evidence.ReadBack != nil {
		refs = append(refs, &evidence.ReadBack.Response)
	}
	for _, ref := range refs {
		if ref == nil {
			continue
		}
		meta, _, err := objectRow(ctx, s.db, ref.ID)
		if err != nil {
			return receipt, err
		}
		if meta.Ref != *ref || meta.SourceOperationID != p.Lease.OperationID || meta.ACL.Owner != p.Record.Actor || meta.Origin != "observation" || meta.ACL.LifeID != p.Lease.Target.LifeID || meta.Ref.Class != "channel_receipt" {
			return receipt, fault(api.CodeIntegrity, "channel result lacks its actual retained worker response")
		}
	}
	var old dataAcknowledgement
	if err := storedProjection(ctx, s.db, "channel_ack", p.Lease.ID, &old); err == nil {
		if !sameValue(old.Submission, submission) {
			return receipt, fault(api.CodeConflict, "channel result changed its original retained bytes")
		}
		return old.Receipt, nil
	} else if !absent(err) {
		return receipt, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return receipt, err
	}
	defer finish(tx, &resultErr)
	actor := p.Record.Actor
	id := api.ID("channel-result-" + hash(submission.Result))
	ref, err := s.retain(ctx, tx, api.Scope{Config: p.Endpoint.Config, Actor: actor}, api.ObjectWrite{ObjectKey: id, Class: "worker_result", Bytes: submission.Result,
		SHA256: api.Digest(hash(submission.Result)), Origin: "observation", ACL: api.ObjectACL{Config: p.Endpoint.Config, Owner: actor, LifeID: p.Lease.Target.LifeID, Audience: "owner", Generation: 1}},
		p.Lease.OperationID, api.Timestamp(s.deps.Clock.Now().UTC().Format(time.RFC3339Nano)))
	if err != nil {
		return receipt, err
	}
	var lane api.Lane
	if err := storedProjection(ctx, tx, "lane", p.Lease.Target.LifeID, &lane); err != nil {
		return receipt, err
	}
	eventID, err := wire.NewID()
	if err != nil {
		return receipt, err
	}
	payload, err := canonicalValue(ref)
	if err != nil {
		return receipt, err
	}
	seq, err := appendPrivateEvent(ctx, tx, api.Event{Schema: api.SchemaVersion, ID: eventID, Config: p.Endpoint.Config, Kind: "blob.committed",
		Actor: actor, RequestedBy: stage.Actor, RequestID: stage.Frame.RequestID, OperationID: p.Lease.OperationID, LifeID: lane.LifeID,
		Run: p.Lease.Target.Run, RootLifeID: lane.RootLifeID, ParentLifeID: lane.ParentLifeID, StarterChain: append([]api.ID{}, lane.StarterChain...),
		StarterEventSeq: lane.StarterEventSeq, Origin: "observation", Payload: payload}, api.Timestamp(s.deps.Clock.Now().UTC().Format(time.RFC3339Nano)))
	if err != nil {
		return receipt, err
	}
	receipt = api.WorkerResultReceipt{LeaseID: p.Lease.ID, StageID: p.StageID, Generation: p.Lease.Generation + 1, Result: ref, CommittedSeq: seq}
	if err := api.ValidateWorkerResult(p, submission, receipt, s.deps.Clock.Now()); err != nil {
		return receipt, err
	}
	worker := p.Lease
	worker.Generation++
	if err := put(ctx, tx, "worker_lease", worker.ID, worker.Generation, worker); err != nil {
		return receipt, err
	}
	if err := put(ctx, tx, "channel_ack", p.Lease.ID, 1, dataAcknowledgement{Submission: submission, Receipt: receipt}); err != nil {
		return receipt, err
	}
	if err := tx.Commit(); err != nil {
		return receipt, err
	}
	s.notifyChanged()
	return receipt, nil
}

var _ api.ChannelBootstrap = (*Service)(nil)
