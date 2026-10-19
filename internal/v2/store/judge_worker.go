package store

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"

	"laneboss.io/laneboss/internal/typesafe"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/judge/job"
	judgewire "laneboss.io/laneboss/internal/v2/judge/wire"
)

func judgeNativeByLease(ctx context.Context, db queryer, lease api.ID) (stage judgeNative, err error) {
	var raw []byte
	err = db.QueryRowContext(ctx, "SELECT data FROM projections WHERE kind='judge_native' AND json_extract(data,'$.Worker.ID')=?", string(lease)).Scan(&raw)
	if err == nil {
		err = decodeStored(raw, &stage)
	}
	return stage, err
}

func (s *Service) otherWorkerPrincipal(ctx context.Context, db queryer, endpoint api.InstalledBinding, peer api.PeerFacts, operation api.WorkerOperation) (api.WorkerPrincipal, error) {
	var lease api.WorkerLease
	if err := storedProjection(ctx, db, "worker_lease", endpoint.WorkerLeaseID, &lease); err == nil && lease.Kind == "judge" {
		return s.judgePrincipal(ctx, db, endpoint, peer, operation, lease)
	} else if err != nil && !absent(err) {
		return api.WorkerPrincipal{}, err
	}
	return s.channelPrincipal(ctx, db, endpoint, peer, operation)
}

func (s *Service) judgePrincipal(ctx context.Context, db queryer, endpoint api.InstalledBinding, peer api.PeerFacts, operation api.WorkerOperation, lease api.WorkerLease) (p api.WorkerPrincipal, err error) {
	stage, err := judgeNativeByLease(ctx, db, lease.ID)
	if err != nil {
		return p, err
	}
	e := stage.Execution
	e.Acquired = true
	scope := api.Scope{Config: s.deps.Config, Actor: e.Intent.Actor, PolicyGeneration: e.Request.Context.PolicyGeneration, Source: "worker"}
	if _, err := s.judgeExecutionClaim(ctx, db, scope, e); err != nil {
		return p, err
	}
	if stage.Endpoint == nil || stage.Handoff == nil || !sameValue(*stage.Endpoint, endpoint) || lease.ConsumedBy != stage.LaunchID ||
		lease.Input != stage.Worker.Input || lease.Target != stage.Worker.Target || lease.GrantSetID != stage.Worker.GrantSetID {
		return p, fault(api.CodeForbidden, "judge endpoint differs from its original committed worker")
	}
	binding, err := s.launchBinding(ctx, db, stage.LaunchID)
	if err != nil {
		return p, err
	}
	r := binding.Record
	var projected api.EndpointProjection
	if err := storedProjection(ctx, db, "endpoint", r.ID, &projected); err != nil {
		return p, err
	}
	if projected.Revoked || r.Revoked || !sameValue(projected.Binding, endpoint) || r.Actor != stage.Actor ||
		r.HostUID != peer.HostUID || stage.Allocation.GID != peer.HostGID || r.ContainmentID != peer.ContainmentID ||
		r.UIDLeaseID != stage.Allocation.ID || r.GrantSetID != stage.Worker.GrantSetID || r.ProcessGeneration != binding.Prepared.ProcessGeneration {
		return p, fault(api.CodeUnauthenticated, "judge worker lost its original native identity")
	}
	claim, err := s.judgeNativeEffect(ctx, db, scope, stage.Worker.EffectID)
	if err != nil {
		return p, err
	}
	if !sameValue(claim, stage.Claim.Record) {
		return p, fault(api.CodeConflict, "judge worker changed its original durable execution claim")
	}
	boot, _, valid := strings.Cut(r.ProcessGeneration, ":")
	peerBoot, _, validPeer := strings.Cut(peer.ProcessGeneration, ":")
	if !valid || !validPeer || boot == "" || boot != peerBoot {
		return p, fault(api.CodeContainmentUnknown, "judge worker boot differs from the retained native lifetime")
	}
	p = api.WorkerPrincipal{StageID: stage.Worker.ID, Lease: lease, Record: r, Endpoint: endpoint, Peer: peer, BootID: boot,
		AllocationGeneration: stage.Allocation.EndpointGeneration, CancellationEpoch: e.Intent.CancellationEpoch, Claim: stage.Claim}
	return p, api.ValidateWorkerPrincipal(p, endpoint, peer, operation, s.deps.Clock.Now())
}

func (s *Service) judgeInput(ctx context.Context, db queryer, p api.WorkerPrincipal) (api.WorkerJobInput, error) {
	meta, raw, err := objectRow(ctx, db, p.Lease.Input.ID)
	if err != nil {
		return api.WorkerJobInput{}, err
	}
	if meta.Ref != p.Lease.Input || meta.SourceOperationID != p.Lease.OperationID || meta.Origin != "service" || meta.ACL.Audience != "private" {
		return api.WorkerJobInput{}, fault(api.CodeIntegrity, "judge worker lost its exact private input provenance")
	}
	result := api.WorkerJobInput{Schema: "laneboss.worker-input.v2", StageID: p.StageID, LeaseID: p.Lease.ID,
		Kind: "judge", OperationID: p.Lease.OperationID, EffectID: p.Lease.EffectID, Input: p.Lease.Input, Bytes: raw}
	return result, api.ValidateWorkerInput(p, result, s.deps.Clock.Now())
}

// JudgeWorkerContext is a protected component read after native authentication;
// it selects only the retained exact execution, never caller-supplied settings.
func (s *Service) JudgeWorkerContext(ctx context.Context, scope api.Scope, q api.WorkerInputRequest) (api.JudgeRequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, err := s.dataWorkerScope(ctx, s.db, scope, api.WorkerJudgeContext)
	if err != nil {
		return api.JudgeRequest{}, err
	}
	stage, err := judgeNativeByLease(ctx, s.db, p.Lease.ID)
	if err != nil {
		return api.JudgeRequest{}, err
	}
	if q.LeaseID != p.Lease.ID || stage.Ack != nil {
		return api.JudgeRequest{}, fault(api.CodeConflict, "judge worker context is foreign or already completed")
	}
	return stage.Execution.Request, nil
}

func (s *Service) JudgeRetain(ctx context.Context, scope api.Scope, q job.RetainRequest) (ref api.BlobRef, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, err := s.dataWorkerScope(ctx, s.db, scope, api.WorkerJudgeRetain)
	if err != nil {
		return ref, err
	}
	stage, err := judgeNativeByLease(ctx, s.db, p.Lease.ID)
	if err != nil {
		return ref, err
	}
	if q.LeaseID != p.Lease.ID || stage.Ack != nil || len(q.Bytes) == 0 ||
		q.Class != "judge_request" && q.Class != "judge_raw" || len(q.Bytes) > judgewire.MaxResponseBytes {
		return ref, fault(api.CodeForbidden, "judge retention differs from its bounded original worker")
	}
	if q.Class == "judge_request" {
		body, _, err := judgewire.Payload(stage.Execution.Request)
		if err != nil || !bytes.Equal(body, q.Bytes) {
			return ref, fault(api.CodeIntegrity, "judge retention changed its exact resolved provider request")
		}
	} else {
		root, err := typesafe.Decode(q.Bytes)
		if err != nil || judgewire.SensitiveResponse(root, "") {
			return ref, fault(api.CodeUnscored, "judge raw response was not completely screened")
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ref, err
	}
	defer finish(tx, &resultErr)
	owner := stage.Execution.Intent.RequestedBy
	ref, err = s.retain(context.WithValue(ctx, dataObjectKey{}, s), tx, scope,
		api.ObjectWrite{ObjectKey: api.ID(hash(append([]byte(string(p.Lease.ID)+":"+q.Class+":"), q.Bytes...))),
			Class: q.Class, SHA256: api.Digest(hash(q.Bytes)), Bytes: q.Bytes, Origin: "service",
			ACL: api.ObjectACL{Config: scope.Config, Owner: owner, LifeID: p.Lease.Target.LifeID, Audience: "owner", Generation: 1}},
		p.Lease.OperationID, api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat)))
	if err != nil {
		return ref, err
	}
	return ref, tx.Commit()
}

func (s *Service) judgeResult(ctx context.Context, p api.WorkerPrincipal, submission api.WorkerResultSubmission) (receipt api.WorkerResultReceipt, resultErr error) {
	stage, err := judgeNativeByLease(ctx, s.db, p.Lease.ID)
	if err != nil {
		return receipt, err
	}
	if stage.Ack != nil {
		if !sameValue(stage.Ack.Submission, submission) {
			return receipt, fault(api.CodeIdempotencyConflict, "judge worker changed its original result bytes")
		}
		return stage.Ack.Receipt, nil
	}
	if submission.LeaseID != p.Lease.ID || submission.ExpectedGeneration != p.Lease.Generation ||
		submission.InputSHA256 != p.Lease.Input.SHA256 || len(submission.Result) == 0 || len(submission.Result) > api.MaxFrameBytes {
		return receipt, fault(api.CodeConflict, "judge result differs from its exact original input or generation")
	}
	var measured job.Result
	if err := api.DecodeObject(submission.Result, &measured); err != nil {
		return receipt, err
	}
	if err := s.checkJudgeResult(ctx, s.db, stage, measured); err != nil {
		return receipt, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return receipt, err
	}
	defer finish(tx, &resultErr)
	ref, err := s.retain(context.WithValue(ctx, dataObjectKey{}, s), tx, api.Scope{Config: s.deps.Config, Actor: stage.Execution.Intent.Actor},
		api.ObjectWrite{ObjectKey: api.ID("judge-result-" + string(p.Lease.ID)), Class: "worker_result", Bytes: submission.Result,
			SHA256: api.Digest(hash(submission.Result)), Origin: "observation", ACL: api.ObjectACL{Config: s.deps.Config,
				Owner: stage.Execution.Intent.Actor, LifeID: p.Lease.Target.LifeID, Audience: "private", Generation: 1}},
		p.Lease.OperationID, api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat)))
	if err != nil {
		return receipt, err
	}
	var head api.Sequence
	if err := tx.QueryRowContext(ctx, "SELECT coalesce(max(seq),0) FROM events").Scan(&head); err != nil {
		return receipt, err
	}
	receipt = api.WorkerResultReceipt{LeaseID: p.Lease.ID, StageID: p.StageID, Generation: p.Lease.Generation + 1, Result: ref, CommittedSeq: head + 1}
	if err := api.ValidateWorkerResult(p, submission, receipt, s.deps.Clock.Now()); err != nil {
		return receipt, err
	}
	stage.Ack = &dataAcknowledgement{Submission: submission, Receipt: receipt}
	stage.ReceivedAt = api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat))
	id := api.ID("judge-result-event-" + string(p.Lease.ID))
	payload, err := json.Marshal(ref)
	if err != nil {
		return receipt, err
	}
	seq, err := appendPrivateEvent(ctx, tx, api.Event{Schema: api.SchemaVersion, ID: id, Config: s.deps.Config,
		Kind: "blob.committed", Actor: p.Record.Actor, RequestedBy: stage.Execution.Intent.RequestedBy,
		RequestID: stage.Execution.Intent.CauseRequestID, OperationID: p.Lease.OperationID, LifeID: p.Lease.Target.LifeID,
		Run: p.Lease.Target.Run, Origin: "service", Payload: payload}, stage.ReceivedAt)
	if err != nil || seq != receipt.CommittedSeq {
		return receipt, fault(api.CodeIntegrity, "judge result receipt differs from its committed event")
	}
	lease := p.Lease
	lease.Generation++
	if err := put(ctx, tx, "worker_lease", lease.ID, lease.Generation, lease); err != nil {
		return receipt, err
	}
	if err := saveJudgeNative(ctx, tx, stage); err != nil {
		return receipt, err
	}
	return receipt, tx.Commit()
}

func (s *Service) checkJudgeResult(ctx context.Context, db queryer, stage judgeNative, result job.Result) error {
	if result.Reply.Request == nil {
		return fault(api.CodeUnscored, "judge worker has no retained exact request")
	}
	var raw []byte
	for _, ref := range []*api.BlobRef{result.Reply.Request, result.Reply.Raw} {
		if ref == nil {
			continue
		}
		meta, data, err := objectRow(ctx, db, ref.ID)
		if err != nil {
			return err
		}
		if meta.Ref != *ref || meta.SourceOperationID != stage.Worker.OperationID || meta.ACL.LifeID != stage.Worker.Target.LifeID {
			return fault(api.CodeIntegrity, "judge result object differs from its original retained worker bytes")
		}
		if ref.Class == "judge_raw" {
			raw = data
		}
	}
	return judgewire.AuditReply(result.Reply, stage.Execution.Request, result.Fit, raw)
}
