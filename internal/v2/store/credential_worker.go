package store

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

var _ api.CredentialWorkerSelectionStore = (*Service)(nil)

func (s *Service) RegisterCredentialWorker(ctx context.Context, scope api.Scope, h api.PreparedSpecHandoff) (resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return err
	}
	if err := s.credentialScope(ctx, s.db, scope); err != nil {
		return err
	}
	selected, err := s.credentialWorker(ctx, s.db, h)
	if err != nil {
		return err
	}
	job, err := effectRow(ctx, s.db, selected.Lease.EffectID)
	if err != nil {
		return err
	}
	attempt, ok := api.EffectLeaseFromContext(ctx)
	if !ok || !api.EffectLeaseClaimed(attempt) || !sameValue(attempt.Record, job) || attempt.ClaimID != job.ClaimID || attempt.ExpiresAt != job.ClaimExpiresAt || scope.Actor.ID != job.ClaimantID {
		return fault(api.CodeForbidden, "credential worker registration requires its explicit current job attempt")
	}
	var retained api.PreparedSpecHandoff
	err = storedProjection(ctx, s.db, "credential_worker_handoff", h.Spec.ID, &retained)
	if err == nil {
		if !sameValue(retained, h) {
			return fault(api.CodeConflict, "credential worker registration changed its original sealed handoff")
		}
		return nil
	}
	if !absent(err) {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer finish(tx, &resultErr)
	if err := put(ctx, tx, "credential_worker_handoff", h.Spec.ID, 1, h); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) credentialWorkerRequest(ctx context.Context, db queryer, request api.CredentialProjectionRequest) error {
	selection, err := s.credentialWorker(ctx, db, request.Handoff)
	if err != nil {
		return err
	}
	if request.Worker == nil || selection.Lease != *request.Worker || !sameValue(selection.Credentials, request.WorkerCredentials) {
		return fault(api.CodeForbidden, "credential worker request differs from its protected job selection")
	}
	return nil
}

func (s *Service) CredentialWorkerSelection(ctx context.Context, scope api.Scope, handoff api.PreparedSpecHandoff) (api.CredentialWorkerSelection, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return api.CredentialWorkerSelection{}, err
	}
	if err := s.credentialScope(ctx, s.db, scope); err != nil {
		return api.CredentialWorkerSelection{}, err
	}
	return s.credentialWorker(ctx, s.db, handoff)
}

func (s *Service) credentialWorker(ctx context.Context, db queryer, h api.PreparedSpecHandoff) (api.CredentialWorkerSelection, error) {
	var result api.CredentialWorkerSelection
	spec := h.Spec
	if h.Config != s.deps.Config || spec.Kind != "worker" || spec.Runner != nil || spec.Worker == nil ||
		spec.Worker.Kind != "channel" && spec.Worker.Kind != "usage" || h.Cause.Kind != api.InternalHelperRegister ||
		h.Cause.Config != h.Config || h.Cause.Actor.Kind != "service" || !wire.ValidID(string(h.Cause.Actor.ID)) ||
		h.Original.Bytes < 1 || h.Original.Bytes > api.MaxFrameBytes || h.Cause.Target != spec.Target || h.Cause.CauseOperationID != h.OperationID || h.Cause.CauseRequestID != h.RequestID {
		return result, fault(api.CodeForbidden, "credential worker requires its protected channel or usage job")
	}
	metadata, raw, err := objectRow(ctx, db, h.Original.ID)
	if err != nil {
		return result, err
	}
	var retained api.LaunchSpec
	if err := api.DecodeObject(raw, &retained); err != nil {
		return result, err
	}
	if metadata.Ref != h.Original || h.Original.Class != "launch_spec" || h.Original.SHA256 != h.SpecSHA256 ||
		metadata.Origin != "service" || metadata.SourceOperationID != h.OperationID || metadata.ACL.Config != h.Config ||
		metadata.ACL.Owner.Kind != "service" || metadata.ACL.Audience != "owner" && metadata.ACL.Audience != "service" && metadata.ACL.Audience != "private" ||
		len(metadata.ACL.Participants) != 0 || !sameValue(retained, spec) {
		return result, fault(api.CodeIntegrity, "credential worker spec lost its immutable service provenance")
	}
	var count int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM projections WHERE kind='worker_lease' AND json_extract(data,'$.ConsumedBy')=?", string(spec.LaunchID)).Scan(&count); err != nil {
		return result, err
	}
	if count != 1 {
		return result, fault(api.CodeForbidden, "credential worker has no unique assigned durable job lease")
	}
	var leaseRaw []byte
	if err := db.QueryRowContext(ctx, "SELECT data FROM projections WHERE kind='worker_lease' AND json_extract(data,'$.ConsumedBy')=?", string(spec.LaunchID)).Scan(&leaseRaw); err != nil {
		return result, err
	}
	var lease api.WorkerLease
	if err := decodeStored(leaseRaw, &lease); err != nil {
		return result, err
	}
	if lease.Kind != spec.Worker.Kind || lease.Target != spec.Target || lease.OperationID != h.OperationID || lease.Input != spec.Worker.Input ||
		lease.RuntimeManifest != spec.RuntimeManifest || lease.GrantSetID != spec.Grants.ID || lease.Generation == 0 || !future(lease.ExpiresAt, s.deps.Clock.Now()) {
		return result, fault(api.CodeForbidden, "credential worker differs from its actual assigned lease")
	}
	job, err := effectRow(ctx, db, lease.EffectID)
	if err != nil {
		return result, err
	}
	matchesPlan := job.Effect.Worker != nil && sameValue(*job.Effect.Worker, *spec.Worker)
	if lease.Kind == "channel" && job.Effect.Channel != nil {
		stage, err := channelStageFor(ctx, db, lease.ID)
		if err != nil {
			return result, err
		}
		matchesPlan = stage.Native != nil && stage.Native.ID == spec.LaunchID && sameValue(stage.Native.Plan, *spec.Worker) && sameValue(stage.Job, *job.Effect.Channel)
	}
	if job.State != api.EffectClaimed || job.Outcome != nil || !future(job.ClaimExpiresAt, s.deps.Clock.Now()) || job.Effect.Context == nil ||
		job.Effect.OperationID != h.OperationID || job.Effect.Context.Target != lease.Target || job.Effect.Context.Config != h.Config ||
		job.Effect.Context.CauseRequestID != h.RequestID || job.Effect.Context.CancellationEpoch != h.Cause.CancellationEpoch ||
		!matchesPlan {
		return result, fault(api.CodeConflict, "credential worker lost its current protected job claim")
	}
	var grants api.GrantSet
	if err := storedProjection(ctx, db, "grants", lease.GrantSetID, &grants); err != nil {
		return result, err
	}
	var policy api.EffectivePolicy
	if err := storedProjection(ctx, db, "policy", api.ID(h.Config), &policy); err != nil {
		return result, err
	}
	var lane api.Lane
	if err := storedProjection(ctx, db, "lane", lease.Target.LifeID, &lane); err != nil {
		return result, err
	}
	if grants.Revoked || grants.LifeID != lease.Target.LifeID || !sameValue(grants, spec.Grants) || !future(grants.ExpiresAt, s.deps.Clock.Now()) ||
		policy.Generation != spec.PolicyGeneration || policy.Generation != grants.PolicyGeneration || lane.Cleaned || lane.Run != lease.Target.Run || lane.CancellationEpoch != h.Cause.CancellationEpoch {
		return result, fault(api.CodeForbidden, "credential worker grants policy or cancellation fence changed")
	}
	runtimeMeta, runtimeRaw, err := objectRow(ctx, db, lease.RuntimeManifest.ID)
	if err != nil {
		return result, err
	}
	var runtime api.RuntimeManifest
	if runtimeMeta.Ref != lease.RuntimeManifest || runtimeMeta.Origin != "service" || runtimeMeta.ACL.Config != h.Config || runtimeMeta.ACL.Owner.Kind != "service" ||
		api.DecodeObject(runtimeRaw, &runtime) != nil || runtime.Schema != "laneboss.runtime.v2" || runtime.Generation == 0 || runtime.Bootstrap != spec.Worker.Executable {
		return result, fault(api.CodeForbidden, "credential worker runtime differs from its installed executable")
	}
	inputMeta, inputRaw, err := objectRow(ctx, db, lease.Input.ID)
	if err != nil {
		return result, err
	}
	if inputMeta.Ref != lease.Input || inputMeta.Origin != "service" || inputMeta.SourceOperationID != lease.OperationID || inputMeta.ACL.Config != h.Config || inputMeta.ACL.Owner.Kind != "service" ||
		inputMeta.ACL.LifeID != "" && inputMeta.ACL.LifeID != lease.Target.LifeID || len(inputMeta.ACL.Participants) != 0 ||
		inputMeta.ACL.Audience != "private" && inputMeta.ACL.Audience != "service" && inputMeta.ACL.Audience != "owner" {
		return result, fault(api.CodeIntegrity, "credential worker input lost its sealed private provenance")
	}
	var selected api.SecretGrant
	if lease.Kind == "usage" {
		var input api.UsageCredentialInput
		if err := api.DecodeObject(inputRaw, &input); err != nil {
			return result, err
		}
		stage, err := usageForLease(ctx, db, lease.ID)
		if err != nil && !absent(err) {
			return result, err
		}
		// Generic protected usage jobs may pin the worker itself as their
		// query program. The installed vendor-query coordinator instead keeps
		// two distinct executable pins in its original durable usage stage.
		matches := input.Request.Executable == spec.Worker.Executable
		if err == nil {
			matches = sameValue(input, stage.Job.Input) && sameValue(*spec.Worker, stage.Job.Plan) && stage.Job.LaunchID == spec.LaunchID
		}
		if input.Schema != "laneboss.usage-input.v1" || input.Request.Target != lease.Target || input.Request.OperationID != lease.OperationID || input.Request.RuntimeManifest != lease.RuntimeManifest ||
			!matches || input.VendorProfile == "" || input.ProfileGeneration == 0 {
			return result, fault(api.CodeForbidden, "usage credential differs from its actual sealed job")
		}
		selected = input.Source
	} else {
		var input api.ChannelSendInput
		if err := api.DecodeObject(inputRaw, &input); err != nil {
			return result, err
		}
		var channel api.EnrolledChannel
		if err := storedProjection(ctx, db, "channel", input.ChannelID, &channel); err != nil {
			return result, err
		}
		if input.Schema != "laneboss.channel-input.v2" || input.LeaseID != lease.ID || channel.Config != h.Config || channel.Revoked || channel.Generation != input.ChannelGeneration ||
			!future(channel.ExpiresAt, s.deps.Clock.Now()) || channel.Runtime == nil || channel.Runtime.Manifest != lease.RuntimeManifest || channel.Runtime.Executable != spec.Worker.Executable {
			return result, fault(api.CodeForbidden, "channel credential differs from its protected runtime and input")
		}
		matches := 0
		for _, destination := range channel.Destinations {
			if destination.ID != input.DestinationID {
				continue
			}
			for _, grant := range grants.Secrets {
				if grant.SourceHandle == destination.CredentialHandle {
					selected, matches = grant, matches+1
				}
			}
		}
		if matches != 1 {
			return result, fault(api.CodeForbidden, "channel destination has no unique current credential source")
		}
	}
	if !wire.ValidID(string(selected.ID)) || !wire.ValidID(string(selected.SourceHandle)) || selected.Name == "" || selected.Version == "" || !future(selected.ExpiresAt, s.deps.Clock.Now()) {
		return result, fault(api.CodeForbidden, "credential worker source is absent or expired")
	}
	result = api.CredentialWorkerSelection{Lease: lease, Credentials: []api.WorkerCredential{{Name: selected.Name, SourceHandle: selected.SourceHandle, Version: selected.Version, Delivery: selected.Delivery, Target: selected.Target}}}
	return result, nil
}
