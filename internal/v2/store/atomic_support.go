package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func (s *Service) compare(ctx context.Context, tx *sql.Tx, comparisons []api.Compare) error {
	for _, compare := range comparisons {
		var generation uint64
		err := tx.QueryRowContext(ctx, "SELECT generation FROM projections WHERE kind=? AND id=?", string(compare.Kind), string(compare.ID)).Scan(&generation)
		if errors.Is(err, sql.ErrNoRows) {
			if compare.Generation == 0 {
				continue
			}
			return fault(api.CodeConflict, "expected projection is absent")
		}
		if err != nil {
			return err
		}
		if compare.Generation == 0 || generation != uint64(compare.Generation) {
			return fault(api.CodeConflict, "projection generation changed")
		}
	}
	return nil
}

func future(value api.Timestamp, now time.Time) bool {
	parsed, err := time.Parse(time.RFC3339Nano, string(value))
	return err == nil && parsed.After(now)
}

func (s *Service) guards(ctx context.Context, tx *sql.Tx, input api.Transaction, operation api.ID) error {
	for _, guard := range input.Guards {
		switch {
		case guard.Proof != nil:
			use := guard.Proof
			var proof api.VerifiedHumanProof
			if err := storedProjection(ctx, tx, "proof", use.Proof.ID, &proof); err != nil {
				return err
			}
			actual, err := s.authorizationTarget(ctx, tx, input.Scope, input.Scope.Request)
			if err != nil {
				return err
			}
			if actual != use.Target {
				return fault(api.CodeConflict, "human proof base or target changed")
			}
			if input.Scope.Actor.Kind != "human" || input.Scope.Connection == nil || input.Scope.Request.Proof == nil ||
				*input.Scope.Request.Proof != use.Proof || proof.Ref != use.Proof || proof.ConsumedBy != "" || proof.Config != s.deps.Config ||
				proof.PrincipalID != input.Scope.Actor.ID || proof.EndpointClass != api.EndpointHuman || proof.EndpointGeneration != input.Scope.EndpointGeneration ||
				proof.Target != use.Target || proof.Target.Method != input.Scope.Request.Method || proof.Target.RequestSHA256 != input.Scope.Request.RequestSHA256 || !future(proof.Ref.ExpiresAt, s.deps.Clock.Now()) {
				return fault(api.CodeForbidden, "human proof is expired, used or bound to another intent")
			}
			var enrollment api.HumanEnrollment
			if err := storedProjection(ctx, tx, "enrollment", input.Scope.Actor.ID, &enrollment); err != nil {
				return err
			}
			found := false
			for _, credential := range enrollment.Credentials {
				if credential.ID == proof.CredentialID && !credential.Revoked {
					found = true
				}
			}
			if !found {
				return fault(api.CodeUnauthenticated, "proof credential is revoked")
			}
			proof.ConsumedBy = operation
			key, err := s.proofCredential(ctx, tx, proof)
			if err != nil {
				return err
			}
			useReceipt := api.ProofUseReceipt{ProofID: proof.Ref.ID, CredentialID: proof.CredentialID, NonceID: proof.NonceID, OperationID: operation, UsedAt: api.Timestamp(s.deps.Clock.Now().UTC().Format(time.RFC3339Nano)), SimulatedPresence: proof.SimulatedPresence}
			if err := api.ValidateProofPresence(key, proof, useReceipt); err != nil {
				return err
			}
			if err := put(ctx, tx, "proof", proof.Ref.ID, 1, proof); err != nil {
				return err
			}
			if err := put(ctx, tx, "proof_use", proof.Ref.ID, 1, useReceipt); err != nil {
				return err
			}
		case guard.Ticket != nil:
			use := guard.Ticket
			var retained ticketRecord
			if err := storedProjection(ctx, tx, "ticket", use.TicketID, &retained); err != nil {
				return err
			}
			ticket := retained.Ticket
			if retained.Config != s.deps.Config || retained.PrincipalID != use.PrincipalID || retained.EndpointGeneration != use.EndpointGeneration || ticket.PrincipalID != retained.PrincipalID || ticket.Config != retained.Config || ticket.EndpointGeneration != retained.EndpointGeneration {
				return fault(api.CodeForbidden, "ticket provenance does not cover caller")
			}
			if input.Scope.Connection == nil || input.Scope.Connection.Binding().Class != api.EndpointHuman || input.Scope.Actor.Kind != "human" ||
				use.PrincipalID != input.Scope.Actor.ID || use.Config != s.deps.Config || use.EndpointGeneration != input.Scope.EndpointGeneration ||
				ticket.Redeemed || !future(ticket.ExpiresAt, s.deps.Clock.Now()) || ticket.Level != use.Level || ticket.Role != use.Role || ticket.GrantSetID != use.GrantSetID {
				return fault(api.CodeForbidden, "root ticket binding or expiry is invalid")
			}
			ticket.Redeemed = true
			retained.Ticket = ticket
			retained.RedeemedBy = operation
			if err := put(ctx, tx, "ticket", ticket.ID, 1, retained); err != nil {
				return err
			}
		case guard.Approval != nil:
			use := guard.Approval
			var approval api.ChangeApproval
			if err := storedProjection(ctx, tx, "approval", use.ApprovalID, &approval); err != nil {
				return err
			}
			if approval.ChangeID != use.ChangeID || approval.ManifestSHA256 != use.ManifestSHA256 || approval.BaseGeneration != use.BaseGeneration {
				return fault(api.CodeConflict, "approval does not cover this change")
			}
			if !future(approval.ExpiresAt, s.deps.Clock.Now()) {
				return fault(api.CodeForbidden, "approval has expired")
			}
			var prior approvalConsumption
			err := storedProjection(ctx, tx, "approval_use", approval.ID, &prior)
			if err == nil && prior.OperationID != operation {
				return fault(api.CodeConflict, "approval is already consumed by another operation")
			}
			if err != nil && !absent(err) {
				return err
			}
			if err := put(ctx, tx, "approval_use", approval.ID, 1, approvalConsumption{Approval: approval, OperationID: operation}); err != nil {
				return err
			}
		case guard.Cancellation != nil:
			if input.Internal != nil && input.Internal.Kind == api.InternalHelperRelease && len(input.Effects) == 0 {
				if err := s.releaseGuard(ctx, tx, input, *guard.Cancellation); err != nil {
					return err
				}
				continue
			}
			epoch, err := s.cancellationEpoch(ctx, tx, guard.Cancellation.LifeID)
			if err != nil {
				return err
			}
			if epoch != guard.Cancellation.Epoch {
				return fault(api.CodeConflict, "life cancellation epoch changed")
			}
		default:
			return wire.Invalid("empty transaction guard")
		}
	}
	return nil
}

func storedProjection(ctx context.Context, db queryer, kind string, id api.ID, out any) error {
	var data []byte
	err := db.QueryRowContext(ctx, "SELECT data FROM projections WHERE kind=? AND id=?", kind, string(id)).Scan(&data)
	if err != nil {
		if cause := ctx.Err(); cause != nil {
			return cause
		}
	}
	if errors.Is(err, sql.ErrNoRows) {
		component := "store_projection"
		switch kind {
		case "lane":
			component = "store_lane"
		case "launch", "launch_binding", "endpoint":
			component = "store_launch"
		case "launch_plan", "launch_authority", "launch_operation":
			component = "store_launch_plan"
		case "worker_lease":
			component = "store_worker"
		case "data_stage", "data_ack", "data_measurement":
			component = "store_materialization"
		case "grants":
			component = "store_grants"
		case "policy", "policy_history":
			component = "store_policy"
		case "source", "org_snapshot":
			component = "store_source"
		case "template", "briefing":
			component = "store_template"
		case "guidance":
			component = "store_guidance"
		}
		return api.WithErrorComponent(fault(api.CodeNotFound, "object is absent or not visible"), component)
	}
	if err != nil {
		return err
	}
	return decodeStored(data, out)
}

func (s *Service) writeState(ctx context.Context, tx *sql.Tx, input api.Transaction, operation api.ID, now api.Timestamp) error {
	if err := s.validateOrgPublicationWrite(ctx, input); err != nil {
		return err
	}
	// Specs and stage inputs must exist inside this same transaction before
	// validating plan references; a later rollback retains neither half.
	for _, object := range input.Writes.Objects {
		if _, err := s.retain(ctx, tx, input.Scope, object, operation, now); err != nil {
			return err
		}
	}
	writes := reflect.ValueOf(input.Writes)
	if len(input.Writes.Guidance) != 0 {
		if err := s.writeGuidance(ctx, tx, input); err != nil {
			return err
		}
	}
	for index := 0; index < writes.NumField(); index++ {
		field, name := writes.Field(index), writes.Type().Field(index).Name
		if field.IsZero() {
			continue
		}
		switch name {
		case "Objects":
			continue
		case "LaunchPlans":
			if err := s.writeLaunchPlans(ctx, tx, input, now); err != nil {
				return err
			}
		case "Guidance":
			continue
		case "Turns":
			if len(input.Writes.Guidance) == 0 {
				if err := s.projectionWrites(ctx, tx, input, name, field); err != nil {
					return err
				}
			}
		case "UploadBegins", "UploadChunks", "UploadCommits":
			if err := s.uploadWrites(ctx, tx, input, operation, now, name); err != nil {
				return err
			}
		case "Counters":
			if err := s.counterWrites(ctx, tx, input); err != nil {
				return err
			}
		case "Lanes", "Grants", "Changes", "Approvals", "Applications", "Mail", "Continuations", "Deployments", "WorkerLeases", "Channels", "JudgeAudits", "Decisions", "Endpoints", "OrgSnapshots", "Policy", "Challenges", "Proofs", "Tickets", "ReadSessions", "IdentityBindings":
			if err := s.projectionWrites(ctx, tx, input, name, field); err != nil {
				return err
			}
		case "Enrollments":
			if err := s.enrollmentWrites(ctx, tx, input, operation); err != nil {
				return err
			}
		case "HumanChanges":
			if err := s.humanChanges(ctx, tx, input); err != nil {
				return err
			}
		default:
			return api.NotImplemented("lb-v2-service", "atomic state field "+name)
		}
	}
	return nil
}

func (s *Service) projectionWrites(ctx context.Context, tx *sql.Tx, input api.Transaction, name string, field reflect.Value) error {
	if name == "Challenges" || name == "Proofs" || name == "ReadSessions" || name == "Tickets" {
		return s.identityWrites(ctx, tx, input, name)
	}
	if name == "Decisions" || name == "IdentityBindings" {
		return nil // Their authority is stamped from actual appended events below.
	}
	if field.Kind() == reflect.Pointer {
		if err := s.validatePublishedPolicy(ctx, tx, input); err != nil {
			return err
		}
		return putGenerated(ctx, tx, "policy", api.ID(s.deps.Config), input.Writes.Policy.Generation, *input.Writes.Policy)
	}
	for index := 0; index < field.Len(); index++ {
		if name == "JudgeAudits" {
			if err := s.writeJudgeAudit(ctx, tx, input, input.Writes.JudgeAudits[index]); err != nil {
				return err
			}
			continue
		}
		value := field.Index(index)
		kind, idField := "", "ID"
		switch name {
		case "Lanes":
			kind, idField = "lane", "LifeID"
		case "Grants":
			kind = "grants"
		case "Changes":
			kind = "change"
		case "Approvals":
			kind = "approval"
		case "Applications":
			kind, idField = "application", "ChangeID"
		case "Mail":
			kind = "mail"
		case "Turns":
			kind, idField = "turn", "LogicalTurnID"
		case "Continuations":
			kind = "continuation"
		case "Deployments":
			kind = "upgrade"
		case "WorkerLeases":
			kind = "worker_lease"
		case "Channels":
			kind = "channel"
		case "JudgeAudits":
			kind = "judge_audit"
		case "OrgSnapshots":
			kind, idField = "org", "OrgID"
			value = value.FieldByName("Ref")
		case "Endpoints":
			endpoint := input.Writes.Endpoints[index]
			if err := api.ValidateBinding(endpoint.Binding, s.deps.Config, endpoint.Binding.ServiceVersion); err != nil {
				return err
			}
			if endpoint.Binding.LaunchID == "" {
				return wire.Invalid("endpoint projection requires its launch identity")
			}
			if err := putGenerated(ctx, tx, "endpoint", endpoint.Binding.LaunchID, endpoint.Generation, endpoint); err != nil {
				return err
			}
			continue
		default:
			return api.NotImplemented("lb-v2-service", "validated projection "+name)
		}
		idValue := value.FieldByName(idField)
		if !idValue.IsValid() || idValue.Kind() != reflect.String || !wire.ValidID(idValue.String()) {
			return wire.Invalid("projection requires an authentic object ID")
		}
		id := api.ID(idValue.String())
		generation := api.Generation(1)
		if f := value.FieldByName("Generation"); f.IsValid() && f.Kind() == reflect.Uint64 {
			generation = api.Generation(f.Uint())
		}
		if generation == 0 {
			return wire.Invalid("projection generation must be positive")
		}
		if name == "Changes" && input.Internal != nil && input.Internal.Kind == api.InternalOrgPublish {
			var previous api.Generation
			if err := tx.QueryRowContext(ctx, "SELECT generation FROM projections WHERE kind='change' AND id=?", string(id)).Scan(&previous); err != nil {
				return err
			}
			generation = previous + 1
		}
		if input.Internal == nil && (name == "Channels" || name == "JudgeAudits") {
			return fault(api.CodeForbidden, "projection requires an internal emitter")
		}
		if err := putGenerated(ctx, tx, kind, id, generation, field.Index(index).Interface()); err != nil {
			return err
		}
	}
	return nil
}

func putGenerated(ctx context.Context, tx *sql.Tx, kind string, id api.ID, generation api.Generation, value any) error {
	if !wire.ValidID(string(id)) || generation == 0 {
		return wire.Invalid("projection requires a valid identity and generation")
	}
	var oldGeneration uint64
	var oldData []byte
	err := tx.QueryRowContext(ctx, "SELECT generation,data FROM projections WHERE kind=? AND id=?", kind, string(id)).Scan(&oldGeneration, &oldData)
	if err == nil {
		if sameValue(json.RawMessage(oldData), value) {
			return nil
		}
		if generation != api.Generation(oldGeneration)+1 {
			return fault(api.CodeConflict, "typed projection generation changed")
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	} else if generation != 1 {
		return fault(api.CodeConflict, "new typed projection must start at generation one")
	}
	return put(ctx, tx, kind, id, generation, value)
}

func (s *Service) finalReply(ctx context.Context, tx *sql.Tx, input api.Transaction, operation api.Operation) (*api.RPCReply, error) {
	reply := &api.RPCReply{Result: append(json.RawMessage(nil), input.Reply.Result...), Error: input.Reply.Error}
	if reply.Error != nil {
		return reply, nil
	}
	switch input.Scope.Request.Method {
	case "records.append", "decisions.mutate":
		var submitted api.Record
		if err := wire.Decode(reply.Result, &submitted); err != nil {
			return nil, err
		}
		var record api.Record
		if err := projection(ctx, tx, "record", submitted.ID, &record); err != nil {
			return nil, err
		}
		if submitted.Content != record.Content || submitted.Collection != record.Collection || submitted.Actor != record.Actor || submitted.Generation != record.Generation {
			return nil, fault(api.CodeIntegrity, "reply disagrees with committed record")
		}
		data, err := json.Marshal(record)
		if err != nil {
			return nil, err
		}
		reply.Result = data
	case "blob.begin", "blob.chunk":
		var upload api.BlobUpload
		if err := wire.Decode(reply.Result, &upload); err != nil {
			return nil, err
		}
		var leaseData []byte
		if err := tx.QueryRowContext(ctx, "SELECT lease FROM uploads WHERE id=?", string(upload.ObjectID)).Scan(&leaseData); err != nil {
			return nil, err
		}
		var lease api.UploadLease
		if err := decodeStored(leaseData, &lease); err != nil {
			return nil, err
		}
		if upload.ExpiresAt != lease.ExpiresAt || upload.MaxChunkBytes != api.MaxChunkBytes {
			return nil, fault(api.CodeIntegrity, "upload reply differs from lease")
		}
	case "blob.commit":
		var ref api.BlobRef
		if err := wire.Decode(reply.Result, &ref); err != nil {
			return nil, err
		}
		metadata, _, err := objectRow(ctx, tx, ref.ID)
		if err != nil {
			return nil, err
		}
		if metadata.Ref != ref {
			return nil, fault(api.CodeIntegrity, "blob reply differs from committed object")
		}
	case "lane.check":
		var target api.LifeRef
		var observed api.ProcessObservation
		var lane api.Lane
		var retained struct {
			Observation api.ProcessObservation
			Generation  api.Generation
		}
		if err := wire.Decode(input.Scope.Request.Params, &target); err != nil {
			return nil, err
		}
		if err := wire.Decode(reply.Result, &observed); err != nil {
			return nil, err
		}
		if err := storedProjection(ctx, tx, "lane", target.LifeID, &lane); err != nil {
			return nil, err
		}
		if err := storedProjection(ctx, tx, "launch_observation", lane.LaunchID, &retained); err != nil {
			return nil, err
		}
		// A fresh census of the same still-running process is the same run (natural_completion.go
		// sameRunningProcess, box 100); any other state still needs the exact retained bytes.
		if lane.Run != target.Run || !sameValue(retained.Observation, observed) && !sameRunningProcess(observed, retained.Observation) {
			return nil, fault(api.CodeForbidden, "lane.check reply differs from its actual retained observation")
		}
	case "policy.evaluate":
		var value, retained api.PolicyDecision
		if err := wire.Decode(reply.Result, &value); err != nil {
			return nil, err
		}
		if len(input.Events) != 1 || input.Events[0].Kind != "policy.evaluated" {
			return nil, fault(api.CodeIntegrity, "policy reply has no sole committed audit event")
		}
		var raw []byte
		if err := tx.QueryRowContext(ctx, "SELECT data FROM events WHERE id=?", string(input.Events[0].ID)).Scan(&raw); err != nil {
			return nil, err
		}
		var event api.Event
		if err := wire.Decode(raw, &event); err != nil {
			return nil, err
		}
		if err := wire.Decode(event.Payload, &retained); err != nil {
			return nil, err
		}
		metadata, _, err := objectRow(ctx, tx, value.Input.ID)
		if err != nil {
			return nil, err
		}
		if !sameValue(value, retained) || !value.AuditComplete || event.OperationID != operation.ID || event.RequestID != input.Scope.Request.RequestID ||
			event.RequestedBy != input.Scope.Actor || metadata.Ref != value.Input || metadata.SourceOperationID != operation.ID || metadata.ACL.Owner != input.Scope.Actor {
			return nil, fault(api.CodeIntegrity, "policy reply differs from its committed audit and retained input")
		}
	case "guidance.select":
		var value api.Guidance
		if err := wire.Decode(reply.Result, &value); err != nil {
			return nil, err
		}
		var retained api.GuidanceReservation
		if err := storedProjection(ctx, tx, "guidance", value.ReservationID, &retained); err != nil {
			return nil, err
		}
		if retained.Result == nil || !sameValue(*retained.Result, value) {
			return nil, fault(api.CodeForbidden, "guidance reply differs from its one retained selection")
		}
	case "human.challenge":
		var value api.HumanChallenge
		if err := wire.Decode(reply.Result, &value); err != nil {
			return nil, err
		}
		var stored api.StoredChallenge
		if err := storedProjection(ctx, tx, "challenge", value.ID, &stored); err != nil {
			return nil, err
		}
		if !sameValue(value, stored.Challenge) || stored.PrincipalID != input.Scope.Actor.ID {
			return nil, fault(api.CodeIntegrity, "challenge reply differs from committed challenge")
		}
	case "human.confirm":
		var value api.ProofRef
		if err := wire.Decode(reply.Result, &value); err != nil {
			return nil, err
		}
		var stored api.VerifiedHumanProof
		if err := storedProjection(ctx, tx, "proof", value.ID, &stored); err != nil {
			return nil, err
		}
		if value != stored.Ref || stored.PrincipalID != input.Scope.Actor.ID {
			return nil, fault(api.CodeIntegrity, "proof reply differs from verified proof")
		}
	case "human.session":
		var value api.HumanSession
		if err := wire.Decode(reply.Result, &value); err != nil {
			return nil, err
		}
		var stored api.StoredReadSession
		if err := storedProjection(ctx, tx, "read_session", value.ID, &stored); err != nil {
			return nil, err
		}
		if value != stored.Session || stored.PrincipalID != input.Scope.Actor.ID || stored.ConnectionID != input.Scope.Connection.ID() {
			return nil, fault(api.CodeIntegrity, "session reply differs from committed connection session")
		}
	case "human.enroll":
		if err := s.humanReply(ctx, tx, input, operation, reply.Result); err != nil {
			return nil, err
		}
	case "ticket.issue":
		var value api.Ticket
		if err := wire.Decode(reply.Result, &value); err != nil {
			return nil, err
		}
		var stored ticketRecord
		if err := storedProjection(ctx, tx, "ticket", value.ID, &stored); err != nil {
			return nil, err
		}
		if value != stored.Ticket || stored.PrincipalID != input.Scope.Actor.ID {
			return nil, fault(api.CodeIntegrity, "ticket reply differs from committed ticket")
		}
	case "mail.send", "report.submit":
		var value api.Mail
		if err := wire.Decode(reply.Result, &value); err != nil {
			return nil, err
		}
		var stored api.Mail
		if err := projection(ctx, tx, "mail", value.ID, &stored); err != nil {
			return nil, err
		}
		if stored.Sender != input.Scope.Actor || stored.Content != value.Content {
			return nil, fault(api.CodeIntegrity, "mail reply differs from committed sender or content")
		}
		data, err := json.Marshal(stored)
		if err != nil {
			return nil, err
		}
		reply.Result = data
	case "grants.enroll":
		var ref api.BlobRef
		if err := wire.Decode(reply.Result, &ref); err != nil {
			return nil, err
		}
		metadata, _, err := objectRow(ctx, tx, ref.ID)
		if err != nil {
			return nil, err
		}
		if metadata.Ref != ref || metadata.Origin != "service" || metadata.ACL.Owner != input.Scope.Actor ||
			metadata.ACL.Config != input.Scope.Config || metadata.ACL.Generation != 1 || metadata.ACL.LifeID != "" {
			return nil, fault(api.CodeIntegrity, "capability reply differs from its protected committed record")
		}
	case "grants.root":
		var value api.GrantSet
		if err := wire.Decode(reply.Result, &value); err != nil {
			return nil, err
		}
		var stored api.GrantSet
		if err := projection(ctx, tx, "grants", value.ID, &stored); err != nil {
			return nil, err
		}
		if !sameValue(value, stored) {
			return nil, fault(api.CodeIntegrity, "grant reply differs from committed grants")
		}
	case "secret.stage":
		if err := s.secretStageReply(ctx, tx, input, operation); err != nil {
			return nil, err
		}
	case "secret.import", "secret.rotate":
		if err := s.secretInfoReply(ctx, tx, input, operation); err != nil {
			return nil, err
		}
	case "org.change.propose":
		var value api.ChangeRequest
		if err := wire.Decode(reply.Result, &value); err != nil {
			return nil, err
		}
		var stored api.ChangeRequest
		if err := projection(ctx, tx, "change", value.ID, &stored); err != nil {
			return nil, err
		}
		if !sameValue(value, stored) {
			return nil, fault(api.CodeIntegrity, "change reply differs from committed proposal")
		}
	case "org.change.approve":
		var value api.ChangeApproval
		if err := wire.Decode(reply.Result, &value); err != nil {
			return nil, err
		}
		var stored api.ChangeApproval
		if err := projection(ctx, tx, "approval", value.ID, &stored); err != nil {
			return nil, err
		}
		if !sameValue(value, stored) {
			return nil, fault(api.CodeIntegrity, "approval reply differs from committed approval")
		}
	default:
		if api.Methods[input.Scope.Request.Method].Response == reflect.TypeFor[api.Operation]() {
			data, err := json.Marshal(operation)
			if err != nil {
				return nil, err
			}
			reply.Result = data
		} else {
			return nil, api.NotImplemented("lb-v2-service", "projection-correlated reply for method")
		}
	}
	return reply, wire.ValidateResult(input.Scope.Request.Method, reply.Result)
}

func stampEffectCause(effect *api.Effect) {
	if effect.HelperAllocate != nil {
		effect.HelperAllocate.Cause = *effect.Context
	}
	if effect.HelperPrepare != nil {
		effect.HelperPrepare.Cause = *effect.Context
	}
	if effect.HelperRelease != nil {
		effect.HelperRelease.Cause = *effect.Context
	}
	if effect.HelperAbort != nil {
		effect.HelperAbort.Cause = *effect.Context
		effect.HelperAbort.OperationID = effect.OperationID
	}
}

func allowedInternal(input api.Transaction) bool {
	return boundInternalActor(input) && validEmitter(input)
}

func boundInternalActor(input api.Transaction) bool {
	if input.Internal == nil || input.Scope.Connection != nil && input.Scope.Actor.Kind != "worker" {
		return false
	}
	if input.Scope.Actor.Kind != "service" && input.Scope.Actor.Kind != "scheduler" && input.Scope.Actor.Kind != "watchdog" && input.Scope.Actor.Kind != "worker" {
		return false
	}
	if input.Internal.Actor != input.Scope.Actor {
		return false
	}
	return true
}

func containsWord(words, word string) bool {
	for _, item := range strings.Fields(words) {
		if item == word {
			return true
		}
	}
	return false
}
