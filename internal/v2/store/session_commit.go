package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/identity"
)

var _ identity.SessionReadback = (*Service)(nil)

// ReadSessionCommit is a constructor-only identity capability. It selects the
// session from the verified request's actual completed receipt, never a caller
// session label. Transport verification stays outside the store lock; all
// durable facts below come from one read transaction without public read access.
func (s *Service) ReadSessionCommit(ctx context.Context, scope api.Scope) (identity.SessionCommit, error) {
	var empty identity.SessionCommit
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if scope.Config != s.deps.Config || scope.Actor.Kind != "human" || !wire.ValidID(string(scope.Actor.ID)) ||
		scope.Request.Config != scope.Config || scope.LaunchID != "" || scope.Connection == nil || scope.Frame == nil || scope.Request.Method != "human.session" || scope.Request.Proof == nil {
		return empty, fault(api.CodeUnauthenticated, "session read-back requires its verified human session frame")
	}
	connection, frame := scope.Connection, scope.Frame
	binding, connectionID := connection.Binding(), connection.ID()
	if err := api.ValidateBinding(binding, s.deps.Config, binding.ServiceVersion); err != nil {
		return empty, err
	}
	peer := connection.Peer()
	if binding.Class != api.EndpointHuman || binding.EndpointGeneration != scope.EndpointGeneration || !wire.ValidID(string(connectionID)) || peer == nil {
		return empty, fault(api.CodeUnauthenticated, "session read-back differs from the installed human endpoint")
	}
	if err := frame.Verify(ctx, connection); err != nil {
		return empty, err
	}
	if err := peer.Alive(ctx); err != nil {
		return empty, err
	}
	facts, err := peer.Facts(ctx)
	if err != nil {
		return empty, err
	}
	if facts.HostPID <= 1 || facts.ProcessGeneration == "" {
		return empty, fault(api.CodeUnauthenticated, "session read-back requires a pinned native peer lifetime")
	}
	raw := append([]byte(nil), frame.Bytes()...)
	request, err := wire.DecodeRequest(raw)
	if err != nil {
		return empty, err
	}
	encoded, err := json.Marshal(scope.Request)
	if err != nil || !wire.SameJSON(encoded, raw) {
		return empty, fault(api.CodeIntegrity, "session read-back scope differs from its verified frame")
	}
	// Freeze the only connection fields used by database authorization helpers.
	// Neither the native peer nor the frame can be called under mu.
	frozen := scope
	frozen.Connection = readSessionConnection{id: connectionID, binding: binding}
	frozen.Frame, frozen.ReadView, frozen.ReadAuthority = nil, nil, nil
	frozen.Request = request
	snapshot, err := s.readSessionCommit(ctx, frozen, raw)
	if err != nil {
		return empty, err
	}
	if err := frame.Verify(ctx, connection); err != nil {
		return empty, err
	}
	if err := peer.Alive(ctx); err != nil {
		return empty, err
	}
	current, err := peer.Facts(ctx)
	if err != nil {
		return empty, err
	}
	if current != facts || connection.ID() != connectionID || !reflect.DeepEqual(connection.Binding(), binding) || !bytes.Equal(frame.Bytes(), raw) {
		return empty, fault(api.CodeUnauthenticated, "session read-back peer or frame changed")
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	return snapshot, nil
}

func (s *Service) readSessionCommit(ctx context.Context, scope api.Scope, raw []byte) (snapshot identity.SessionCommit, resultErr error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return snapshot, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return snapshot, err
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			resultErr = errors.Join(resultErr, err)
		}
	}()
	key := requestKey(scope.Request)
	snapshot.Receipt, err = s.lookupReceipt(ctx, tx, scope, key)
	if err != nil {
		return snapshot, err
	}
	receipt := snapshot.Receipt
	committed, stampErr := time.Parse(time.RFC3339Nano, string(receipt.RecordedAt))
	now := s.deps.Clock.Now()
	if receipt.Config != scope.Config || receipt.Actor != scope.Actor || receipt.Key != key || !bytes.Equal(receipt.RawRequest, raw) ||
		receipt.Reply == nil || receipt.Reply.Error != nil || receipt.Deferred != nil || receipt.Operation.Status != "succeeded" || receipt.Operation.Error != nil ||
		!wire.ValidID(string(receipt.Operation.ID)) || receipt.FirstSeq == 0 || receipt.LastSeq < receipt.FirstSeq ||
		receipt.Operation.FirstSeq != receipt.FirstSeq || receipt.Operation.LastSeq != receipt.LastSeq || stampErr != nil || committed.After(now) {
		return snapshot, fault(api.CodeIntegrity, "session read-back has no exact completed receipt")
	}
	// Independently bind the immutable request/operation row and current operation
	// projection to the completed reply rather than trusting the reply alone.
	var retainedRaw, retainedOperation, operationData []byte
	if err := tx.QueryRowContext(ctx, "SELECT request,operation FROM receipts WHERE principal=? AND method=? AND key=?",
		principal(scope), string(key.Method), string(key.IdempotencyKey)).Scan(&retainedRaw, &retainedOperation); err != nil {
		return snapshot, err
	}
	if err := tx.QueryRowContext(ctx, "SELECT data FROM operations WHERE id=? AND principal=?", string(receipt.Operation.ID), principal(scope)).Scan(&operationData); err != nil {
		return snapshot, err
	}
	var operation, original api.Operation
	if wire.Decode(operationData, &operation) != nil || wire.Decode(retainedOperation, &original) != nil ||
		!sameValue(operation, receipt.Operation) || !sameValue(original, receipt.Operation) || !bytes.Equal(retainedRaw, raw) {
		return snapshot, fault(api.CodeIntegrity, "session receipt differs from its durable operation")
	}
	policy, err := s.operationPolicy(ctx, tx)
	if err != nil {
		return snapshot, err
	}
	if policy == 0 || policy != scope.PolicyGeneration || receipt.PolicyGeneration != policy {
		return snapshot, fault(api.CodeUnauthenticated, "session receipt policy is no longer current")
	}
	var retained api.HumanSession
	if err := wire.Decode(receipt.Reply.Result, &retained); err != nil {
		return snapshot, err
	}
	sessionRevision, err := sessionProjection(ctx, tx, "read_session", retained.ID, &snapshot.Session)
	if err != nil {
		return snapshot, err
	}
	session := snapshot.Session
	expires, expiryErr := time.Parse(time.RFC3339Nano, string(retained.ExpiresAt))
	idle, idleErr := time.Parse(time.RFC3339Nano, string(retained.IdleExpiresAt))
	if sessionRevision != 1 || session.Generation != sessionRevision || session.Session != retained || session.Revoked ||
		retained.Config != scope.Config || session.PrincipalID != scope.Actor.ID || session.ConnectionID != scope.Connection.ID() || session.EndpointGeneration != scope.EndpointGeneration ||
		!wire.ValidID(string(session.CredentialID)) || expiryErr != nil || idleErr != nil || !now.Before(expires) || !now.Before(idle) || idle.After(expires) ||
		expires.After(committed.Add(30*time.Minute)) || idle.After(committed.Add(5*time.Minute)) {
		return snapshot, fault(api.CodeUnauthenticated, "session read-back is not this live initial session")
	}
	var principals int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM projections WHERE kind='enrollment'").Scan(&principals); err != nil {
		return snapshot, err
	}
	enrollmentRevision, err := sessionProjection(ctx, tx, "enrollment", scope.Actor.ID, &snapshot.Enrollment)
	if err != nil {
		return snapshot, err
	}
	enrollment := snapshot.Enrollment
	if principals != 1 || enrollment.Config != scope.Config || enrollment.PrincipalID != scope.Actor.ID || enrollmentRevision == 0 || enrollment.Generation != enrollmentRevision {
		return snapshot, fault(api.CodeUnauthenticated, "session read-back enrollment is not the current endpoint principal")
	}
	if err := api.ValidateHumanEnrollments(scope.Config, []api.HumanEnrollment{enrollment}); err != nil {
		return snapshot, err
	}
	proofRevision, err := sessionProjection(ctx, tx, "proof", scope.Request.Proof.ID, &snapshot.Proof)
	if err != nil {
		return snapshot, err
	}
	proof := snapshot.Proof
	target, err := s.authorizationTarget(ctx, tx, scope, scope.Request)
	if err != nil {
		return snapshot, err
	}
	verified, verifiedErr := time.Parse(time.RFC3339Nano, string(proof.VerifiedAt))
	proofEnd, proofErr := time.Parse(time.RFC3339Nano, string(proof.Ref.ExpiresAt))
	if proofRevision != 1 || proof.Ref != *scope.Request.Proof || proof.Target != target || proof.ConsumedBy != receipt.Operation.ID ||
		proof.Config != scope.Config || proof.PrincipalID != scope.Actor.ID || proof.CredentialID != session.CredentialID ||
		proof.EndpointClass != api.EndpointHuman || proof.EndpointGeneration != scope.EndpointGeneration || !wire.ValidID(string(proof.ConnectionID)) ||
		!wire.ValidID(string(proof.NonceID)) || !wire.ValidID(string(proof.AssertionEvidence.ID)) || !wire.ValidDigest(string(proof.AssertionEvidence.SHA256)) ||
		proof.AssertionEvidence.Class != "artifact" || proof.AssertionEvidence.Bytes <= 0 || proof.AssertionEvidence.Bytes > api.MaxFrameBytes ||
		verifiedErr != nil || proofErr != nil || verified.After(committed) || !committed.Before(proofEnd) || !verified.Before(proofEnd) || proofEnd.After(verified.Add(120*time.Second)) ||
		retained.SimulatedPresence != proof.SimulatedPresence || receipt.SimulatedPresence != proof.SimulatedPresence || operation.SimulatedPresence != proof.SimulatedPresence {
		return snapshot, fault(api.CodeUnauthenticated, "session read-back proof was not consumed by this operation")
	}
	credential, err := s.proofCredential(ctx, tx, proof)
	if err != nil {
		return snapshot, err
	}
	if credential.Generation == 0 {
		return snapshot, fault(api.CodeUnauthenticated, "session credential has no current revision")
	}
	var used api.ProofUseReceipt
	useRevision, err := sessionProjection(ctx, tx, "proof_use", proof.Ref.ID, &used)
	if err != nil {
		return snapshot, err
	}
	if useRevision != 1 || used.OperationID != operation.ID || used.NonceID != proof.NonceID {
		return snapshot, fault(api.CodeIntegrity, "session proof-use receipt belongs to another operation")
	}
	if err := api.ValidateProofPresence(credential, proof, used); err != nil {
		return snapshot, err
	}
	metadata, assertion, err := objectRow(ctx, tx, proof.AssertionEvidence.ID)
	if err != nil {
		return snapshot, err
	}
	var confirmation api.HumanConfirmRequest
	if metadata.Ref != proof.AssertionEvidence || metadata.Ref.Class != "artifact" || metadata.Origin != "identity" ||
		metadata.ACL.Config != scope.Config || metadata.ACL.Owner != scope.Actor || metadata.ACL.Audience != "private" || metadata.ACL.LifeID != "" || len(metadata.ACL.Participants) != 0 ||
		metadata.ACL.Generation != 1 ||
		wire.Decode(assertion, &confirmation) != nil || confirmation.ChallengeID != proof.NonceID || confirmation.CredentialID != proof.CredentialID {
		return snapshot, fault(api.CodeIntegrity, "session proof has no exact private assertion evidence")
	}
	return snapshot, nil
}

// Decode a private row together with its actual database revision. Ordinary
// public projection readers and their connection authority checks are unchanged.
func sessionProjection(ctx context.Context, tx *sql.Tx, kind string, id api.ID, out any) (api.Generation, error) {
	var revision api.Generation
	var data []byte
	if err := tx.QueryRowContext(ctx, "SELECT generation,data FROM projections WHERE kind=? AND id=?", kind, string(id)).Scan(&revision, &data); err != nil {
		return 0, err
	}
	return revision, decodeStored(data, out)
}
