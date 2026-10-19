package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

type archiveAttemptOutcome struct{ cause error }

func (e *archiveAttemptOutcome) Error() string { return e.cause.Error() }
func (e *archiveAttemptOutcome) Unwrap() error { return e.cause }

func archiveFailure(err error) *api.Error {
	var typed *api.Error
	if errors.As(err, &typed) {
		copy := *typed
		if copy.Instead == "" {
			copy.Instead = "Preserve the original workspace and inspect the failed archive operation before requesting another archive."
		}
		return &copy
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fault(api.CodeDeadline, "archive preparation exceeded its deadline")
	}
	if errors.Is(err, context.Canceled) {
		return fault(api.CodeCancelled, "archive preparation was cancelled")
	}
	return fault(api.CodeUnavailable, "native archive preparation failed; inspect its retained operation")
}

// Native retry state shares the original writer. Live attempts cannot race a
// recovery tick; transient unavailability has durable exponential backoff.
func (s *Service) attemptArchive(ctx context.Context, prior archiveRecord) (archivejob.Job, error) {
	s.mu.Lock()
	var r archiveRecord
	if err := s.available(); err != nil {
		s.mu.Unlock()
		return archivejob.Job{}, err
	}
	if err := storedProjection(ctx, s.db, "archive_job", prior.Job.Intent.OperationID, &r); err != nil {
		s.mu.Unlock()
		return archivejob.Job{}, err
	}
	if r.Failure != nil {
		s.mu.Unlock()
		return archivejob.Job{}, &archiveAttemptOutcome{r.Failure}
	}
	if r.Phase != "freezing" {
		s.mu.Unlock()
		return r.Job, nil
	}
	if s.archiveFreezes[r.Job.Intent.OperationID] || future(r.NextFreeze, s.deps.Clock.Now()) {
		s.mu.Unlock()
		return archivejob.Job{}, &archiveAttemptOutcome{fault(api.CodeUnavailable, "original archive freeze is pending its recorded retry time")}
	}
	if s.archiveFreezes == nil {
		s.archiveFreezes = map[api.ID]bool{}
	}
	r.FreezeAttempts++
	delay := min(30*time.Second, time.Second<<min(r.FreezeAttempts-1, 5))
	r.NextFreeze = api.Timestamp(s.deps.Clock.Now().Add(delay).UTC().Format(timeFormat))
	tx, err := s.db.BeginTx(ctx, nil)
	if err == nil {
		err = s.saveArchive(ctx, tx, r)
		if err == nil {
			err = tx.Commit()
		} else {
			if rollback := tx.Rollback(); rollback != nil {
				err = rollback
			}
		}
	}
	if err != nil {
		s.mu.Unlock()
		return archivejob.Job{}, err
	}
	s.archiveFreezes[r.Job.Intent.OperationID] = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.archiveFreezes, r.Job.Intent.OperationID); s.mu.Unlock() }()
	// The insertion winner owns the intent, not the requesting connection.
	deadline, parseErr := time.Parse(time.RFC3339Nano, string(r.Job.Lease.ExpiresAt))
	if parseErr != nil {
		return archivejob.Job{}, parseErr
	}
	freezeParent := ctx
	if owner, _ := ctx.Value(reservationOwnerKey{}).(*reservationOwner); owner != nil && owner.store == s && owner.operation == r.Job.Intent.OperationID {
		freezeParent = context.WithoutCancel(ctx)
	}
	freezeCtx, cancel := context.WithTimeout(freezeParent, max(time.Duration(0), deadline.Sub(s.deps.Clock.Now())))
	defer cancel()
	job, err := s.sealArchive(freezeCtx, r)
	if err == nil {
		return job, nil
	}
	failure := archiveFailure(err)
	if ctx.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) && future(r.Job.Lease.ExpiresAt, s.deps.Clock.Now()) {
		return archivejob.Job{}, &archiveAttemptOutcome{failure}
	}
	// A transient native outage waits under this same intent. All other first
	// attempt outcomes, including moved life fences, receive a terminal reply.
	if failure.Code == api.CodeUnavailable && future(r.Job.Lease.ExpiresAt, s.deps.Clock.Now()) {
		return archivejob.Job{}, &archiveAttemptOutcome{failure}
	}
	if ctx.Err() != nil {
		ctx = context.WithoutCancel(ctx)
	}
	if err := s.failArchiveFreeze(ctx, r.Job.Intent.OperationID, failure); err != nil {
		return archivejob.Job{}, err
	}
	return archivejob.Job{}, &archiveAttemptOutcome{failure}
}

func (s *Service) failArchiveFreeze(ctx context.Context, operationID api.ID, failure *api.Error) (resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var r archiveRecord
	if err := storedProjection(ctx, s.db, "archive_job", operationID, &r); err != nil {
		return err
	}
	if r.Phase == "failed" {
		return nil
	}
	if r.Phase != "freezing" {
		return fault(api.CodeConflict, "archive was sealed before its freeze failure")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer finish(tx, &resultErr)
	public, err := s.lookupReceipt(ctx, tx, r.Scope, requestKey(r.Request))
	if err != nil {
		return err
	}
	op := public.Operation
	op.Status, op.Error, op.LifeID, op.Run = "failed", failure, r.Lane.LifeID, r.Lane.Run
	var head api.Sequence
	if err := tx.QueryRowContext(ctx, "SELECT coalesce(max(seq),0)+1 FROM events").Scan(&head); err != nil {
		return err
	}
	op.LastSeq = head
	if op.FirstSeq == 0 {
		op.FirstSeq = head
	}
	body, err := wire.EncodeOperationEvent(api.OperationEvent{Operation: op, RequestSHA256: r.Request.RequestSHA256})
	if err != nil {
		return err
	}
	event, err := s.archiveEvent(r, "operation.failed", json.RawMessage(body))
	if err != nil {
		return err
	}
	seq, err := appendPrivateEvent(ctx, tx, event, api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat)))
	if err != nil {
		return err
	}
	if seq != head {
		return fault(api.CodeIntegrity, "archive failure changed its journal head")
	}
	public.Operation, public.Reply, public.FirstSeq, public.LastSeq = op, &api.RPCReply{Error: failure}, op.FirstSeq, seq
	operationBytes, err := json.Marshal(op)
	if err != nil {
		return err
	}
	receiptBytes, err := json.Marshal(storedReceipt{Config: s.deps.Config, Receipt: public})
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE operations SET data=? WHERE id=?", operationBytes, string(operationID)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO receipts VALUES(?,?,?,?,?,?)", principal(r.Scope), string(r.Request.Method), string(r.Request.IdempotencyKey), string(r.Request.RequestSHA256), public.RawRequest, operationBytes); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO replies VALUES(?,?,?,?)", principal(r.Scope), string(r.Request.Method), string(r.Request.IdempotencyKey), receiptBytes); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM reservations WHERE operation_id=?", string(operationID)); err != nil {
		return err
	}
	r.Phase, r.Failure = "failed", failure
	r.Commit = &api.Commit{Operation: op, Reply: public.Reply, FirstSeq: seq, LastSeq: seq}
	if err := s.saveArchive(ctx, tx, r); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.notifyChanged()
	return nil
}
