package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

var _ api.LaunchReceiptReader = (*Service)(nil)

type loopReceipt struct {
	Scheduler api.InstalledScheduler
	Receipt   api.MutationReceipt
}

func (s *Service) loopReceipt(ctx context.Context, db queryer, r api.LaunchReservation) (api.MutationReceipt, error) {
	var saved loopReceipt
	if err := storedProjection(ctx, db, "loop_receipt", r.ID, &saved); err != nil {
		return api.MutationReceipt{}, err
	}
	c, receipt := r.Loop, saved.Receipt
	var operation api.Operation
	if c == nil || saved.Scheduler != c.Scheduler || receipt.Config != r.Config || receipt.Actor != r.RequestedBy ||
		receipt.Key != (api.RequestKey{Method: "loop.reserved", IdempotencyKey: r.ID, RequestSHA256: r.RequestSHA256}) ||
		receipt.PolicyGeneration != r.PolicyGeneration || receipt.Operation.ID != r.OperationID || receipt.Operation.Status != "pending" ||
		receipt.Operation.LifeID != r.Target.LifeID || receipt.Operation.Run != r.Target.Run || receipt.FirstSeq == 0 || receipt.LastSeq != receipt.FirstSeq ||
		receipt.Operation.FirstSeq != receipt.FirstSeq || receipt.Operation.LastSeq != receipt.LastSeq || receipt.RecordedAt != c.ReservedAt ||
		receipt.Reply == nil || receipt.Reply.Error != nil || receipt.Deferred != nil || receipt.SimulatedPresence ||
		wire.Decode(receipt.Reply.Result, &operation) != nil || !sameValue(operation, receipt.Operation) ||
		api.Digest(hash(receipt.RawRequest)) != r.RequestSHA256 || int64(len(receipt.RawRequest)) != r.OriginalRequest.Bytes {
		return api.MutationReceipt{}, fault(api.CodeIntegrity, "loop receipt lost its original private scheduler input")
	}
	var raw []byte
	if err := db.QueryRowContext(ctx, "SELECT data FROM events WHERE seq=?", uint64(receipt.FirstSeq)).Scan(&raw); err != nil {
		return api.MutationReceipt{}, err
	}
	var event api.Event
	if wire.Decode(raw, &event) != nil || api.ValidateLoopReservedEvent(event, r) != nil || !bytes.Equal(event.Payload, receipt.RawRequest) {
		return api.MutationReceipt{}, fault(api.CodeIntegrity, "loop receipt lost its exact reservation event")
	}
	return receipt, nil
}

// LaunchReceipt preserves the service reader and binds the original public
// receipt to its protected reservation. Public LookupReceipt remains keyed to
// its authenticated owner and is never called with a borrowed human identity.
func (s *Service) LaunchReceipt(ctx context.Context, scope api.Scope, request api.LaunchReceiptRequest) (api.MutationReceipt, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return api.MutationReceipt{}, err
	}
	if err := s.readScope(ctx, scope); err != nil {
		return api.MutationReceipt{}, err
	}
	if !internalScope(scope) || scope.Actor.Kind != "service" || scope.Frame != nil || scope.Request.Method != "" {
		return api.MutationReceipt{}, fault(api.CodeForbidden, "launch receipt selection requires the private service read scope")
	}
	db, err := s.reader(scope)
	if err != nil {
		return api.MutationReceipt{}, err
	}
	var plan api.LaunchPlanRecord
	if err := storedProjection(ctx, db, "launch_plan", request.ReservationID, &plan); err != nil {
		return api.MutationReceipt{}, err
	}
	if plan.Reservation.ID != request.ReservationID {
		return api.MutationReceipt{}, fault(api.CodeIntegrity, "launch receipt reservation identity differs")
	}
	return s.reservationReceipt(ctx, db, plan)
}

func (s *Service) reservationReceipt(ctx context.Context, db queryer, plan api.LaunchPlanRecord) (api.MutationReceipt, error) {
	if err := s.checkLaunchBytes(ctx, db, plan); err != nil {
		return api.MutationReceipt{}, err
	}
	r := plan.Reservation
	if r.Loop != nil {
		return s.loopReceipt(ctx, db, r)
	}
	refuse := func() (api.MutationReceipt, error) {
		return api.MutationReceipt{}, fault(api.CodeForbidden, "launch receipt differs from its retained reservation authority")
	}
	if r.Config != s.deps.Config || r.RequestedBy.Kind != "human" && r.RequestedBy.Kind != "lane" ||
		r.Mode != "start" && r.Mode != "adopt" && r.Mode != "resume" && r.Mode != "turn" {
		return refuse()
	}
	var owner launchOwner
	if err := storedProjection(ctx, db, "launch_operation", r.OperationID, &owner); err != nil {
		return api.MutationReceipt{}, err
	}
	if owner.ReservationID != r.ID || owner.Actor != r.RequestedBy || owner.Request.OperationID != r.OperationID || owner.Request.ContinuationID != "" {
		return refuse()
	}
	var principalID string
	var raw, receiptData []byte
	if err := db.QueryRowContext(ctx, "SELECT receipts.principal,receipts.request,replies.data FROM receipts JOIN replies USING(principal,method,key) WHERE json_extract(receipts.operation,'$.id')=?", string(r.OperationID)).Scan(&principalID, &raw, &receiptData); err != nil {
		if cause := ctx.Err(); cause != nil {
			return api.MutationReceipt{}, cause
		}
		if errors.Is(err, sql.ErrNoRows) {
			return api.MutationReceipt{}, fault(api.CodeIntegrity, "launch receipt has no retained owner")
		}
		return api.MutationReceipt{}, err
	}
	var stored storedReceipt
	if err := decodeStored(receiptData, &stored); err != nil {
		return api.MutationReceipt{}, err
	}
	frame, err := wire.DecodeRequest(raw)
	if err != nil {
		return api.MutationReceipt{}, err
	}
	receipt := stored.Receipt
	if principalID != r.RequestedBy.Kind+":"+string(r.RequestedBy.ID)+":"+string(r.RequestedBy.LifeID) ||
		stored.Config != r.Config || receipt.Config != r.Config || receipt.Actor != r.RequestedBy ||
		receipt.Operation.ID != r.OperationID || receipt.Operation.LifeID != r.Target.LifeID || receipt.Operation.Run != r.Target.Run ||
		receipt.PolicyGeneration != r.PolicyGeneration || receipt.Key != requestKey(frame) || !bytes.Equal(receipt.RawRequest, raw) ||
		frame.Config != r.Config || frame.Method != api.Method("lane."+r.Mode) || frame.RequestID != r.RequestID || frame.RequestSHA256 != r.RequestSHA256 {
		return refuse()
	}
	return receipt, nil
}
