package store

import (
	"context"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

var _ api.LaunchTicketReader = (*Service)(nil)

// LaunchTicket preserves the authenticated caller and its pinned read view.
// Ownership comes from the retained receipt and consumed reservation guard,
// including the original human endpoint generation, never from a relabelled
// service scope. Public Ticket continues to enforce its caller's provenance.
func (s *Service) LaunchTicket(ctx context.Context, scope api.Scope, request api.LaunchTicketRequest) (api.Ticket, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return api.Ticket{}, err
	}
	if err := s.readScope(ctx, scope); err != nil {
		return api.Ticket{}, err
	}
	if !internalScope(scope) || scope.Actor.Kind != "service" || scope.Frame != nil || scope.Request.Method != "" {
		return api.Ticket{}, fault(api.CodeForbidden, "launch ticket selection requires the private service read scope")
	}
	db, err := s.reader(scope)
	if err != nil {
		return api.Ticket{}, err
	}
	var plan api.LaunchPlanRecord
	if err := storedProjection(ctx, db, "launch_plan", request.ReservationID, &plan); err != nil {
		return api.Ticket{}, err
	}
	if plan.Reservation.ID != request.ReservationID {
		return api.Ticket{}, fault(api.CodeIntegrity, "launch ticket reservation identity differs")
	}
	return s.reservationTicket(ctx, db, plan)
}

func (s *Service) reservationTicket(ctx context.Context, db queryer, plan api.LaunchPlanRecord) (api.Ticket, error) {
	if err := s.checkLaunchBytes(ctx, db, plan); err != nil {
		return api.Ticket{}, err
	}
	r := plan.Reservation
	refuse := func() (api.Ticket, error) {
		return api.Ticket{}, fault(api.CodeForbidden, "launch ticket differs from its retained reservation authority")
	}
	if r.Config != s.deps.Config || r.RequestedBy.Kind != "human" || r.ParentLifeID != "" ||
		(r.Mode != "start" && r.Mode != "adopt") || r.Authority.Kind != "ticket" {
		return refuse()
	}
	var owner launchOwner
	if err := storedProjection(ctx, db, "launch_operation", r.OperationID, &owner); err != nil {
		return api.Ticket{}, err
	}
	if owner.ReservationID != r.ID || owner.Actor != r.RequestedBy || owner.Request.OperationID != r.OperationID ||
		owner.Request.ContinuationID != "" || len(owner.Request.Guards) != 1 {
		return refuse()
	}
	guard := owner.Request.Guards[0]
	use := guard.Ticket
	if use == nil || !sameValue(guard, api.TransactionGuard{Ticket: use}) || use.TicketID != r.Authority.ID ||
		use.PrincipalID != r.RequestedBy.ID || use.Config != r.Config || use.EndpointGeneration == 0 ||
		use.Level != r.Level || use.Role != r.Role || use.Target != (api.LifeRef{}) {
		return refuse()
	}
	// The actual receipt independently binds the requester and exact bytes;
	// its read does not invoke public LookupReceipt or construct a human scope.
	receipt, err := s.reservationReceipt(ctx, db, plan)
	if err != nil {
		return api.Ticket{}, err
	}
	// ReserveLaunch consumes the ticket and retains this private input in
	// the same transaction. Its service timestamp bounds admission, whereas
	// the current planning claimant may run after the one-use ticket expires.
	metadata, _, err := objectRow(ctx, db, r.OriginalRequest.ID)
	if err != nil {
		return api.Ticket{}, err
	}
	reservedAt, err := time.Parse(time.RFC3339Nano, string(metadata.CommittedAt))
	if err != nil || reservedAt.IsZero() || reservedAt.UTC().Format(time.RFC3339Nano) != string(metadata.CommittedAt) || reservedAt.After(s.deps.Clock.Now()) {
		return refuse()
	}
	frame, err := wire.DecodeRequest(receipt.RawRequest)
	if err != nil {
		return api.Ticket{}, err
	}
	var selected api.ID
	switch frame.Method {
	case "lane.start":
		var start api.StartRequest
		if err := api.DecodeObject(frame.Params, &start); err != nil {
			return api.Ticket{}, err
		}
		selected = start.RootTicketID
	case "lane.adopt":
		var adopt api.AdoptRequest
		if err := api.DecodeObject(frame.Params, &adopt); err != nil {
			return api.Ticket{}, err
		}
		selected = adopt.RootTicketID
	default:
		return refuse()
	}
	var authority launchAuthority
	if err := storedProjection(ctx, db, "launch_authority", r.ID, &authority); err != nil {
		return api.Ticket{}, err
	}
	var retained ticketRecord
	if err := storedProjection(ctx, db, "ticket", r.Authority.ID, &retained); err != nil {
		return api.Ticket{}, err
	}
	ticket := retained.Ticket
	if selected != r.Authority.ID || authority.TicketID != r.Authority.ID || use.GrantSetID != authority.Ceiling.ID ||
		retained.RedeemedBy != r.OperationID || retained.PrincipalID != use.PrincipalID || retained.Config != use.Config ||
		retained.EndpointGeneration != use.EndpointGeneration || ticket.ID != use.TicketID ||
		ticket.PrincipalID != use.PrincipalID || ticket.Config != use.Config || ticket.EndpointGeneration != use.EndpointGeneration ||
		ticket.Level != use.Level || ticket.Role != use.Role || ticket.GrantSetID != use.GrantSetID ||
		!ticket.Redeemed || !future(ticket.ExpiresAt, reservedAt) {
		return refuse()
	}
	return ticket, nil
}
