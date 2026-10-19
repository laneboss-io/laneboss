package api

import "context"

// LaunchTicketRequest selects a protected reservation, never a substitute
// principal or ticket. This in-process read port is absent from the RPC catalog.
type LaunchTicketRequest struct {
	ReservationID ID
}

type LaunchTicketReader interface {
	LaunchTicket(context.Context, Scope, LaunchTicketRequest) (Ticket, error)
}
