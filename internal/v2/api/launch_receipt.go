package api

import "context"

// LaunchReceiptRequest selects the original receipt through a protected public
// launch reservation. It supplies no caller identity or arbitrary receipt key.
type LaunchReceiptRequest struct {
	ReservationID ID
}

// LaunchReceiptReader is an internal port, absent from the RPC catalog.
type LaunchReceiptReader interface {
	LaunchReceipt(context.Context, Scope, LaunchReceiptRequest) (MutationReceipt, error)
}
