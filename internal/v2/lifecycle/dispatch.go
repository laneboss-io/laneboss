package lifecycle

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

// MutationDispatch is a private service capability. It resolves the actual
// current dispatcher invocation's reservation ownership, including retries
// carrying an identical request ID/frame. IDs and matching bytes are not an
// ownership grant. The service must bind this to its atomic reservation winner.
type MutationDispatch interface {
	OwnsMutation(context.Context, api.Scope, api.RequestKey, api.ID) (bool, error)
}

func (s *Service) ownsMutation(ctx context.Context, scope api.Scope, key api.RequestKey, receipt api.MutationReceipt) (bool, error) {
	control := s.deps.Dispatch
	if absent(control) {
		control, _ = s.deps.Store.(MutationDispatch)
	}
	if absent(control) {
		return false, api.NotImplemented("lb-v2-service", "dispatcher pending receipt ownership")
	}
	if !receiptMatches(scope, key, receipt) || !validID(receipt.Operation.ID) {
		return false, integrity("pending mutation lost its exact reservation")
	}
	owned, err := control.OwnsMutation(ctx, scope, key, receipt.Operation.ID)
	return owned, failure(err)
}
