// Contract draft.3 consumer stubs. These fail until the owning lane ports
// its implementation; no interface-only change is runtime acceptance.
package records

import (
	"context"
	"laneboss.io/laneboss/internal/v2/api"
)

var _ api.OwnerIntake = (*Service)(nil)

func (s *Service) ReceiveExternal(arg0 context.Context, arg1 api.Scope, arg2 api.WorkerLease, arg3 api.ExternalMessage) (api.Mail, error) {
	var result api.Mail
	return result, api.NotImplemented("lb-v2-integrate", "records.ReceiveExternal")
}

func (s *Service) ImportOwnerSheet(arg0 context.Context, arg1 api.Scope, arg2 api.WorkerLease, arg3 api.OwnerSheetInput) (api.Operation, error) {
	var result api.Operation
	return result, api.NotImplemented("lb-v2-integrate", "records.ImportOwnerSheet")
}
