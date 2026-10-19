// Contract draft.3 consumer stubs. These fail until the owning lane ports
// its implementation; no interface-only change is runtime acceptance.
package admin

import (
	"context"
	"laneboss.io/laneboss/internal/v2/api"
)

var _ api.HelperControl = (*Service)(nil)
var _ api.DeploymentInstaller = (*Service)(nil)
var _ api.ProbeBinder = (*Service)(nil)

func (s *Service) StageDeployment(arg0 context.Context, arg1 api.Scope, arg2 api.DeploymentInstallRequest) (api.DeploymentReceipt, error) {
	var result api.DeploymentReceipt
	return result, api.NotImplemented("lb-v2-admin", "admin.StageDeployment")
}

func (s *Service) ActivateDeployment(arg0 context.Context, arg1 api.Scope, arg2 api.DeploymentInstallRequest) (api.DeploymentReceipt, error) {
	var result api.DeploymentReceipt
	return result, api.NotImplemented("lb-v2-admin", "admin.ActivateDeployment")
}

func (s *Service) RestoreDeployment(arg0 context.Context, arg1 api.Scope, arg2 api.RollbackRequest) (api.DeploymentReceipt, error) {
	var result api.DeploymentReceipt
	return result, api.NotImplemented("lb-v2-admin", "admin.RestoreDeployment")
}
