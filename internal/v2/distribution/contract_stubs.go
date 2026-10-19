// Contract draft.3 consumer stubs. These fail until the owning lane ports
// its implementation; no interface-only change is runtime acceptance.
package distribution

import (
	"context"
	"laneboss.io/laneboss/internal/v2/api"
)

var _ api.DeploymentCoordinator = (*Service)(nil)

func (s *Service) PlanDeployment(arg0 context.Context, arg1 api.Scope, arg2 api.UpgradePlanRequest) (api.DeploymentPlan, error) {
	var result api.DeploymentPlan
	return result, api.NotImplemented("lb-v2-packaging", "distribution.PlanDeployment")
}

func (s *Service) ApplyDeployment(arg0 context.Context, arg1 api.Scope, arg2 api.UpgradeApplyRequest) (api.Operation, error) {
	var result api.Operation
	return result, api.NotImplemented("lb-v2-packaging", "distribution.ApplyDeployment")
}

func (s *Service) ReconcileDeployment(arg0 context.Context, arg1 api.Scope, arg2 api.ID) (api.Operation, error) {
	var result api.Operation
	return result, api.NotImplemented("lb-v2-packaging", "distribution.ReconcileDeployment")
}

func (s *Service) RollbackDeployment(arg0 context.Context, arg1 api.Scope, arg2 api.RollbackRequest) (api.Operation, error) {
	var result api.Operation
	return result, api.NotImplemented("lb-v2-packaging", "distribution.RollbackDeployment")
}
