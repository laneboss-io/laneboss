// Package distribution is owned by lb-v2-packaging.
package distribution

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

type Dependencies struct {
	Control   api.DispatchControl
	Installer api.DeploymentInstaller
	Migration api.MigrationAPI
	Store     api.StateStore
	Human     api.HumanVerifier
	Helper    api.Helper
}

type Service struct {
	deps Dependencies
}

func New(deps Dependencies) (*Service, error) {
	if err := api.RequireDependencies("lb-v2-packaging", deps.Store, deps.Human, deps.Helper, deps.Control, deps.Installer, deps.Migration); err != nil {
		return nil, err
	}
	return &Service{deps: deps}, nil
}

var _ api.PackagingAPI = (*Service)(nil)
var _ api.Module = (*Service)(nil)

func (s *Service) Register(registry api.Registrar) error {
	if err := api.RequireDependencies("lb-v2-packaging", s, registry); err != nil {
		return err
	}
	routes := []func() error{
		func() error { return register(registry, "upgrade.plan", s.UpgradePlan) },
		func() error { return register(registry, "upgrade.apply", s.UpgradeApply) },
	}
	for _, route := range routes {
		if err := route(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) UpgradePlan(ctx context.Context, scope api.Scope, request api.UpgradePlanRequest) (api.UpgradePlan, error) {
	// TODO(lb-v2-packaging): implement upgrade.plan under the frozen contract.
	var result api.UpgradePlan
	return result, api.NotImplemented("lb-v2-packaging", "distribution.upgrade.plan")
}

func (s *Service) UpgradeApply(ctx context.Context, scope api.Scope, request api.UpgradeApplyRequest) (api.Operation, error) {
	// TODO(lb-v2-packaging): implement upgrade.apply under the frozen contract.
	var result api.Operation
	return result, api.NotImplemented("lb-v2-packaging", "distribution.upgrade.apply")
}
