//go:build !linux

package store

import (
	"context"
	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Service) PublishChange(context.Context, api.Scope, api.PublishChangeRequest) (api.ChangeReceipt, error) {
	return api.ChangeReceipt{}, fault(api.CodeUnsupported, "canonical publication requires the enrolled Linux publisher")
}
func (s *Service) ReconcileChange(ctx context.Context, scope api.Scope, request api.PublishChangeRequest) (api.ChangeReceipt, error) {
	return s.PublishChange(ctx, scope, request)
}
func (s *Service) publicationReadback(orgApply) (orgPublicationMarker, error) {
	return orgPublicationMarker{}, fault(api.CodeUnsupported, "canonical publication requires the enrolled Linux publisher")
}
func (s *Service) publicationUnchanged(orgApply) error {
	return fault(api.CodeUnsupported, "canonical publication requires the enrolled Linux publisher")
}
func (s *Service) verifyCurrentOrgPublication(orgApply, api.ChangeReceipt) error {
	return fault(api.CodeUnsupported, "canonical publication requires the enrolled Linux publisher")
}
