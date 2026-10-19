//go:build !linux

package admin

import (
	"context"
	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Service) ServeEnrollment(context.Context, api.AdminEnrollmentEndpoint) error {
	return failure(api.CodeUnsupported, "protected administrator enrollment requires its native Linux backend")
}

func runEnrollment(context.Context, string, enrollmentOptions) (any, error) {
	return nil, failure(api.CodeUnsupported, "fixed administrator enrollment requires its native Linux backend")
}
