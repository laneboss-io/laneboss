//go:build !linux

package admin

import (
	"context"
	"laneboss.io/laneboss/internal/v2/api"
)

func readReviewProtected(string, int64) ([]byte, error) {
	return nil, failure(api.CodeUnsupported, "native protected review requirements require Linux")
}

func (s *Service) bindReviewContainment(context.Context, archiveReg) error {
	return failure(api.CodeUnsupported, "native review containment requires Linux")
}
