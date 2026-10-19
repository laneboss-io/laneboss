package admin

import (
	"context"

	"laneboss.io/laneboss/internal/v2/orgrender"
)

func (s *Service) RenderOrg(ctx context.Context, stage orgrender.Stage) (orgrender.Result, error) {
	var result orgrender.Result
	err := s.call(ctx, "org_render", stage, &result)
	return result, err
}
