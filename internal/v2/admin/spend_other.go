//go:build !linux

package admin

import (
	"context"
	"laneboss.io/laneboss/internal/v2/api"
)

func SpendContext(context.Context, api.AdminEnrollmentEndpoint, api.ConnectionContext, api.FrameContext) (context.Context, error) {
	return nil, failure(api.CodeUnsupported, "spend administrator channel requires Linux")
}
