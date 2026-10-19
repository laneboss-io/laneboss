//go:build !linux

package admin

import (
	"context"
	"io"

	"laneboss.io/laneboss/internal/v2/api"
)

func loadInitialInstalled(context.Context, api.AdminEnrollmentEndpoint, InitialRequest) (initialBundle, error) {
	return initialBundle{}, failure(api.CodeUnsupported, "initial protected publication requires Linux")
}
func RunInitialValidation(context.Context, string, []string, io.Writer) error {
	return failure(api.CodeUnsupported, "initial protected validation requires Linux")
}
func InitialContext(context.Context, api.AdminEnrollmentEndpoint, api.ConnectionContext, api.FrameContext) (context.Context, error) {
	return nil, failure(api.CodeUnsupported, "initial protected channel requires Linux")
}
