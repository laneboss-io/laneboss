package assembly

import (
	"context"
	"io"

	"laneboss.io/laneboss/internal/v2/dashboard"
	"laneboss.io/laneboss/internal/v2/service"
)

type noDashboardEntry struct{}

func (noDashboardEntry) Close() error { return nil }

// bindDashboardEntry uses the already installed relying-party pins. It adds
// no service boot keys and never opens a TLS listener with a default origin.
func bindDashboardEntry(ctx context.Context, server *service.Server, views *dashboard.Service, installed Installation) (io.Closer, error) {
	if installed.AdminEnrollment == nil {
		return noDashboardEntry{}, nil
	}
	if err := views.ConfigureHTTP(installed.Config, installed.AdminEnrollment.Origin, installed.AdminEnrollment.RPID); err != nil {
		return nil, err
	}
	return server.OpenDashboardEntry(ctx)
}
