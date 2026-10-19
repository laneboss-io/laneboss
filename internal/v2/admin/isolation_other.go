//go:build !linux

package admin

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

func isolationDenials(isolationCanary) bool { return false }
func limitValues(leaseRecord) [][2]string   { return nil }
func verifyIsolationHost(isolationProof) error {
	return failure(api.CodeUnsupported, "installed isolation evidence requires Linux")
}
func runIsolationCanary(context.Context, string) error {
	return failure(api.CodeUnsupported, "installed isolation canary requires Linux")
}
