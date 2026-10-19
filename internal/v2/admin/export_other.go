//go:build !linux

package admin

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

// Native mount/export ownership is a Linux helper capability. Darwin keeps
// the typed refusal and uses the independent-copy route until its owner hook
// is installed; no path or success-shaped descriptor is fabricated here.
func (m *leaseManager) registerGateExports(_ context.Context, record *leaseRecord) error {
	if record == nil || record.Spec == nil {
		return failure(api.CodeIntegrity, "registered export needs its retained launch spec")
	}
	if len(record.Exports) != 0 {
		return failure(api.CodeIntegrity, "registered export journal cannot be reopened on this native backend")
	}
	for _, grant := range record.Spec.Handoff.Spec.Grants.Data {
		if grant.Destination != "/work/main" || grant.Delivery != "copy" || grant.HistoryScope == "reachable" {
			return failure(api.CodeUnsupported, "native backend requires the independent-copy data route")
		}
	}
	return nil
}

func (m *leaseManager) collectGateExports(_ api.ID) error { return nil }
