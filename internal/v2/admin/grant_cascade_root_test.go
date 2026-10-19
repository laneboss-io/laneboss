//go:build linux && laneboss_root_canary && laneboss_gate_integration

package admin

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func RunGrantCascadeUnit(t *testing.T) { runReleaseUnit(t, "TestGrantCascadeNative", true) }

func RunSealedDelegationUnit(t *testing.T) { runReleaseUnit(t, "TestSealedDelegationNative", true) }

func (n *NaturalReleaseNative) GrantCascadeStop(raw json.RawMessage) (api.ProcessObservation, error) {
	var request api.HelperStopRequest
	if err := decodeStrict(raw, &request); err != nil {
		return api.ProcessObservation{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return n.m.stopGate(ctx, request)
}
