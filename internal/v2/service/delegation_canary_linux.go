//go:build linux && laneboss_root_canary && laneboss_gate_integration

package service

import (
	"context"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

func ExerciseSealedDelegationCanary(t *testing.T, exchange func(string, any, any) error) {
	exerciseNaturalReleaseCanary(t, exchange, false, true)
}

// The parent is the actual native process measured by the surrounding canary.
// The already-delegated lower child is an explicit real-store component fact;
// it executes no vendor code and receives no human-presence assertion.
func sealedCanaryChild(t *testing.T, parent *fx.Fixture) *fx.Fixture {
	t.Helper()
	f := *parent
	f.CaptureSetup = nil
	controller := parent.LaneScope(t)
	f.Ceiling = parent.Plan.Inputs.Grants
	f.Start.Lane, f.Start.Level, f.Start.Role, f.Start.RootTicketID = string(fx.ID(t)), 3, "executor", ""
	raw := []byte("prior child delegation before the measured native parent exit")
	var err error
	f.Start.Task, err = f.State.RetainObject(context.Background(), f.Execution, api.RetainObjectRequest{Intent: f.Intent(t, api.InternalObjectRetain), Object: api.ObjectWrite{
		ObjectKey: fx.ID(t), Class: "task", Bytes: raw, SHA256: fx.Digest(raw), Origin: "service", ACL: api.ObjectACL{Config: f.Deps.Config, Owner: controller.Actor, LifeID: controller.Actor.LifeID, Audience: "owner", Generation: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	f.Start.Grants.Data = append([]api.DataGrantRequest{}, parent.Start.Grants.Data...)
	f.Start.Grants.Profiles = append([]api.ProfileDelegation{}, parent.Start.Grants.Profiles...)
	f.Start.Grants.Data[0].ParentGrantID = f.Ceiling.Data[0].ID
	f.Start.Grants.Profiles[0].ParentGrantID = f.Ceiling.Profiles[0].ID
	f.Start.ProfileGrantID = f.Ceiling.Profiles[0].ID
	expires := api.Timestamp(time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339Nano))
	f.Start.Grants.Data[0].ExpiresAt, f.Start.Grants.Profiles[0].ExpiresAt = expires, expires
	f.Human = controller
	f.Admit(t, "lane.start", f.Start)
	f.Reserve(t)
	f.Source(t)
	f.BuildPlan(t, true)
	f.Spec(t)
	f.PreparedClaim = api.EffectLease{}
	f.Bind(t)
	f.Opened(t)
	if _, err := f.State.VerifyDelegationLease(context.Background(), f.Execution, parent.Lane.LifeID, f.Lane.GrantSetID); err == nil {
		t.Fatal("live native parent fabricated a post-exit lease")
	}
	return &f
}
