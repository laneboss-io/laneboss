package claudock

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	linux "laneboss.io/laneboss/internal/v2/isolation/linux"
)

// Prepare reaches the missing handoff port only after the real Linux spec
// validator accepts the actual adapter output. No process is launched.
func TestLinuxPlan(t *testing.T) {
	f := runnerReady(t, nil)
	plan, err := f.service.Start(context.Background(), f.request)
	if err != nil {
		t.Fatal(err)
	}
	end := api.Timestamp(time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano))
	plan.Slot.ExpiresAt = end
	runtime := api.BlobRef{ID: "runtime", Class: "manifest", Bytes: 1, SHA256: contentDigest([]byte("runtime"))}
	grants := api.GrantSet{ID: "grants", LifeID: plan.Home.ID, Generation: 1, PolicyGeneration: 1,
		SHA256: contentDigest([]byte("grants")), ExpiresAt: end,
		Profiles: []api.ProfileGrant{{ID: plan.Slot.ProfileGrantID, ProfileID: plan.Slot.ProfileID,
			Driver: plan.Driver, ExpiresAt: end}}}
	spec := api.LaunchSpec{ID: "spec", LaunchID: "launch", PlanID: "plan", Kind: "agent",
		Target: api.LifeRef{LifeID: grants.LifeID, Run: 1}, UIDLeaseID: "lease", EndpointGeneration: 1,
		PolicyGeneration: 1, Backend: "linux-bwrap-landlock", RuntimeManifest: runtime, Runner: &plan,
		Workspace:       api.Workspace{ID: plan.Home.WorkspaceID, LogicalCWD: plan.CWD},
		Materialization: api.Materialization{GrantSetID: grants.ID, Manifest: runtime}, Grants: grants, Budget: f.request.Budget}
	spec.Injection = api.Injection{Target: spec.Target, Outcome: "prepared", SlotIDs: []api.ID{plan.Slot.ID}}
	launcher, err := linux.New(linux.Dependencies{Helper: &struct{ api.HelperControl }{}, RuntimeManifest: runtime})
	if err != nil {
		t.Fatal(err)
	}
	_, err = launcher.Prepare(context.Background(), spec)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeNotImplemented || typed.Owner != "lb-v2-integrate" ||
		!strings.Contains(typed.Message, "ControlSource") {
		t.Fatal("adapter plan failed Linux validation", err)
	}
}
