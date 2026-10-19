package approval

import (
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestApprovalPresenceFromVerifiedProof(t *testing.T) {
	for _, simulated := range []bool{false, true} {
		f := readyFixture(t)
		request := api.ChangeApproveRequest{ChangeID: f.store.change.ID, ManifestSHA256: f.store.change.ManifestSHA256, BaseGeneration: 7}
		scope := f.bound("org.change.approve", request, true)
		scope.Request.Proof.SimulatedPresence = simulated
		target := api.HumanChallengeRequest{Method: scope.Request.Method, TargetID: request.ChangeID, RequestSHA256: scope.Request.RequestSHA256, BaseGeneration: 7}
		facts, err := f.human.check(scope, *scope.Request.Proof, target)
		if err != nil {
			t.Fatal(err)
		}
		facts.SimulatedPresence = simulated
		approved, err := approvalFromProof(f.service.deps.Clock.Now(), scope, "presence-operation", f.store.change, facts)
		t.Run(map[bool]string{false: "physical", true: "simulated"}[simulated], func(t *testing.T) {
			if err != nil || approved.SimulatedPresence != simulated {
				t.Fatalf("approval lost verified presence: want %t, got %t, error %v", simulated, approved.SimulatedPresence, err)
			}
		})
		facts.SimulatedPresence = !simulated
		t.Run(map[bool]string{false: "false_reference", true: "true_reference"}[simulated], func(t *testing.T) {
			if _, err := approvalFromProof(f.service.deps.Clock.Now(), scope, "presence-operation", f.store.change, facts); err == nil {
				t.Fatal("approval accepted inconsistent verified proof/reference presence")
			}
		})
	}
}
