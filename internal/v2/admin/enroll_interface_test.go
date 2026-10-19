package admin

import (
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestDirectEnrollment(t *testing.T) {
	v, identity, store, ctx, endpoint := initialEnrollmentFixture(t)
	var port api.EnrollmentValidator = v
	install, err := port.ValidateEnrollment(ctx, identity.request)
	if err != nil || identity.validateCalls != 1 {
		t.Fatalf("direct identity validation was not reached: %v", err)
	}
	if err := CheckInitialEnrollmentInstall(ctx, endpoint, install, store.evidence); err != nil {
		t.Fatalf("acceptance: interface validation omitted its native handoff: %v", err)
	}
	retained := copyEnrollmentInstall(install)
	install.Enrollment.Credentials[0].PublicKeyDER[0] ^= 1
	identity.install.Enrollment.Credentials[0].PublicKeyDER[0] ^= 1
	identity.request.ClientDataJSON[0] ^= 1
	if err := CheckInitialEnrollmentInstall(ctx, endpoint, retained, store.evidence); err != nil {
		t.Fatalf("interface handoff retained aliased input or output bytes: %v", err)
	}
}

func TestDirectInventory(t *testing.T) {
	v, identity, _, ctx, _ := initialEnrollmentFixture(t)
	identity.install.Enrollment.Config = "foreign-config"
	want := api.ValidateHumanEnrollments(v.endpoint.Config, []api.HumanEnrollment{identity.install.Enrollment})
	if want == nil {
		t.Fatal("invalid produced inventory fixture was accepted")
	}
	var port api.EnrollmentValidator = v
	_, err := port.ValidateEnrollment(ctx, identity.request)
	channel := ctx.Value(enrollmentChannelKey{}).(*enrollmentChannel)
	if !reflect.DeepEqual(err, want) || identity.validateCalls != 1 || channel.validated != nil {
		t.Fatal("acceptance: produced enrollment inventory refusal was not preserved")
	}
}

func TestCompleteReply(t *testing.T) {
	for _, fault := range []string{"challenge", "evidence"} {
		t.Run(fault, func(t *testing.T) {
			_, identity, _, _, endpoint := initialEnrollmentFixture(t)
			r := api.EnrollmentReceipt{Config: endpoint.Config, CeremonyID: identity.request.Ceremony.CeremonyID,
				PrincipalID: identity.request.Ceremony.PrincipalID, ChallengeID: identity.request.ChallengeID, Generation: 1,
				Evidence: identity.install.CeremonyEvidence, OperationID: "operation", EventID: "event", CommittedSeq: 1}
			if err := validateCompleteReceipt(endpoint.Config, identity.request, r); err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "challenge":
				r.ChallengeID = "foreign-challenge"
			case "evidence":
				r.Evidence.SHA256 = "invalid-digest"
			}
			if err := validateCompleteReceipt(endpoint.Config, identity.request, r); err == nil {
				t.Fatal("acceptance: complete reply lost its request or evidence binding")
			}
		})
	}
}
