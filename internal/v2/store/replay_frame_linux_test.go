//go:build linux

package store

import (
	"context"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// This exercises the post-native replay continuation, never a mocked peer
// verifier or a claim of root-helper acceptance. Receipt/validation rows are
// actual SQLite projections; changed frames leave that successful setup intact.
func TestEnrollmentReplayFrame(t *testing.T) {
	s, _ := testStore(t)
	endpoint := api.AdminEnrollmentEndpoint{Config: s.deps.Config, Socket: "/runtime/enroll.sock", ServiceUID: 1000,
		InstallationGeneration: 1, Origin: "https://enroll.invalid", RPID: "enroll.invalid",
		Helper: api.Executable{ID: testID(t), Version: "fixture-v1", SHA256: testDigest([]byte(testID(t)))}}
	s.deps.Enrollment = &endpoint
	request := api.EnrollmentValidationRequest{Ceremony: api.EnrollmentCeremonyRequest{Config: endpoint.Config, CeremonyID: testID(t), PrincipalID: testID(t)},
		ChallengeID: testID(t), ClientDataJSON: []byte("retained client data"), AttestationObject: []byte("retained attestation")}
	operation := testID(t)
	receipt := api.EnrollmentReceipt{CeremonyID: request.Ceremony.CeremonyID, ChallengeID: request.ChallengeID,
		PrincipalID: request.Ceremony.PrincipalID, Config: endpoint.Config, Generation: 1, OperationID: operation}
	fixtureProjection(t, s, "enrollment_receipt", receipt.CeremonyID, 1, receipt)
	fixtureProjection(t, s, "enrollment_validation", operation, 1, enrollmentValidation{Request: request})
	frame := api.AdminEnrollmentFrame{Protocol: api.AdminEnrollmentProtocol, Revision: api.ContractRevision, Config: endpoint.Config,
		Generation: endpoint.InstallationGeneration, ArtifactSHA256: endpoint.Helper.SHA256, Nonce: testID(t), Method: "enroll_complete", Params: enrollmentJSON(t, request)}
	actual, err := s.replayEnrollment(context.Background(), enrollmentJSON(t, frame), request)
	if err != nil || !reflect.DeepEqual(actual, receipt) {
		t.Fatal("matching replay frame lost its retained receipt", err)
	}
	for _, mode := range []string{"params", "method", "config", "generation", "old_frame"} {
		t.Run(mode, func(t *testing.T) {
			changed := frame
			switch mode {
			case "params":
				other := request
				other.ClientDataJSON = []byte("different client data")
				changed.Params = enrollmentJSON(t, other)
			case "method":
				changed.Method = "enroll_begin"
			case "config":
				changed.Config += "-changed"
			case "generation":
				changed.Generation++
			}
			raw := enrollmentJSON(t, changed)
			if mode == "old_frame" {
				raw = []byte(`{"action":"complete","request":{}}`)
			}
			if _, err := s.replayEnrollment(context.Background(), raw, request); err == nil {
				t.Fatal("replay accepted an unrelated administrator frame", mode)
			}
			var retained api.EnrollmentReceipt
			if err := storedProjection(context.Background(), s.db, "enrollment_receipt", receipt.CeremonyID, &retained); err != nil || !reflect.DeepEqual(retained, receipt) {
				t.Fatal("replay refusal changed its retained receipt", err)
			}
		})
	}
}
