package store

import (
	"encoding/json"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestEnrollmentFrameBinding(t *testing.T) {
	e := api.AdminEnrollmentEndpoint{Config: "frame-case", Socket: "/runtime/enroll.sock", ServiceUID: 1000, InstallationGeneration: 1,
		Origin: "https://enroll.invalid", RPID: "enroll.invalid", Helper: api.Executable{ID: "helper", Version: "fixture-v1", SHA256: api.Digest(strings.Repeat("a", 64))}}
	request := api.EnrollmentValidationRequest{Ceremony: api.EnrollmentCeremonyRequest{Config: e.Config, CeremonyID: "ceremony", PrincipalID: "principal"},
		ChallengeID: "challenge", ClientDataJSON: []byte("component client data"), AttestationObject: []byte("component attestation")}
	params, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	frame := api.AdminEnrollmentFrame{Protocol: api.AdminEnrollmentProtocol, Revision: api.ContractRevision, Config: e.Config,
		Generation: e.InstallationGeneration, ArtifactSHA256: e.Helper.SHA256, Nonce: api.ID(strings.Repeat("b", 32)), Method: "enroll_complete", Params: params}
	raw, err := json.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkEnrollmentFrame(raw, e, request); err != nil {
		t.Fatal("complete enrollment frame was refused", err)
	}
	for _, mode := range []string{"params", "method", "generation", "old_frame"} {
		t.Run(mode, func(t *testing.T) {
			changed, expected := frame, request
			switch mode {
			case "params":
				expected.ClientDataJSON = []byte("different client data")
			case "method":
				changed.Method = "enroll_begin"
			case "generation":
				changed.Generation++
			}
			data, err := json.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "old_frame" {
				data = []byte(`{"action":"complete","request":{}}`)
			}
			if err := checkEnrollmentFrame(data, e, expected); err == nil {
				t.Fatal("enrollment retained a foreign frame", mode)
			}
		})
	}
}
