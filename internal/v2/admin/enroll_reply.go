package admin

import "laneboss.io/laneboss/internal/v2/api"

// The native helper has already authenticated the service and envelope. The
// typed completion must still match the exact request and retained evidence.
func validateCompleteReceipt(config string, request api.EnrollmentValidationRequest, receipt api.EnrollmentReceipt) error {
	if receipt.Config != config || receipt.CeremonyID != request.Ceremony.CeremonyID || receipt.PrincipalID != request.Ceremony.PrincipalID || receipt.Generation != 1 ||
		!validID(receipt.EventID) || !validID(receipt.OperationID) || receipt.CommittedSeq == 0 {
		return failure(api.CodeIntegrity, "administrator complete reply lost its committed ceremony")
	}
	if !validID(request.ChallengeID) || receipt.ChallengeID != request.ChallengeID {
		return failure(api.CodeIntegrity, "administrator complete reply changed its registration challenge")
	}
	if !validID(receipt.Evidence.ID) || receipt.Evidence.Class != "artifact" || !validDigest(receipt.Evidence.SHA256) || receipt.Evidence.Bytes < 1 || receipt.Evidence.Bytes > api.MaxFrameBytes {
		return failure(api.CodeIntegrity, "administrator complete reply lacks its retained evidence pin")
	}
	return nil
}
