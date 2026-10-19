package approval

import "laneboss.io/laneboss/internal/v2/api"

// Result validators bind the frozen typed response to the caller's request.
// They check references and receipt metadata; they do not attest publication,
// verify human assertions or replace the service's atomic authority checks.
func ValidateProposeResult(request api.ChangeProposeRequest, result api.ChangeRequest) error {
	if err := ValidatePropose(request); err != nil {
		return err
	}
	if err := ValidateChange(result); err != nil {
		return err
	}
	if result.OrgID != request.OrgID || result.BaseGeneration != request.BaseGeneration || result.Status != "proposed" {
		return resultMismatch()
	}
	if result.Reason != request.Reason {
		return resultMismatch()
	}
	expected := result
	expected.Files = request.Files
	digest, err := ManifestDigest(expected)
	if err != nil || digest != result.ManifestSHA256 {
		return resultMismatch()
	}
	return nil
}

func ValidateGetResult(request api.ChangeGetRequest, result api.ChangeRequest) error {
	if err := ValidateGet(request); err != nil {
		return err
	}
	if err := ValidateChange(result); err != nil {
		return err
	}
	if result.ID != request.ChangeID {
		return resultMismatch()
	}
	return nil
}

func ValidateApproveResult(request api.ChangeApproveRequest, result api.ChangeApproval) error {
	if err := ValidateApprove(request); err != nil {
		return err
	}
	if err := ValidateApproval(result); err != nil {
		return err
	}
	if result.ChangeID != request.ChangeID || result.ManifestSHA256 != request.ManifestSHA256 ||
		result.BaseGeneration != request.BaseGeneration {
		return resultMismatch()
	}
	return nil
}

func ValidateApplyResult(request api.ChangeApplyRequest, result api.ChangeReceipt) error {
	if err := ValidateApply(request); err != nil {
		return err
	}
	if err := ValidateReceipt(result); err != nil {
		return err
	}
	if result.ChangeID != request.ChangeID || result.ApprovalID != request.ApprovalID ||
		result.OldGeneration != request.ExpectedGeneration {
		return resultMismatch()
	}
	return nil
}

// ValidateProofRef checks only canonical shape and intent binding. Expiry at the
// current clock and nonce consumption belong after authorized durable replay
// in the service transaction; the client must not invalidate completed replay.
func ValidateProofRef(proof api.ProofRef, intent api.Digest) error {
	if !validID(proof.ID) || !validDigest(intent) || !validDigest(proof.RequestSHA256) || proof.RequestSHA256 != intent {
		return invalid("proof reference is invalid or covers another exact request")
	}
	if _, err := timestamp(proof.ExpiresAt); err != nil {
		return invalid("proof reference expiry is not canonical UTC")
	}
	return nil
}

func resultMismatch() *api.Error {
	return integrity("approval response does not match its exact request")
}
