package codex

import "laneboss.io/laneboss/internal/v2/api"

// CredentialValidator implements the secrets broker's narrow installed port.
// NewCredential remains the only schema/account validator; no vendor rules
// are copied into the broker or another package.
type CredentialValidator struct{}

func (CredentialValidator) ValidateCodexCredential(profile, canonicalLogin api.ID, enrolledAccount api.Digest, data []byte) error {
	credential, err := NewCredential(profile, canonicalLogin, enrolledAccount, data)
	clear(credential.payload)
	return err
}
