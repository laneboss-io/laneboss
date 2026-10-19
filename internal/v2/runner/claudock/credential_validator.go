package claudock

// CredentialValidator implements the secrets broker's narrow installed port.
// NewCredential remains the only headless-token validator.
type CredentialValidator struct{}

func (CredentialValidator) ValidateHeadlessCredential(profile, canonicalLogin string, token []byte) error {
	credential, err := NewCredential(profile, canonicalLogin, token)
	clear(credential.token)
	return err
}
