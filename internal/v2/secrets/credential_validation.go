package secrets

import "laneboss.io/laneboss/internal/v2/api"

// CodexCredentialValidator is an installed, outside-worker schema/account
// validator. The Codex runner implements it using its own credential parser;
// secrets must not import a runner or copy its vendor schema. This port does
// not authenticate a provider or enroll an account from the supplied bytes.
type CodexCredentialValidator interface {
	ValidateCodexCredential(profile, canonicalLogin api.ID, enrolledAccount api.Digest, data []byte) error
}

// HeadlessCredentialValidator validates only the selected headless token. Its
// distinct method prevents installing the Codex parser in the headless slot.
type HeadlessCredentialValidator interface {
	ValidateHeadlessCredential(profile, canonicalLogin string, token []byte) error
}

// APIKeyCredentialValidator validates the selected API key before any native
// projection. It does not authenticate the key with a provider.
type APIKeyCredentialValidator interface {
	ValidateAPIKeyCredential(profile, canonicalLogin string, key []byte) error
}
