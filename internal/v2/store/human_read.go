package store

import (
	"crypto/ed25519"
	"crypto/x509"

	"laneboss.io/laneboss/internal/v2/api"
)

// Compatibility belongs to typed retained-state reads, never to new writes
// or public request decoding. Only an actual Ed25519 key may use this alias.
// The original retained bytes and all key/presence/generation facts stay intact.
func normalizeEnrollmentRead(out any) error {
	var enrollment *api.HumanEnrollment
	switch value := out.(type) {
	case *api.HumanEnrollment:
		enrollment = value
	case *api.EnrollmentInstall:
		enrollment = &value.Enrollment
	case *enrollmentValidation:
		enrollment = &value.Install.Enrollment
	default:
		return nil
	}
	for i := range enrollment.Credentials {
		credential := &enrollment.Credentials[i]
		if credential.Algorithm != "Ed25519" {
			continue
		}
		parsed, err := x509.ParsePKIXPublicKey(credential.PublicKeyDER)
		key, ok := parsed.(ed25519.PublicKey)
		if err != nil || !ok || len(key) != ed25519.PublicKeySize {
			return fault(api.CodeIntegrity, "legacy Ed25519 label differs from its retained public key")
		}
		credential.Algorithm = "EdDSA"
	}
	return nil
}
