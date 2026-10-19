package identity

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"regexp"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
)

// AttestationPolicy is supplied only by the protected installation/composition
// root. It is not an enrollment parameter, environment override or downloaded
// trust list. No roots means production enrollment is closed. An optional
// AAGUID allowlist narrows certificate trust; an AAGUID alone proves no hardware.
type AttestationPolicy struct {
	Config                 string
	InstallationGeneration api.Generation
	RootsDER               [][]byte
	AllowedAAGUIDs         []string
}

type attestationTrust struct {
	config       string
	installation api.Generation
	roots        *x509.CertPool
	allow        map[string]bool
}

var attestationAAGUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var attestationAAGUIDOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}

func cloneAttestationPolicy(policy AttestationPolicy) AttestationPolicy {
	result := policy
	result.RootsDER = make([][]byte, len(policy.RootsDER))
	for i, der := range policy.RootsDER {
		result.RootsDER[i] = append([]byte(nil), der...)
	}
	result.AllowedAAGUIDs = append([]string(nil), policy.AllowedAAGUIDs...)
	return result
}

func freezeAttestation(policy AttestationPolicy) (attestationTrust, error) {
	var empty attestationTrust
	if policy.Config == "" && policy.InstallationGeneration == 0 && len(policy.RootsDER) == 0 && len(policy.AllowedAAGUIDs) == 0 {
		return empty, nil
	}
	if !enrollmentConfigName.MatchString(policy.Config) || policy.InstallationGeneration == 0 || policy.InstallationGeneration >= 1<<53 ||
		len(policy.RootsDER) > 32 || len(policy.AllowedAAGUIDs) > 256 {
		return empty, refusal(api.CodeInvalid, "invalid installed attestation policy")
	}
	trust := attestationTrust{config: policy.Config, installation: policy.InstallationGeneration,
		roots: x509.NewCertPool(), allow: make(map[string]bool)}
	for _, der := range policy.RootsDER {
		if len(der) == 0 || len(der) > 65536 {
			return empty, refusal(api.CodeInvalid, "invalid pinned attestation root")
		}
		certificate, err := x509.ParseCertificate(append([]byte(nil), der...))
		if err != nil || !certificate.IsCA || !certificate.BasicConstraintsValid || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return empty, refusal(api.CodeInvalid, "attestation root is not a pinned certificate authority")
		}
		trust.roots.AddCert(certificate)
	}
	for _, name := range policy.AllowedAAGUIDs {
		if !attestationAAGUID.MatchString(name) || trust.allow[name] {
			return empty, refusal(api.CodeInvalid, "invalid or duplicate pinned attestation AAGUID")
		}
		trust.allow[name] = true
	}
	return trust, nil
}

func (s *Service) verifyAttestation(challenge api.EnrollmentChallenge, credential api.HumanCredential, statement map[any]any, auth, client []byte, key any) error {
	format := credential.AttestationFormat
	if format == "none" {
		if len(statement) == 0 && credential.SimulatedPresence {
			return api.ValidateCredentialPresence(credential)
		}
		return refusal(api.CodeForbidden, "certificate-backed direct attestation is required")
	}
	clientHash := sha256.Sum256(client)
	switch format {
	case "packed":
		signature, sigOK := statement["sig"].([]byte)
		if !sigOK || len(signature) == 0 || len(signature) > 8192 {
			return registrationInvalid()
		}
		alg, ok := statement["alg"].(int64)
		if !ok {
			return registrationInvalid()
		}
		signed := append(append([]byte(nil), auth...), clientHash[:]...)
		if _, hasChain := statement["x5c"]; !hasChain && len(statement) == 2 && credential.SimulatedPresence {
			if err := api.ValidateCredentialPresence(credential); err != nil {
				return err
			}
			if !(credential.Algorithm == "ES256" && alg == -7 || credential.Algorithm == "RS256" && alg == -257 || credential.Algorithm == "Ed25519" && alg == -8) {
				return registrationInvalid()
			}
			return verifyAttestationSignature(key, alg, signed, signature)
		}
		if len(statement) != 3 {
			return refusal(api.CodeForbidden, "packed attestation requires a trusted certificate chain")
		}
		leaf, err := s.attestationLeaf(challenge, credential, statement["x5c"], false)
		if err != nil {
			return err
		}
		if !packedCertificate(leaf) {
			return refusal(api.CodeUnauthenticated, "packed attestation certificate subject or constraints differ")
		}
		return verifyAttestationSignature(leaf.PublicKey, alg, signed, signature)
	case "fido-u2f":
		signature, sigOK := statement["sig"].([]byte)
		if !sigOK || len(signature) == 0 || len(signature) > 8192 {
			return registrationInvalid()
		}
		if len(statement) != 2 || credential.AAGUID != "00000000-0000-0000-0000-000000000000" {
			return registrationInvalid()
		}
		public, ok := key.(*ecdsa.PublicKey)
		if !ok || public.Curve != elliptic.P256() {
			return registrationInvalid()
		}
		leaf, err := s.attestationLeaf(challenge, credential, statement["x5c"], true)
		if err != nil {
			return err
		}
		attester, ok := leaf.PublicKey.(*ecdsa.PublicKey)
		if !ok || attester.Curve != elliptic.P256() {
			return registrationInvalid()
		}
		signed := append([]byte{0}, auth[:32]...)
		signed = append(signed, clientHash[:]...)
		signed = append(signed, credential.RawCredentialID...)
		signed = append(signed, elliptic.Marshal(elliptic.P256(), public.X, public.Y)...)
		return verifyAttestationSignature(attester, -7, signed, signature)
	default:
		return refusal(api.CodeUnsupported, "registration attestation format is unsupported")
	}
}

func packedCertificate(leaf *x509.Certificate) bool {
	if leaf.Version != 3 || !leaf.BasicConstraintsValid || leaf.IsCA ||
		len(leaf.Subject.Country) != 1 || len(leaf.Subject.Country[0]) != 2 || len(leaf.Subject.Organization) == 0 ||
		len(leaf.Subject.OrganizationalUnit) != 1 {
		return false
	}
	country := leaf.Subject.Country[0]
	return country[0] >= 'A' && country[0] <= 'Z' && country[1] >= 'A' && country[1] <= 'Z' &&
		strings.TrimSpace(leaf.Subject.Organization[0]) != "" && leaf.Subject.OrganizationalUnit[0] == "Authenticator Attestation" &&
		strings.TrimSpace(leaf.Subject.CommonName) != ""
}

func (s *Service) attestationLeaf(challenge api.EnrollmentChallenge, credential api.HumanCredential, value any, u2f bool) (*x509.Certificate, error) {
	chain, ok := value.([]any)
	if !ok || len(chain) == 0 || len(chain) > 8 || u2f && len(chain) != 1 {
		return nil, registrationInvalid()
	}
	if s.attestation.roots == nil || len(s.attestation.roots.Subjects()) == 0 || s.attestation.config != challenge.Ceremony.Config ||
		s.attestation.installation != challenge.InstallationGeneration {
		return nil, refusal(api.CodeForbidden, "installed attestation trust is unavailable or belongs to another installation")
	}
	if len(s.attestation.allow) > 0 && !s.attestation.allow[credential.AAGUID] {
		return nil, refusal(api.CodeForbidden, "authenticator AAGUID is not allowed by the installed policy")
	}
	certificates := make([]*x509.Certificate, 0, len(chain))
	intermediates := x509.NewCertPool()
	total := 0
	for i, item := range chain {
		der, ok := item.([]byte)
		total += len(der)
		if !ok || len(der) == 0 || len(der) > 65536 || total > 262144 {
			return nil, registrationInvalid()
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, registrationInvalid()
		}
		certificates = append(certificates, certificate)
		if i > 0 {
			intermediates.AddCert(certificate)
		}
	}
	leaf := certificates[0]
	if leaf.IsCA || leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, refusal(api.CodeUnauthenticated, "attestation certificate cannot sign an authenticator statement")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: s.attestation.roots, Intermediates: intermediates,
		CurrentTime: s.deps.Clock.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, refusal(api.CodeUnauthenticated, "attestation certificate chain is not trusted or current")
	}
	// WebAuthn 8.6 does not bind a U2F certificate's model AAGUID extension
	// to the all-zero AAGUID required in U2F authenticator data. Installed
	// roots, the optional data-AAGUID allowlist and the signature still apply.
	if u2f {
		return leaf, nil
	}
	seen := false
	for _, extension := range leaf.Extensions {
		if !extension.Id.Equal(attestationAAGUIDOID) {
			continue
		}
		var aaguid []byte
		rest, err := asn1.Unmarshal(extension.Value, &aaguid)
		if seen || extension.Critical || err != nil || len(rest) != 0 || len(aaguid) != 16 || !bytes.Equal(aaguid, credentialAAGUID(credential)) {
			return nil, refusal(api.CodeUnauthenticated, "attestation certificate AAGUID differs from authenticator data")
		}
		seen = true
	}
	return leaf, nil
}

func credentialAAGUID(credential api.HumanCredential) []byte {
	// The string was derived from the exact sixteen authenticator-data bytes.
	value, err := hex.DecodeString(strings.ReplaceAll(credential.AAGUID, "-", ""))
	if err != nil || len(value) != 16 {
		return nil
	}
	return value
}

func verifyAttestationSignature(key any, alg int64, signed, signature []byte) error {
	hash := sha256.Sum256(signed)
	valid := false
	switch public := key.(type) {
	case *ecdsa.PublicKey:
		valid = alg == -7 && public.Curve == elliptic.P256() && ecdsa.VerifyASN1(public, hash[:], signature)
	case *rsa.PublicKey:
		valid = alg == -257 && public.N.BitLen() >= 2048 && public.N.BitLen() <= 8192 && rsa.VerifyPKCS1v15(public, crypto.SHA256, hash[:], signature) == nil
	case ed25519.PublicKey:
		valid = alg == -8 && ed25519.Verify(public, signed, signature)
	}
	if !valid {
		return refusal(api.CodeUnauthenticated, "registration attestation signature is invalid")
	}
	return nil
}
