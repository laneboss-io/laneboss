package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/url"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// VerifyAssertion verifies a WebAuthn get assertion against an immutable,
// service-held challenge and an administrator-enrolled PKIX public key.
// The key and previous counter MUST come from protected enrollment state, never
// from the request. The returned counter must be committed with challenge use.
// This pure check does not issue authority or prove hardware-backed enrollment.
// Service.Confirm resolves the enrolled key and commits challenge/counter/proof
// writes atomically; calling this function alone cannot mint a ProofRef.
func VerifyAssertion(challenge api.HumanChallenge, credentialID api.ID,
	publicKeyDER []byte, previousCounter uint32, request api.HumanConfirmRequest,
	now time.Time) (uint32, error) {
	if err := validateConfirmation(request); err != nil {
		return 0, err
	}
	if !validID(credentialID) || request.CredentialID != credentialID ||
		challenge.ID != request.ChallengeID || challenge.Config == "" ||
		len(challenge.Challenge) < 32 || len(challenge.Challenge) > 128 {
		return 0, refusal(api.CodeUnauthenticated, "assertion does not match the issued challenge")
	}
	intent := api.HumanChallengeRequest{Method: challenge.Method, TargetID: challenge.TargetID,
		RequestSHA256: challenge.RequestSHA256, BaseGeneration: challenge.BaseGeneration}
	if err := validateIntent(intent); err != nil {
		return 0, err
	}
	expiry, err := utcTime(challenge.ExpiresAt)
	if err != nil || !now.Before(expiry) || expiry.After(now.Add(120*time.Second)) {
		return 0, refusal(api.CodeUnauthenticated, "human challenge is expired or exceeds its lifetime")
	}
	if err := originPolicy(challenge.Origin, challenge.RPID); err != nil {
		return 0, err
	}
	client, err := decodeClientData(request.ClientDataJSON)
	if err != nil {
		return 0, err
	}
	encoded := base64.RawURLEncoding.EncodeToString(challenge.Challenge)
	if client.Type != "webauthn.get" || client.CrossOrigin ||
		client.TopOrigin != nil ||
		client.Origin != challenge.Origin ||
		subtle.ConstantTimeCompare([]byte(client.Challenge), []byte(encoded)) != 1 {
		return 0, refusal(api.CodeUnauthenticated, "wrong authenticator ceremony, origin or challenge")
	}
	data := request.AuthenticatorData
	rpHash := sha256.Sum256([]byte(challenge.RPID))
	if subtle.ConstantTimeCompare(data[:32], rpHash[:]) != 1 {
		return 0, refusal(api.CodeUnauthenticated, "authenticator RP ID does not match enrollment")
	}
	flags := data[32]
	// UP and UV are both mandatory. AT is invalid in a get assertion; reserved
	// bits cannot introduce a new meaning silently. BS requires BE.
	if flags&0x05 != 0x05 || flags&0x62 != 0 || (flags&0x10 != 0 && flags&0x08 == 0) {
		return 0, refusal(api.CodeUnauthenticated, "authenticator presence or verification is absent")
	}
	// Extensions need a versioned CBOR/extension contract. Do not silently
	// ignore bytes that might alter the approved credential's semantics.
	if flags&0x80 != 0 {
		return 0, refusal(api.CodeUnsupported, "authenticator extensions are not supported")
	}
	if len(data) != 37 {
		return 0, refusal(api.CodeInvalid, "unexpected authenticator data suffix")
	}
	counter := binary.BigEndian.Uint32(data[33:37])
	if (counter != 0 || previousCounter != 0) && counter <= previousCounter {
		return 0, refusal(api.CodeUnauthenticated, "authenticator counter did not advance")
	}
	if len(publicKeyDER) == 0 || len(publicKeyDER) > 8192 {
		return 0, refusal(api.CodeIntegrity, "enrolled public key is invalid")
	}
	key, err := x509.ParsePKIXPublicKey(publicKeyDER)
	if err != nil {
		return 0, refusal(api.CodeIntegrity, "enrolled public key cannot be parsed")
	}
	clientHash := sha256.Sum256(request.ClientDataJSON)
	signed := make([]byte, 0, len(data)+len(clientHash))
	signed = append(signed, data...)
	signed = append(signed, clientHash[:]...)
	hash := sha256.Sum256(signed)
	valid := false
	switch key := key.(type) {
	case *ecdsa.PublicKey:
		if key.Curve != elliptic.P256() {
			return 0, refusal(api.CodeUnsupported, "enrolled EC algorithm is not supported")
		}
		valid = ecdsa.VerifyASN1(key, hash[:], request.Signature)
	case *rsa.PublicKey:
		if key.N.BitLen() < 2048 || key.E < 65537 {
			return 0, refusal(api.CodeIntegrity, "enrolled RSA key is too weak")
		}
		valid = rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], request.Signature) == nil
	case ed25519.PublicKey:
		valid = ed25519.Verify(key, signed, request.Signature)
	default:
		return 0, refusal(api.CodeUnsupported, "enrolled signature algorithm is not supported")
	}
	if !valid {
		return 0, refusal(api.CodeUnauthenticated, "authenticator signature is invalid")
	}
	return counter, nil
}

type collectedClientData struct {
	Type        string  `json:"type"`
	Challenge   string  `json:"challenge"`
	Origin      string  `json:"origin"`
	CrossOrigin bool    `json:"crossOrigin,omitempty"`
	TopOrigin   *string `json:"topOrigin,omitempty"`
}

// WebAuthn permits future client-data members. Validate the complete original
// JSON for duplicates/encoding first, then strictly decode only the known
// ceremony fields. Signature verification still hashes the original bytes,
// including every unknown member; this projection is never signed evidence.
func decodeClientData(raw []byte) (collectedClientData, error) {
	var client collectedClientData
	if _, err := api.CanonicalJSON(raw); err != nil {
		return client, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return client, refusal(api.CodeInvalid, "WebAuthn client data must be an object")
	}
	known := make(map[string]json.RawMessage)
	for _, name := range []string{"type", "challenge", "origin", "crossOrigin", "topOrigin"} {
		if value, exists := fields[name]; exists {
			known[name] = value
		}
	}
	encoded, err := json.Marshal(known)
	if err != nil {
		return client, refusal(api.CodeInvalid, "invalid WebAuthn client data")
	}
	if err := strictObject(encoded, &client); err != nil {
		return client, err
	}
	return client, nil
}

func originPolicy(origin, rpID string) error {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.User != nil || parsed.Host == "" ||
		parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.Opaque != "" || parsed.ForceQuery || parsed.Hostname() == "" ||
		rpID == "" || strings.ToLower(rpID) != rpID || strings.ContainsAny(rpID, "/:\\ \t\r\n") {
		return refusal(api.CodeIntegrity, "enrolled origin or RP ID is invalid")
	}
	host := parsed.Hostname()
	if host != rpID && !strings.HasSuffix(host, "."+rpID) {
		return refusal(api.CodeIntegrity, "enrolled RP ID does not match the origin")
	}
	if parsed.Scheme != "https" {
		ip := net.ParseIP(host)
		if parsed.Scheme != "http" || (host != "localhost" && (ip == nil || !ip.IsLoopback())) {
			return refusal(api.CodeIntegrity, "enrolled origin must be a secure context")
		}
	}
	return nil
}
