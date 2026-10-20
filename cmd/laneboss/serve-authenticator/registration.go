//go:build laneboss_e2e_authenticator

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// WebAuthn packed self-attestation signs authData || SHA256(clientDataJSON).
// This is a real signature under the newly created credential key. The shared
// AAGUID/marker declare software presence; they never claim trusted hardware.
func registrationData(key *ecdsa.PrivateKey, public descriptor, nonce []byte) ([]byte, []byte, []byte, error) {
	client, err := json.Marshal(map[string]any{"type": "webauthn.create", "challenge": base64.RawURLEncoding.EncodeToString(nonce),
		"origin": public.Origin, "crossOrigin": false})
	if err != nil {
		return nil, nil, nil, err
	}
	aaguid, err := hex.DecodeString(strings.ReplaceAll(api.SoftwareAuthenticatorAAGUID, "-", ""))
	if err != nil || len(aaguid) != 16 || len(public.RawCredentialID) > 65535 {
		return nil, nil, nil, errors.New("registration identity invalid")
	}
	rp := sha256.Sum256([]byte(public.RPID))
	auth := append([]byte{}, rp[:]...)
	auth = append(auth, 0x45, 0, 0, 0, 0) // UP, UV, attested credential data; initial counter zero.
	auth = append(auth, aaguid...)
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(public.RawCredentialID)))
	auth = append(auth, length...)
	auth = append(auth, public.RawCredentialID...)
	x, y := key.PublicKey.X.FillBytes(make([]byte, 32)), key.PublicKey.Y.FillBytes(make([]byte, 32))
	// COSE EC2/P-256/ES256 public key; integer keys in canonical CBOR order.
	keyData := []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21}
	keyData = append(keyData, cborBytes(x)...)
	keyData = append(keyData, 0x22)
	keyData = append(keyData, cborBytes(y)...)
	auth = append(auth, keyData...)
	clientHash := sha256.Sum256(client)
	signed := append(append([]byte{}, auth...), clientHash[:]...)
	hash := sha256.Sum256(signed)
	signature, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
	return client, auth, signature, err
}

func cborHead(major byte, length int) []byte {
	if length < 24 {
		return []byte{major<<5 | byte(length)}
	}
	if length <= 255 {
		return []byte{major<<5 | 24, byte(length)}
	}
	if length <= 65535 {
		return []byte{major<<5 | 25, byte(length >> 8), byte(length)}
	}
	return []byte{major<<5 | 26, byte(length >> 24), byte(length >> 16), byte(length >> 8), byte(length)}
}
func cborBytes(data []byte) []byte { return append(cborHead(2, len(data)), data...) }
func cborText(data string) []byte  { return append(cborHead(3, len(data)), []byte(data)...) }

func register(root *os.Root, config string, raw []byte, now time.Time) (api.EnrollmentValidationRequest, error) {
	var result api.EnrollmentValidationRequest
	var challenge api.EnrollmentChallenge
	if api.DecodeObject(raw, &challenge) != nil || challenge.Ceremony.Config != config || challenge.Ceremony.ExpectedGeneration != 0 {
		return result, errors.New("registration challenge differs from empty-baseline request")
	}
	if err := api.ValidateEnrollmentChallenge(challenge, challenge.Ceremony, now); err != nil {
		return result, err
	}
	data, err := readPrivate(root, "public.json")
	if err != nil {
		return result, err
	}
	var public descriptor
	if api.DecodeObject(data, &public) != nil || public.Config != config || public.PrincipalID != challenge.Ceremony.PrincipalID ||
		public.Origin != challenge.Origin || public.RPID != challenge.RPID || public.AAGUID != api.SoftwareAuthenticatorAAGUID ||
		public.Attestation != api.SoftwareAuthenticatorAttestationMarker || public.Enrolled || public.Presence != "simulated" {
		return result, errors.New("registration challenge differs from private device")
	}
	wantID := api.SoftwareAuthenticatorCredentialID
	if challenge.InviteID != "" {
		wantID = api.InvitedCredentialID(public.RawCredentialID)
	}
	if public.CredentialID != wantID {
		return result, errors.New("registration credential differs from invitation mode")
	}
	private, err := readPrivate(root, "key.der")
	if err != nil {
		return result, err
	}
	defer clear(private)
	parsed, err := x509.ParsePKCS8PrivateKey(private)
	if err != nil {
		return result, errors.New("registration private key invalid")
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return result, errors.New("registration algorithm differs")
	}
	actual, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil || !bytes.Equal(actual, public.PublicKeyDER) {
		return result, errors.New("registration public key pin differs")
	}
	client, auth, signature, err := registrationData(key, public, challenge.Challenge)
	if err != nil {
		return result, errors.New("registration signing failed")
	}
	// packed attestation with alg=-7 and the genuine self-attestation signature.
	statement := append([]byte{0xa2}, cborText("alg")...)
	statement = append(statement, 0x26)
	statement = append(statement, cborText("sig")...)
	statement = append(statement, cborBytes(signature)...)
	object := append([]byte{0xa3}, cborText("fmt")...)
	object = append(object, cborText("packed")...)
	object = append(object, cborText("attStmt")...)
	object = append(object, statement...)
	object = append(object, cborText("authData")...)
	object = append(object, cborBytes(auth)...)
	return api.EnrollmentValidationRequest{Ceremony: challenge.Ceremony, ChallengeID: challenge.ID,
		ClientDataJSON: client, AttestationObject: object, AttestationMarker: api.SoftwareAuthenticatorAttestationMarker}, nil
}
