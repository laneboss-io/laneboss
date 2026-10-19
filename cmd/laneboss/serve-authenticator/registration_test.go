//go:build laneboss_e2e_authenticator

package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestRegistrationSignature(t *testing.T) {
	root, input, public, _, _, now := keyFixture(t)
	private, err := readPrivate(root, "key.der")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	parsed, err := x509.ParsePKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	key := parsed.(*ecdsa.PrivateKey)
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	client, auth, signature, err := registrationData(key, public, nonce)
	if err != nil {
		t.Fatal(err)
	}
	clientHash := sha256.Sum256(client)
	digest := sha256.Sum256(append(append([]byte{}, auth...), clientHash[:]...))
	if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], signature) {
		t.Fatal("registration signature failed real ECDSA verification")
	}
	signature[0] ^= 1
	if ecdsa.VerifyASN1(&key.PublicKey, digest[:], signature) {
		t.Fatal("modified registration signature was accepted")
	}
	var decoded map[string]any
	if json.Unmarshal(client, &decoded) != nil || decoded["type"] != "webauthn.create" ||
		decoded["challenge"] != base64.RawURLEncoding.EncodeToString(nonce) || decoded["origin"] != public.Origin ||
		len(auth) < 55 || auth[32] != 0x45 {
		t.Fatal("registration did not bind nonce, origin and attested flags")
	}
	challenge := api.EnrollmentChallenge{ID: "challenge", Ceremony: api.EnrollmentCeremonyRequest{Config: input.Config,
		CeremonyID: "ceremony", PrincipalID: public.PrincipalID}, Challenge: nonce, Origin: public.Origin, RPID: public.RPID,
		EndpointGeneration: 1, InstallationGeneration: 1, ExpiresAt: api.Timestamp(now.Add(time.Minute).Format(time.RFC3339Nano))}
	raw, err := json.Marshal(challenge)
	if err != nil {
		t.Fatal(err)
	}
	request, err := register(root, input.Config, raw, now)
	if err != nil || request.Ceremony != challenge.Ceremony || request.ChallengeID != challenge.ID ||
		request.AttestationMarker != api.SoftwareAuthenticatorAttestationMarker || len(request.AttestationObject) == 0 {
		t.Fatal("registration request was not derived from real challenge", err)
	}
	challenge.Ceremony.ExpectedGeneration = 1
	raw, err = json.Marshal(challenge)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := register(root, input.Config, raw, now); err == nil {
		t.Fatal("baseline entry signed replacement enrollment")
	}
}
