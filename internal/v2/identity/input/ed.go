// Package testinput supplies signed WebAuthn inputs to component tests.
// Synthetic roots and signers here are not installed authenticator evidence.
package testinput

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/identity"
)

type Registration struct {
	Install   api.EnrollmentInstall
	Request   api.EnrollmentValidationRequest
	Challenge api.EnrollmentChallenge
	Private   ed25519.PrivateKey
}

type challengeStore struct {
	api.StateStore
	challenge api.EnrollmentChallenge
}

func (s *challengeStore) EnrollmentChallenge(_ context.Context, config string, id api.ID) (api.EnrollmentChallenge, error) {
	if config != s.challenge.Ceremony.Config || id != s.challenge.ID {
		return api.EnrollmentChallenge{}, &api.Error{Code: api.CodeNotFound, Message: "registration challenge differs"}
	}
	return s.challenge, nil
}

type unusedPorts struct {
	api.PeerVerifier
	api.ContainmentRegistry
}

func randomID(t testing.TB) api.ID {
	t.Helper()
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return api.ID(hex.EncodeToString(raw))
}

// EdRegistration returns the unmodified output of production ValidateEnrollment.
// The only fixture boundaries are the retained challenge and pinned test CA.
func EdRegistration(t testing.TB, config string, principal api.ID, clock api.Clock) Registration {
	t.Helper()
	now := clock.Now().UTC()
	challenge := api.EnrollmentChallenge{ID: randomID(t),
		Ceremony:  api.EnrollmentCeremonyRequest{Config: config, CeremonyID: randomID(t), PrincipalID: principal},
		Challenge: make([]byte, 32), Origin: "https://registration.invalid", RPID: "registration.invalid",
		EndpointGeneration: 1, InstallationGeneration: 1, ExpiresAt: api.Timestamp(now.Add(2 * time.Minute).Format(time.RFC3339Nano))}
	if _, err := rand.Read(challenge.Challenge); err != nil {
		t.Fatal(err)
	}
	return EdFromChallenge(t, challenge, clock)
}

// EdFromChallenge also accepts an actual challenge retained by the real store.
func EdFromChallenge(t testing.TB, challenge api.EnrollmentChallenge, clock api.Clock) Registration {
	t.Helper()
	now := clock.Now().UTC()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(private) })
	client, err := json.Marshal(map[string]any{"type": "webauthn.create", "origin": challenge.Origin,
		"challenge": base64.RawURLEncoding.EncodeToString(challenge.Challenge), "crossOrigin": false})
	if err != nil {
		t.Fatal(err)
	}
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic registration CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCertificate, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	aaguid := make([]byte, 16)
	aaguid[15] = 1
	extension, err := asn1.Marshal(aaguid)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Version: 3,
		Subject: pkix.Name{Country: []string{"US"}, Organization: []string{"Synthetic registration"},
			OrganizationalUnit: []string{"Authenticator Attestation"}, CommonName: "Synthetic registration key"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}, Value: extension}}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, rootCertificate, public, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	auth := make([]byte, 55)
	rp := sha256.Sum256([]byte(challenge.RPID))
	copy(auth, rp[:])
	auth[32] = 0x45
	copy(auth[37:53], aaguid)
	rawID := []byte(randomID(t))
	binary.BigEndian.PutUint16(auth[53:55], uint16(len(rawID)))
	auth = append(auth, rawID...)
	auth = append(auth, cbor(t, map[any]any{int64(1): int64(1), int64(3): int64(-8), int64(-1): int64(6), int64(-2): []byte(public)})...)
	clientHash := sha256.Sum256(client)
	signed := append(append([]byte(nil), auth...), clientHash[:]...)
	request := api.EnrollmentValidationRequest{Ceremony: challenge.Ceremony, ChallengeID: challenge.ID, ClientDataJSON: client,
		AttestationObject: cbor(t, map[any]any{"fmt": "packed", "authData": auth,
			"attStmt": map[any]any{"alg": int64(-8), "sig": ed25519.Sign(private, signed), "x5c": []any{leafDER}}})}
	owner, err := identity.New(identity.Dependencies{Peers: &unusedPorts{}, Registry: &unusedPorts{},
		Store: &challengeStore{challenge: challenge}, Clock: clock,
		Attestation: identity.AttestationPolicy{Config: challenge.Ceremony.Config, InstallationGeneration: challenge.InstallationGeneration, RootsDER: [][]byte{rootDER}}})
	if err != nil {
		t.Fatal(err)
	}
	install, err := owner.ValidateEnrollment(context.Background(), request)
	if err != nil {
		t.Fatal("real Ed25519 registration was refused", err)
	}
	return Registration{Install: install, Request: request, Challenge: challenge, Private: private}
}

func cbor(t testing.TB, value any) []byte {
	t.Helper()
	header := func(major byte, size uint64) []byte {
		switch {
		case size < 24:
			return []byte{major<<5 | byte(size)}
		case size <= 255:
			return []byte{major<<5 | 24, byte(size)}
		case size <= 65535:
			return []byte{major<<5 | 25, byte(size >> 8), byte(size)}
		default:
			t.Fatal("registration CBOR fixture exceeds its size bound")
			return nil
		}
	}
	switch v := value.(type) {
	case string:
		return append(header(3, uint64(len(v))), []byte(v)...)
	case []byte:
		return append(header(2, uint64(len(v))), v...)
	case int64:
		if v < 0 {
			return header(1, uint64(-1-v))
		}
		return header(0, uint64(v))
	case []any:
		raw := header(4, uint64(len(v)))
		for _, item := range v {
			raw = append(raw, cbor(t, item)...)
		}
		return raw
	case map[any]any:
		keys := make([]any, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool { return fmt.Sprint(keys[i]) < fmt.Sprint(keys[j]) })
		raw := header(5, uint64(len(v)))
		for _, key := range keys {
			raw = append(raw, cbor(t, key)...)
			raw = append(raw, cbor(t, v[key])...)
		}
		return raw
	default:
		t.Fatal("unsupported registration CBOR fixture type")
		return nil
	}
}
