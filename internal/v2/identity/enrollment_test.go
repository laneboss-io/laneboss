package identity

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// Software keys are generated in this unit fixture only. This is neither an
// installed authenticator implementation nor evidence of hardware presence.
type registrationFixture struct {
	challenge   api.EnrollmentChallenge
	request     api.EnrollmentValidationRequest
	key         crypto.Signer
	algorithm   int64
	auth        []byte
	statement   map[any]any
	certificate []byte
}

func newRegistration(t *testing.T, now time.Time, algorithm, aaguid, marker string) registrationFixture {
	t.Helper()
	var key crypto.Signer
	var cose map[any]any
	var number int64
	switch algorithm {
	case "ES256":
		private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key, number = private, -7
		cose = map[any]any{int64(1): int64(2), int64(3): number, int64(-1): int64(1),
			int64(-2): private.X.FillBytes(make([]byte, 32)), int64(-3): private.Y.FillBytes(make([]byte, 32))}
	case "RS256":
		private, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		key, number = private, -257
		cose = map[any]any{int64(1): int64(3), int64(3): number, int64(-1): private.N.Bytes(), int64(-2): []byte{1, 0, 1}}
	case "Ed25519":
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key, number = private, -8
		cose = map[any]any{int64(1): int64(1), int64(3): number, int64(-1): int64(6), int64(-2): []byte(public)}
	default:
		t.Fatal("fixture setup: unsupported registration key")
	}
	ceremony := api.EnrollmentCeremonyRequest{Config: "fixture", CeremonyID: "ceremony", PrincipalID: "human"}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	challenge := api.EnrollmentChallenge{ID: "registration-challenge", Ceremony: ceremony, Challenge: nonce,
		Origin: "https://console.example.test", RPID: "console.example.test", EndpointGeneration: 1, InstallationGeneration: 1,
		ExpiresAt: timestamp(now.Add(2 * time.Minute))}
	client, err := json.Marshal(map[string]any{"type": "webauthn.create", "origin": challenge.Origin,
		"challenge": base64.RawURLEncoding.EncodeToString(nonce), "crossOrigin": false})
	if err != nil {
		t.Fatal(err)
	}
	rp := sha256.Sum256([]byte(challenge.RPID))
	auth := make([]byte, 55)
	copy(auth, rp[:])
	auth[32] = 0x45
	binary.BigEndian.PutUint32(auth[33:37], 10)
	guid, err := hex.DecodeString(strings.ReplaceAll(aaguid, "-", ""))
	if err != nil || len(guid) != 16 {
		t.Fatal("fixture setup: bad registration AAGUID")
	}
	copy(auth[37:53], guid)
	rawID := []byte("public-registration-credential")
	binary.BigEndian.PutUint16(auth[53:55], uint16(len(rawID)))
	auth = append(auth, rawID...)
	auth = append(auth, registrationCBORFixture(t, cose)...)
	f := registrationFixture{challenge: challenge, key: key, algorithm: number, auth: auth,
		request: api.EnrollmentValidationRequest{Ceremony: ceremony, ChallengeID: challenge.ID, ClientDataJSON: client, AttestationMarker: marker}}
	f.certificate = fixtureAttestationCert(t, key.Public(), auth[37:53], nil)
	f.seal(t)
	return f
}

func (f *registrationFixture) seal(t *testing.T) {
	t.Helper()
	client := sha256.Sum256(f.request.ClientDataJSON)
	signed := append(append([]byte(nil), f.auth...), client[:]...)
	var signature []byte
	var err error
	if _, ok := f.key.(ed25519.PrivateKey); ok {
		signature, err = f.key.Sign(rand.Reader, signed, crypto.Hash(0))
	} else {
		hash := sha256.Sum256(signed)
		signature, err = f.key.Sign(rand.Reader, hash[:], crypto.SHA256)
	}
	if err != nil {
		t.Fatal(err)
	}
	f.statement = map[any]any{"alg": f.algorithm, "sig": signature, "x5c": []any{f.certificate}}
	f.encode(t, "packed")
}

func (f *registrationFixture) encode(t *testing.T, format string) {
	f.request.AttestationObject = registrationCBORFixture(t, map[any]any{"fmt": format, "authData": f.auth, "attStmt": f.statement})
}

func registrationCBORFixture(t *testing.T, value any) []byte {
	t.Helper()
	header := func(major byte, n uint64) []byte {
		switch {
		case n < 24:
			return []byte{major<<5 | byte(n)}
		case n <= 255:
			return []byte{major<<5 | 24, byte(n)}
		case n <= 65535:
			return []byte{major<<5 | 25, byte(n >> 8), byte(n)}
		default:
			return []byte{major<<5 | 26, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
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
			raw = append(raw, registrationCBORFixture(t, item)...)
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
			raw = append(raw, registrationCBORFixture(t, key)...)
			raw = append(raw, registrationCBORFixture(t, v[key])...)
		}
		return raw
	}
	t.Fatal("fixture setup: unsupported CBOR value")
	return nil
}

func TestEnrollmentConsumerFixture(t *testing.T) {
	for _, rule := range []string{"valid", "used", "nonce", "origin", "rp", "uv", "signature", "duplicate", "selector", "later", "none"} {
		t.Run(rule, func(t *testing.T) {
			s, store, _ := serviceFixture(t)
			f := newRegistration(t, s.deps.Clock.Now(), "Ed25519", "00000000-0000-0000-0000-000000000001", "")
			store.ceremony = &f.challenge
			want := api.CodeUnauthenticated
			switch rule {
			case "used":
				store.ceremony.Consumed = true
				want = api.CodeInvalid
			case "nonce", "origin":
				var client map[string]any
				if err := json.Unmarshal(f.request.ClientDataJSON, &client); err != nil {
					t.Fatal(err)
				}
				if rule == "nonce" {
					client["challenge"] = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
				} else {
					client["origin"] = "https://foreign.example"
				}
				f.request.ClientDataJSON = launchJSON(t, client)
				f.seal(t)
			case "rp":
				f.auth[0] ^= 0x40
				f.seal(t)
			case "uv":
				f.auth[32] &^= 0x04
				f.seal(t)
			case "signature":
				f.statement["sig"].([]byte)[0] ^= 0x40
				f.encode(t, "packed")
			case "duplicate":
				raw := []byte{0xa4}
				raw = append(raw, registrationCBORFixture(t, "fmt")...)
				raw = append(raw, registrationCBORFixture(t, "packed")...)
				f.request.AttestationObject = append(raw, f.request.AttestationObject[1:]...)
				want = api.CodeInvalid
			case "selector":
				store.ceremony.ID = "foreign-challenge"
				want = api.CodeIntegrity
			case "later":
				f.request.Ceremony.ExpectedGeneration = 1
				store.ceremony.Ceremony = f.request.Ceremony
			case "none":
				f.statement = map[any]any{}
				f.encode(t, "none")
				want = api.CodeForbidden
			}
			install, err := s.ValidateEnrollment(context.Background(), f.request)
			if rule != "valid" && rule != "later" {
				fixtureCode(t, err, want)
				if !reflect.DeepEqual(install, api.EnrollmentInstall{}) {
					t.Fatal("fixture check: refused registration returned authority")
				}
				return
			}
			if err != nil || len(install.Enrollment.Credentials) != 1 {
				t.Fatalf("fixture check: verified registration handoff refused: %v", err)
			}
			credential := install.Enrollment.Credentials[0]
			evidence := launchJSON(t, f.request)
			if install.CeremonyEvidence.SHA256 != digestBytes(evidence) || install.CeremonyEvidence.Bytes != int64(len(evidence)) || credential.RegistrationEvidence != install.CeremonyEvidence ||
				credential.Counter != 10 || credential.Algorithm != "EdDSA" || credential.SimulatedPresence || install.Enrollment.Generation != f.request.Ceremony.ExpectedGeneration+1 || store.ceremony.Consumed {
				t.Fatal("fixture check: registration lost verified facts or exact evidence")
			}
			if rule == "later" {
				fixtureCode(t, api.ValidateInitialEnrollment(f.challenge, f.request, install, s.deps.Clock.Now()), api.CodeForbidden)
			}
		})
	}
}

func TestEnrollmentAlgorithmsFixture(t *testing.T) {
	for _, algorithm := range []string{"ES256", "RS256", "Ed25519"} {
		t.Run(algorithm, func(t *testing.T) {
			s, store, _ := serviceFixture(t)
			f := newRegistration(t, s.deps.Clock.Now(), algorithm, "00000000-0000-0000-0000-000000000001", "")
			store.ceremony = &f.challenge
			install, err := s.ValidateEnrollment(context.Background(), f.request)
			want := algorithm
			if algorithm == "Ed25519" {
				want = "EdDSA"
			}
			if err != nil || len(install.Enrollment.Credentials) != 1 || install.Enrollment.Credentials[0].Algorithm != want {
				t.Fatalf("fixture check: real registration key refused: %v", err)
			}
		})
	}
}

func TestEnrollmentBeginFixture(t *testing.T) {
	for _, rule := range []string{"valid", "foreign", "used", "error"} {
		t.Run(rule, func(t *testing.T) {
			s, store, _ := serviceFixture(t)
			f := newRegistration(t, s.deps.Clock.Now(), "Ed25519", "00000000-0000-0000-0000-000000000001", "")
			store.ceremony = &f.challenge
			request := f.request.Ceremony
			if rule == "foreign" {
				store.ceremony.Ceremony.Config = "foreign"
			}
			if rule == "used" {
				store.ceremony.Consumed = true
			}
			if rule == "error" {
				store.err = api.NotImplemented("lb-v2-service", "fixture reserve unavailable")
			}
			challenge, err := s.BeginEnrollment(context.Background(), request)
			if rule == "error" {
				if err != store.err {
					t.Fatal("fixture check: reserve error was replaced")
				}
				return
			}
			if rule != "valid" {
				fixtureCode(t, err, api.CodeInvalid)
				return
			}
			if err != nil || challenge.ID != f.challenge.ID || store.ceremonyConfig != request.Config || store.ceremonyID != request.CeremonyID || !bytes.Equal(challenge.Challenge, f.challenge.Challenge) {
				t.Fatalf("fixture check: stored create challenge was not returned: %v", err)
			}
			challenge.Challenge[0] ^= 0x80
			if bytes.Equal(challenge.Challenge, store.ceremony.Challenge) {
				t.Fatal("fixture check: create challenge aliases protected store bytes")
			}
		})
	}
}

func TestEnrollmentMarkersFixture(t *testing.T) {
	for _, rule := range []string{"marker", "aaguid"} {
		t.Run(rule, func(t *testing.T) {
			s, store, _ := serviceFixture(t)
			aaguid, marker := api.SoftwareAuthenticatorAAGUID, ""
			if rule == "aaguid" {
				aaguid, marker = "00000000-0000-0000-0000-000000000001", api.SoftwareAuthenticatorAttestationMarker
			}
			f := newRegistration(t, s.deps.Clock.Now(), "Ed25519", aaguid, marker)
			store.ceremony = &f.challenge
			install, err := s.ValidateEnrollment(context.Background(), f.request)
			if err == nil || !reflect.DeepEqual(install, api.EnrollmentInstall{}) {
				t.Fatal("fixture check: partial registration markers were admitted")
			}
		})
	}
}
