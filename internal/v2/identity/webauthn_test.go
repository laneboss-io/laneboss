package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type assertionFixture struct {
	challenge api.HumanChallenge
	request   api.HumanConfirmRequest
	key       crypto.Signer
	public    []byte
	now       time.Time
}

func newAssertion(t *testing.T, key crypto.Signer) assertionFixture {
	t.Helper()
	if key == nil {
		var err error
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
	}
	public, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	digest := sha256.Sum256([]byte("operation bytes for this fixture"))
	challenge := api.HumanChallenge{ID: "challenge", Challenge: nonce,
		Config: "fixture", Method: "ticket.issue", TargetID: "root",
		RequestSHA256: api.Digest(hex.EncodeToString(digest[:])), BaseGeneration: 7,
		Origin: "https://console.example.test", RPID: "console.example.test",
		ExpiresAt: api.Timestamp(now.Add(time.Minute).Format(time.RFC3339Nano))}
	client, err := json.Marshal(map[string]any{"type": "webauthn.get",
		"challenge": base64.RawURLEncoding.EncodeToString(nonce),
		"origin":    challenge.Origin, "crossOrigin": false})
	if err != nil {
		t.Fatal(err)
	}
	rpHash := sha256.Sum256([]byte(challenge.RPID))
	data := make([]byte, 37)
	copy(data, rpHash[:])
	data[32] = 0x05
	binary.BigEndian.PutUint32(data[33:], 11)
	f := assertionFixture{challenge: challenge, key: key, public: public, now: now,
		request: api.HumanConfirmRequest{ChallengeID: challenge.ID, CredentialID: "credential",
			ClientDataJSON: client, AuthenticatorData: data}}
	f.sign(t)
	return f
}

func (f *assertionFixture) sign(t *testing.T) {
	t.Helper()
	hash := sha256.Sum256(f.request.ClientDataJSON)
	signed := append(append([]byte{}, f.request.AuthenticatorData...), hash[:]...)
	var signature []byte
	var err error
	if _, ok := f.key.(ed25519.PrivateKey); ok {
		signature, err = f.key.Sign(rand.Reader, signed, crypto.Hash(0))
	} else {
		digest := sha256.Sum256(signed)
		signature, err = f.key.Sign(rand.Reader, digest[:], crypto.SHA256)
	}
	if err != nil {
		t.Fatal(err)
	}
	f.request.Signature = signature
}

func (f *assertionFixture) clientField(t *testing.T, field string, value any) {
	t.Helper()
	var client map[string]any
	if err := json.Unmarshal(f.request.ClientDataJSON, &client); err != nil {
		t.Fatal(err)
	}
	client[field] = value
	data, err := json.Marshal(client)
	if err != nil {
		t.Fatal(err)
	}
	f.request.ClientDataJSON = data
	f.sign(t)
}

func errorCode(t *testing.T, err error, code api.ErrorCode) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("want %s, got %v", code, err)
	}
}

func TestAssertionAlgorithms(t *testing.T) {
	cases := []struct {
		name string
		key  func() (crypto.Signer, error)
	}{
		{"es256", func() (crypto.Signer, error) {
			return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		}},
		{"rs256", func() (crypto.Signer, error) {
			return rsa.GenerateKey(rand.Reader, 2048)
		}},
		{"ed25519", func() (crypto.Signer, error) {
			_, key, err := ed25519.GenerateKey(rand.Reader)
			return key, err
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			key, err := test.key()
			if err != nil {
				t.Fatalf("fixture setup: key generation failed: %v", err)
			}
			f := newAssertion(t, key)
			counter, err := VerifyAssertion(f.challenge, "credential", f.public, 10, f.request, f.now)
			if err != nil || counter != 11 {
				t.Fatalf("valid signed assertion failed: counter=%d error=%v", counter, err)
			}
			f.request.Signature[0] ^= 0x40
			_, err = VerifyAssertion(f.challenge, "credential", f.public, 10, f.request, f.now)
			errorCode(t, err, api.CodeUnauthenticated)
		})
	}
}

// Every policy mutation is re-signed with the real fixture key. Thus a missing
// policy check fails this test rather than being masked by a bad signature.
func TestAssertionControls(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*testing.T, *assertionFixture)
		code   api.ErrorCode
	}{
		{"origin", func(t *testing.T, f *assertionFixture) {
			f.clientField(t, "origin", "https://other.example.test")
		}, api.CodeUnauthenticated},
		{"cross-origin", func(t *testing.T, f *assertionFixture) {
			f.clientField(t, "crossOrigin", true)
		}, api.CodeUnauthenticated},
		{"type", func(t *testing.T, f *assertionFixture) {
			f.clientField(t, "type", "webauthn.create")
		}, api.CodeUnauthenticated},
		{"nonce", func(t *testing.T, f *assertionFixture) {
			f.clientField(t, "challenge", base64.RawURLEncoding.EncodeToString([]byte("other")))
		}, api.CodeUnauthenticated},
		{"rp-id", func(t *testing.T, f *assertionFixture) {
			f.request.AuthenticatorData[0] ^= 0x10
			f.sign(t)
		}, api.CodeUnauthenticated},
		{"no-up", func(t *testing.T, f *assertionFixture) {
			f.request.AuthenticatorData[32] = 0x04
			f.sign(t)
		}, api.CodeUnauthenticated},
		{"no-uv", func(t *testing.T, f *assertionFixture) {
			f.request.AuthenticatorData[32] = 0x01
			f.sign(t)
		}, api.CodeUnauthenticated},
		{"reserved", func(t *testing.T, f *assertionFixture) {
			f.request.AuthenticatorData[32] |= 0x02
			f.sign(t)
		}, api.CodeUnauthenticated},
		{"attested", func(t *testing.T, f *assertionFixture) {
			f.request.AuthenticatorData[32] |= 0x40
			f.sign(t)
		}, api.CodeUnauthenticated},
		{"backup", func(t *testing.T, f *assertionFixture) {
			f.request.AuthenticatorData[32] |= 0x10
			f.sign(t)
		}, api.CodeUnauthenticated},
		{"extension", func(t *testing.T, f *assertionFixture) {
			f.request.AuthenticatorData[32] |= 0x80
			f.sign(t)
		}, api.CodeUnsupported},
		{"suffix", func(t *testing.T, f *assertionFixture) {
			f.request.AuthenticatorData = append(f.request.AuthenticatorData, 0)
			f.sign(t)
		}, api.CodeInvalid},
		{"expired", func(t *testing.T, f *assertionFixture) {
			f.now = f.now.Add(time.Minute)
		}, api.CodeUnauthenticated},
		{"too-long", func(t *testing.T, f *assertionFixture) {
			f.challenge.ExpiresAt = api.Timestamp(f.now.Add(121 * time.Second).Format(time.RFC3339Nano))
		}, api.CodeUnauthenticated},
		{"challenge-id", func(t *testing.T, f *assertionFixture) {
			f.request.ChallengeID = "other"
		}, api.CodeUnauthenticated},
		{"credential-id", func(t *testing.T, f *assertionFixture) {
			f.request.CredentialID = "other"
		}, api.CodeUnauthenticated},
		{"top-origin", func(t *testing.T, f *assertionFixture) {
			f.clientField(t, "topOrigin", f.challenge.Origin)
		}, api.CodeUnauthenticated},
		{"counter-replay", func(t *testing.T, f *assertionFixture) {
			binary.BigEndian.PutUint32(f.request.AuthenticatorData[33:], 10)
			f.sign(t)
		}, api.CodeUnauthenticated},
		{"counter-reset", func(t *testing.T, f *assertionFixture) {
			binary.BigEndian.PutUint32(f.request.AuthenticatorData[33:], 0)
			f.sign(t)
		}, api.CodeUnauthenticated},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			f := newAssertion(t, nil)
			if _, err := VerifyAssertion(f.challenge, "credential", f.public, 10, f.request, f.now); err != nil {
				t.Fatal(err)
			}
			test.mutate(t, &f)
			counter, err := VerifyAssertion(f.challenge, "credential", f.public, 10, f.request, f.now)
			errorCode(t, err, test.code)
			if counter != 0 {
				t.Fatal("refused assertion returned a usable counter")
			}
		})
	}
}

func TestClientDataFixture(t *testing.T) {
	for _, rule := range []string{"extra", "nested-extra", "null-extra", "unsigned-extra", "type-number", "origin-null", "cross-string", "top-number", "missing-type", "duplicate-extra", "array", "trailing"} {
		t.Run(rule, func(t *testing.T) {
			f := newAssertion(t, nil)
			want := api.CodeInvalid
			switch rule {
			case "extra", "unsigned-extra":
				original := append([]byte(nil), f.request.Signature...)
				f.clientField(t, "other_keys_can_be_added_here", "do not compare clientDataJSON against a template")
				want = ""
				if rule == "unsigned-extra" {
					f.request.Signature, want = original, api.CodeUnauthenticated
				}
			case "nested-extra":
				f.clientField(t, "future", map[string]any{"options": []any{true, "value", 3}})
				want = ""
			case "null-extra":
				f.clientField(t, "future", nil)
				want = ""
			case "type-number":
				f.clientField(t, "type", 3)
			case "origin-null":
				f.clientField(t, "origin", nil)
			case "cross-string":
				f.clientField(t, "crossOrigin", "false")
			case "top-number":
				f.clientField(t, "topOrigin", 3)
			case "missing-type":
				var fields map[string]any
				if err := json.Unmarshal(f.request.ClientDataJSON, &fields); err != nil {
					t.Fatal(err)
				}
				delete(fields, "type")
				f.request.ClientDataJSON = launchJSON(t, fields)
				f.sign(t)
			case "duplicate-extra":
				f.clientField(t, "future", true)
				f.request.ClientDataJSON = append(f.request.ClientDataJSON[:len(f.request.ClientDataJSON)-1], []byte(`,"future":false}`)...)
				f.sign(t)
			case "array":
				f.request.ClientDataJSON = []byte(`[]`)
				f.sign(t)
			case "trailing":
				f.request.ClientDataJSON = append(f.request.ClientDataJSON, []byte(` {}`)...)
				f.sign(t)
			}
			counter, err := VerifyAssertion(f.challenge, "credential", f.public, 10, f.request, f.now)
			if want != "" {
				errorCode(t, err, want)
				if counter != 0 {
					t.Fatal("fixture check: invalid client data returned a counter")
				}
				return
			}
			if err != nil || counter != 11 {
				t.Fatalf("fixture check: signed browser client data was refused: %v", err)
			}
		})
	}
}

func TestAssertionCounterless(t *testing.T) {
	f := newAssertion(t, nil)
	binary.BigEndian.PutUint32(f.request.AuthenticatorData[33:], 0)
	f.sign(t)
	counter, err := VerifyAssertion(f.challenge, "credential", f.public, 0, f.request, f.now)
	if err != nil || counter != 0 {
		t.Fatalf("valid counterless assertion failed: %v", err)
	}
	f.request.AuthenticatorData[36] = 1
	_, err = VerifyAssertion(f.challenge, "credential", f.public, 0, f.request, f.now)
	errorCode(t, err, api.CodeUnauthenticated)
}

func TestAssertionWrongKey(t *testing.T) {
	f := newAssertion(t, nil)
	other := newAssertion(t, nil)
	_, err := VerifyAssertion(f.challenge, "credential", other.public, 10, f.request, f.now)
	errorCode(t, err, api.CodeUnauthenticated)
}

func TestOriginConfiguration(t *testing.T) {
	for _, origin := range []string{"http://console.example.test", "https://console.example.test/",
		"https://user" + "@console.example.test", "https://console.example.test?x=1",
		"https://different.example.test"} {
		errorCode(t, originPolicy(origin, "console.example.test"), api.CodeIntegrity)
	}
	for _, origin := range []string{"https://console.example.test", "http://localhost"} {
		rp := "console.example.test"
		if origin == "http://localhost" {
			rp = "localhost"
		}
		if err := originPolicy(origin, rp); err != nil {
			t.Fatal(err)
		}
	}
}
