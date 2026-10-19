package identity

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"reflect"
	"sync"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// All authorities and signers here are ephemeral synthetic test keys. No test
// root/signing code is part of a production build or proof of hardware presence.
type attestationCA struct {
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
	der         []byte
}

var attestationFixtureOnce sync.Once
var attestationFixtureCA attestationCA
var attestationFixtureErr error

func newAttestationCA() (attestationCA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return attestationCA{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return attestationCA{}, err
	}
	serial.Add(serial, big.NewInt(1))
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Synthetic attestation test CA"},
		NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return attestationCA{}, err
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return attestationCA{}, err
	}
	return attestationCA{certificate: certificate, key: key, der: der}, nil
}

func fixtureAttestationCA(t *testing.T) attestationCA {
	t.Helper()
	attestationFixtureOnce.Do(func() { attestationFixtureCA, attestationFixtureErr = newAttestationCA() })
	if attestationFixtureErr != nil {
		t.Fatal(attestationFixtureErr)
	}
	return attestationFixtureCA
}

func fixtureAttestationPolicy(t *testing.T) AttestationPolicy {
	t.Helper()
	ca := fixtureAttestationCA(t)
	return AttestationPolicy{Config: "fixture", InstallationGeneration: 1, RootsDER: [][]byte{append([]byte(nil), ca.der...)}}
}

func fixtureAttestationCert(t *testing.T, public any, aaguid []byte, change func(*x509.Certificate)) []byte {
	t.Helper()
	return fixtureAttestationCertFrom(t, fixtureAttestationCA(t), public, aaguid, change)
}

func fixtureAttestationCertFrom(t *testing.T, ca attestationCA, public any, aaguid []byte, change func(*x509.Certificate)) []byte {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	serial.Add(serial, big.NewInt(1))
	extension, err := asn1.Marshal(append([]byte(nil), aaguid...))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial,
		Subject:   pkix.Name{Country: []string{"US"}, Organization: []string{"Synthetic test devices"}, OrganizationalUnit: []string{"Authenticator Attestation"}, CommonName: "Synthetic test authenticator"},
		NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{{Id: attestationAAGUIDOID, Value: extension}}}
	if change != nil {
		change(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, public, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func directRegistration(t *testing.T, now time.Time, format string) registrationFixture {
	t.Helper()
	aaguid := "00000000-0000-0000-0000-000000000001"
	if format == "fido-u2f" {
		aaguid = "00000000-0000-0000-0000-000000000000"
	}
	f := newRegistration(t, now, "ES256", aaguid, "")
	if format == "fido-u2f" {
		sealU2F(t, &f, f.key, f.certificate)
	}
	return f
}

func sealU2F(t *testing.T, f *registrationFixture, signer crypto.Signer, certificate []byte) {
	t.Helper()
	client := sha256.Sum256(f.request.ClientDataJSON)
	public, ok := f.key.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("fixture setup: U2F credential is not P-256")
	}
	signed := append([]byte{0}, f.auth[:32]...)
	signed = append(signed, client[:]...)
	length := int(f.auth[53])<<8 | int(f.auth[54])
	signed = append(signed, f.auth[55:55+length]...)
	signed = append(signed, elliptic.Marshal(elliptic.P256(), public.X, public.Y)...)
	hash := sha256.Sum256(signed)
	signature, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	f.statement = map[any]any{"sig": signature, "x5c": []any{certificate}}
	f.encode(t, "fido-u2f")
}

func TestAttestation(t *testing.T) {
	for _, rule := range []string{"packed", "packed-other", "u2f", "u2f-other", "no-key-usage", "no-key-sig", "no-key-root", "bad-key-usage", "u2f-aaguid", "unsupported", "none", "self", "unknown", "untrusted", "expired", "subject", "cert-aaguid", "signature", "u2f-signature", "u2f-key", "missing-roots", "config", "installation"} {
		t.Run(rule, func(t *testing.T) {
			s, store, _ := serviceFixture(t)
			format := "packed"
			if rule == "u2f" || rule == "u2f-other" || rule == "u2f-signature" || rule == "u2f-key" || rule == "u2f-aaguid" {
				format = "fido-u2f"
			}
			f := directRegistration(t, s.deps.Clock.Now(), format)
			want := api.CodeUnauthenticated
			switch rule {
			case "no-key-usage", "no-key-sig", "no-key-root":
				ca := fixtureAttestationCA(t)
				if rule == "no-key-root" {
					var err error
					ca, err = newAttestationCA()
					if err != nil {
						t.Fatal(err)
					}
				}
				f.certificate = fixtureAttestationCertFrom(t, ca, f.key.Public(), f.auth[37:53], func(c *x509.Certificate) { c.KeyUsage = 0 })
				leaf, err := x509.ParseCertificate(f.certificate)
				if err != nil || leaf.KeyUsage != 0 {
					t.Fatalf("fixture setup: no-key-usage leaf differs: %v", err)
				}
				for _, extension := range leaf.Extensions {
					if extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 15}) {
						t.Fatal("fixture setup: no-key-usage leaf has a Key Usage extension")
					}
				}
				f.seal(t)
				if rule == "no-key-sig" {
					f.statement["sig"].([]byte)[0] ^= 0x40
				} else if rule == "no-key-root" {
					f.statement["x5c"] = []any{f.certificate, ca.der}
				}
				f.encode(t, "packed")
			case "bad-key-usage":
				f.certificate = fixtureAttestationCert(t, f.key.Public(), f.auth[37:53], func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment })
				f.seal(t)
			case "u2f-aaguid":
				f.certificate = fixtureAttestationCert(t, f.key.Public(), bytes.Repeat([]byte{9}, 16), nil)
				sealU2F(t, &f, f.key, f.certificate)
			case "unsupported":
				f.statement = map[any]any{"x5c": []any{f.certificate}}
				f.encode(t, "apple")
				want = api.CodeUnsupported
			case "packed-other", "u2f-other":
				other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				certificate := fixtureAttestationCert(t, other.Public(), f.auth[37:53], nil)
				if format == "fido-u2f" {
					sealU2F(t, &f, other, certificate)
				} else {
					client := sha256.Sum256(f.request.ClientDataJSON)
					data := append(append([]byte(nil), f.auth...), client[:]...)
					hash := sha256.Sum256(data)
					signature, err := other.Sign(rand.Reader, hash[:], crypto.SHA256)
					if err != nil {
						t.Fatal(err)
					}
					f.statement = map[any]any{"alg": int64(-7), "sig": signature, "x5c": []any{certificate}}
					f.encode(t, "packed")
				}
			case "none":
				f.statement = map[any]any{}
				f.encode(t, "none")
				want = api.CodeForbidden
			case "self":
				delete(f.statement, "x5c")
				f.encode(t, "packed")
				want = api.CodeForbidden
			case "unknown":
				policy := fixtureAttestationPolicy(t)
				policy.AllowedAAGUIDs = []string{"00000000-0000-0000-0000-000000000002"}
				var err error
				s.attestation, err = freezeAttestation(policy)
				if err != nil {
					t.Fatal(err)
				}
				want = api.CodeForbidden
			case "untrusted":
				ca, err := newAttestationCA()
				if err != nil {
					t.Fatal(err)
				}
				f.certificate = fixtureAttestationCertFrom(t, ca, f.key.Public(), f.auth[37:53], nil)
				f.seal(t)
				f.statement["x5c"] = []any{f.certificate, ca.der}
				f.encode(t, "packed")
			case "expired":
				f.certificate = fixtureAttestationCert(t, f.key.Public(), f.auth[37:53], func(c *x509.Certificate) { c.NotAfter = s.deps.Clock.Now().Add(-time.Minute) })
				f.seal(t)
			case "subject":
				f.certificate = fixtureAttestationCert(t, f.key.Public(), f.auth[37:53], func(c *x509.Certificate) { c.Subject.Organization = nil })
				f.seal(t)
			case "cert-aaguid":
				f.certificate = fixtureAttestationCert(t, f.key.Public(), bytes.Repeat([]byte{9}, 16), nil)
				f.seal(t)
			case "signature", "u2f-signature":
				f.statement["sig"].([]byte)[0] ^= 0x40
				f.encode(t, format)
			case "u2f-key":
				other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				certificate := fixtureAttestationCert(t, other.Public(), f.auth[37:53], nil)
				sealU2F(t, &f, other, certificate)
				// Replace the credential with another valid P-256 point while
				// retaining the original statement signature over the first point.
				length := int(f.auth[53])<<8 | int(f.auth[54])
				cose := map[any]any{int64(1): int64(2), int64(3): int64(-7), int64(-1): int64(1),
					int64(-2): other.X.FillBytes(make([]byte, 32)), int64(-3): other.Y.FillBytes(make([]byte, 32))}
				f.auth = append(append([]byte(nil), f.auth[:55+length]...), registrationCBORFixture(t, cose)...)
				f.encode(t, format)
			case "missing-roots":
				s.attestation = attestationTrust{}
				want = api.CodeForbidden
			case "config":
				s.attestation.config = "foreign"
				want = api.CodeForbidden
			case "installation":
				s.attestation.installation++
				want = api.CodeForbidden
			}
			store.ceremony = &f.challenge
			install, err := s.ValidateEnrollment(context.Background(), f.request)
			if rule == "packed" || rule == "packed-other" || rule == "u2f" || rule == "u2f-other" || rule == "no-key-usage" || rule == "u2f-aaguid" {
				publicDER, keyErr := x509.MarshalPKIXPublicKey(f.key.Public())
				if err != nil || len(install.Enrollment.Credentials) != 1 || install.Enrollment.Credentials[0].AttestationFormat != format || install.Enrollment.Credentials[0].SimulatedPresence {
					t.Fatalf("fixture check: valid direct attestation was refused or marked simulated: %v", err)
				}
				if keyErr != nil || !bytes.Equal(install.Enrollment.Credentials[0].PublicKeyDER, publicDER) ||
					install.Enrollment.Credentials[0].Counter != 10 || install.CeremonyEvidence.SHA256 != digestBytes(launchJSON(t, f.request)) {
					t.Fatal("fixture check: direct attestation changed credential key, counter or exact evidence")
				}
				return
			}
			fixtureCode(t, err, want)
			if !reflect.DeepEqual(install, api.EnrollmentInstall{}) {
				t.Fatal("fixture check: untrusted attestation returned enrollment authority")
			}
		})
	}
}

func TestAttestationPolicy(t *testing.T) {
	for _, rule := range []string{"copy", "bad-root", "non-ca", "bad-aaguid", "duplicate", "no-config", "no-generation"} {
		t.Run(rule, func(t *testing.T) {
			s, _, _ := serviceFixture(t)
			policy := fixtureAttestationPolicy(t)
			policy.AllowedAAGUIDs = []string{"00000000-0000-0000-0000-000000000001"}
			switch rule {
			case "bad-root":
				policy.RootsDER[0] = []byte("invalid certificate")
			case "non-ca":
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				policy.RootsDER[0] = fixtureAttestationCert(t, key.Public(), make([]byte, 16), nil)
			case "bad-aaguid":
				policy.AllowedAAGUIDs[0] = "not-a-guid"
			case "duplicate":
				policy.AllowedAAGUIDs = append(policy.AllowedAAGUIDs, policy.AllowedAAGUIDs[0])
			case "no-config":
				policy.Config = ""
			case "no-generation":
				policy.InstallationGeneration = 0
			}
			deps := s.deps
			deps.Attestation = policy
			current, err := New(deps)
			if rule != "copy" {
				fixtureCode(t, err, api.CodeInvalid)
				if current != nil {
					t.Fatal("fixture check: invalid attestation policy constructed identity")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			policy.RootsDER[0][0] ^= 0x40
			policy.AllowedAAGUIDs[0] = "00000000-0000-0000-0000-000000000002"
			store := current.deps.Store.(*fixtureStore)
			f := directRegistration(t, current.deps.Clock.Now(), "packed")
			store.ceremony = &f.challenge
			if _, err := current.ValidateEnrollment(context.Background(), f.request); err != nil {
				t.Fatalf("fixture check: installed attestation policy aliases caller data: %v", err)
			}
		})
	}
}
