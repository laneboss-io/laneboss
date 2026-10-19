package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"
)

func contractCode(t *testing.T, err error, code ErrorCode, diagnostic string) {
	t.Helper()
	var typed *Error
	if !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("%s: %v", diagnostic, err)
	}
}

func TestOrgKinds(t *testing.T) {
	for _, fault := range []string{"source", "derived", "unknown", "no_sources"} {
		t.Run(fault, func(t *testing.T) {
			s := OrgSnapshot{Ref: OrgSnapshotRef{Generation: 2}, Sources: []ResourceFile{{Kind: "prompt"}, {Kind: "drivers"}, {Kind: "policy"}, {Kind: "source"}, {Kind: "task"}}, Derived: []ResourceFile{{Kind: "file"}}}
			if err := ValidateOrgKinds(s); err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "source":
				s.Sources[0].Kind = "file"
			case "derived":
				s.Derived[0].Kind = "prompt"
			case "unknown":
				s.Sources[0].Kind = "unknown"
			case "no_sources":
				s.Sources = nil
			}
			contractCode(t, ValidateOrgKinds(s), CodeInvalid, "noncanonical org kind was accepted")
		})
	}
}

func TestOrgEmpty(t *testing.T) {
	for _, row := range []struct {
		name       string
		generation Generation
	}{{"1", 1}, {"nil1", 1}, {"2", 2}, {"kind2", 2}, {"zero", 2}, {"limit", 2}} {
		t.Run(row.name, func(t *testing.T) {
			s := OrgSnapshot{Ref: OrgSnapshotRef{Generation: row.generation}, Sources: []ResourceFile{{Kind: "prompt"}, {Kind: "drivers"}}, Derived: []ResourceFile{}}
			if row.generation > 1 {
				s.Derived = []ResourceFile{{Kind: "file"}}
			}
			if err := ValidateOrgKinds(s); err != nil {
				t.Fatal("generation-matched org inventory was refused", err)
			}
			switch row.name {
			case "1":
				s.Derived = []ResourceFile{{Kind: "file"}}
			case "nil1":
				s.Derived = nil
			case "2":
				s.Derived = []ResourceFile{}
			case "kind2":
				s.Derived[0].Kind = "prompt"
			case "zero":
				s.Ref.Generation = 0
			case "limit":
				s.Ref.Generation = launchMaxInteger + 1
			}
			contractCode(t, ValidateOrgKinds(s), CodeInvalid, "org generation or derived shape was accepted")
		})
	}
}

func TestTrustRoots(t *testing.T) {
	for _, fault := range []string{"subordinate", "issuer", "signature", "key"} {
		t.Run(fault, func(t *testing.T) {
			pub, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			otherPub, _, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture root"},
				NotBefore: contractNow().Add(-time.Hour), NotAfter: contractNow().Add(time.Hour),
				IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
			der, err := x509.CreateCertificate(rand.Reader, root, root, pub, key)
			if err != nil {
				t.Fatal(err)
			}
			p := InstalledAttestationPolicy{Schema: "laneboss.attestation-trust.v2", Config: "demo", InstallationGeneration: 1, RootsDER: [][]byte{der}}
			if err := ValidateInstalledAttestationPolicy(p, "demo", 1); err != nil {
				t.Fatal("valid self-signed root was refused", err)
			}
			child, parent, subjectKey := *root, *root, pub
			child.SerialNumber = big.NewInt(2)
			switch fault {
			case "subordinate":
				child.Subject.CommonName, subjectKey = "fixture subordinate", otherPub
			case "issuer":
				parent.Subject.CommonName = "different issuer"
			case "signature":
				subjectKey = otherPub
			}
			reissued, err := x509.CreateCertificate(rand.Reader, &child, &parent, subjectKey, key)
			if err != nil {
				t.Fatal(err)
			}
			if fault == "key" {
				p.RootsDER = append(p.RootsDER, reissued)
			} else {
				p.RootsDER = [][]byte{reissued}
			}
			contractCode(t, ValidateInstalledAttestationPolicy(p, "demo", 1), CodeInvalid, "non-root or repeated-key attestation pin was accepted")
		})
	}
}

func TestOrgSelect(t *testing.T) {
	for _, fault := range []string{"empty", "generation", "foreign", "head", "config", "org"} {
		t.Run(fault, func(t *testing.T) {
			scope := Scope{Config: "demo"}
			request := OrgSnapshotRequest{OrgID: "demo", Generation: 3}
			snapshot := OrgSnapshot{Config: "demo", Ref: OrgSnapshotRef{OrgID: "demo", Generation: 3}}
			if err := ValidateOrgSnapshotSelection(scope, request, snapshot); err != nil {
				t.Fatal(err)
			}
			code := CodeInvalid
			switch fault {
			case "empty":
				request.OrgID = ""
			case "generation":
				request.Generation = 0
			case "foreign":
				request.OrgID = "other"
			case "head":
				snapshot.Ref.Generation++
				code = CodeConflict
			case "config":
				snapshot.Config = "other"
				code = CodeIntegrity
			case "org":
				snapshot.Ref.OrgID = "other"
				code = CodeIntegrity
			}
			if code == CodeInvalid {
				contractCode(t, ValidateOrgSnapshotRequest(scope, request), code, "org selection boundary was bypassed")
			} else {
				contractCode(t, ValidateOrgSnapshotSelection(scope, request, snapshot), code, "org selection boundary was bypassed")
			}
		})
	}
}

// Synthetic public certificates generated only by the Linux test workload.
// These are not vendor pins or an observed hardware enrollment.
func trustRoot(t *testing.T, ca bool, usage x509.KeyUsage, padding int) []byte {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture root"},
		NotBefore: contractNow().Add(-time.Hour), NotAfter: contractNow().Add(time.Hour),
		IsCA: ca, BasicConstraintsValid: true, KeyUsage: usage}
	if padding > 0 {
		cert.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: make([]byte, padding)}}
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, public, private)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func trustFixture(t *testing.T) InstalledAttestationPolicy {
	t.Helper()
	return InstalledAttestationPolicy{Schema: "laneboss.attestation-trust.v2", Config: "demo", InstallationGeneration: 1,
		RootsDER:       [][]byte{trustRoot(t, true, x509.KeyUsageCertSign, 0), trustRoot(t, true, x509.KeyUsageCertSign, 0)},
		AllowedAAGUIDs: []string{"00000000-0000-0000-0000-000000000000"}}
}

func TestTrustPolicy(t *testing.T) {
	for _, fault := range []string{"schema", "config", "installation", "der", "ca", "usage", "duplicate", "aaguid", "repeat", "root_size", "root_count", "allow_count", "empty_allow"} {
		t.Run(fault, func(t *testing.T) {
			p := trustFixture(t)
			if err := ValidateInstalledAttestationPolicy(p, "demo", 1); err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "schema":
				p.Schema = "unknown"
			case "config":
				p.Config = "other"
			case "installation":
				p.InstallationGeneration++
			case "der":
				p.RootsDER[0] = []byte{0x30, 0x00}
			case "ca":
				p.RootsDER[0] = trustRoot(t, false, x509.KeyUsageCertSign, 0)
			case "usage":
				p.RootsDER[0] = trustRoot(t, true, x509.KeyUsageDigitalSignature, 0)
			case "duplicate":
				p.RootsDER = append(p.RootsDER, p.RootsDER[0])
			case "aaguid":
				p.AllowedAAGUIDs[0] = "ABCDEF00-0000-0000-0000-000000000000"
			case "repeat":
				p.AllowedAAGUIDs = append(p.AllowedAAGUIDs, p.AllowedAAGUIDs[0])
			case "root_size":
				p.RootsDER[0] = trustRoot(t, true, x509.KeyUsageCertSign, 66000)
			case "root_count":
				p.RootsDER = nil
				for i := 0; i < 33; i++ {
					p.RootsDER = append(p.RootsDER, trustRoot(t, true, x509.KeyUsageCertSign, 0))
				}
			case "allow_count":
				p.AllowedAAGUIDs = nil
				for i := 0; i < 257; i++ {
					p.AllowedAAGUIDs = append(p.AllowedAAGUIDs, fmt.Sprintf("%08x-0000-0000-0000-000000000000", i))
				}
			case "empty_allow":
				p.RootsDER = nil
			}
			contractCode(t, ValidateInstalledAttestationPolicy(p, "demo", 1), CodeInvalid, "installed attestation policy boundary was bypassed")
		})
	}
}

func TestTrustClone(t *testing.T) {
	p := trustFixture(t)
	copy := CloneInstalledAttestationPolicy(p)
	copy.RootsDER[0][0] ^= 1
	if copy.RootsDER[0][0] == p.RootsDER[0][0] {
		t.Fatal("trust policy clone exposed roots")
	}
	copy.AllowedAAGUIDs[0] = "11111111-0000-0000-0000-000000000000"
	if copy.AllowedAAGUIDs[0] == p.AllowedAAGUIDs[0] {
		t.Fatal("trust policy clone exposed allowlist")
	}
	closed := InstalledAttestationPolicy{Schema: p.Schema, Config: "demo", InstallationGeneration: 1}
	if err := ValidateInstalledAttestationPolicy(closed, "demo", 1); err != nil {
		t.Fatal("empty roots must remain an explicit closed policy", err)
	}
}
