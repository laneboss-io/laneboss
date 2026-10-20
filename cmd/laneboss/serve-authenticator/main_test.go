//go:build laneboss_e2e_authenticator

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/identity"
)

func keyFixture(t *testing.T) (*os.Root, options, descriptor, api.HumanChallengeRequest, api.HumanChallenge, time.Time) {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := openPrivate(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	input := options{Config: "fixture-human", Origin: "https://localhost", RPID: "localhost"}
	public, err := create(root, input)
	if err != nil {
		t.Fatal(err)
	}
	input.Mode, input.Method, input.Target = "sign", "human.session", string(public.PrincipalID)
	input.Origin, input.RPID = "", ""
	intent, err := operationIntent(input, []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	challenge := api.HumanChallenge{ID: "actual-challenge", Challenge: nonce, Config: input.Config,
		Method: intent.Method, TargetID: intent.TargetID, RequestSHA256: intent.RequestSHA256,
		BaseGeneration: intent.BaseGeneration, Origin: public.Origin, RPID: public.RPID,
		ExpiresAt: api.Timestamp(now.Add(time.Minute).Format(time.RFC3339Nano))}
	return root, input, public, intent, challenge, now
}

func challengeBytes(t *testing.T, value api.HumanChallenge) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestRealVerifierAndCounter(t *testing.T) {
	root, input, public, intent, challenge, now := keyFixture(t)
	var previous uint32
	for iteration := uint32(1); iteration <= 2; iteration++ {
		if _, err := rand.Read(challenge.Challenge); err != nil {
			t.Fatal(err)
		}
		assertion, err := sign(root, input, intent, challengeBytes(t, challenge), now)
		if err != nil {
			t.Fatal(err)
		}
		counter, err := identity.VerifyAssertion(challenge, public.CredentialID, public.PublicKeyDER, previous, assertion, now)
		if err != nil || counter != iteration {
			t.Fatal("real verifier refused fixture signature", err)
		}
		if _, err := identity.VerifyAssertion(challenge, public.CredentialID, public.PublicKeyDER, counter, assertion, now); err == nil {
			t.Fatal("same signature counter replay was accepted")
		}
		stored, err := readPrivate(root, "counter")
		if err != nil || len(stored) != 4 || binary.BigEndian.Uint32(stored) != counter {
			t.Fatal("signing counter was not retained")
		}
		previous = counter
		assertion.Signature[0] ^= 1
		if _, err := identity.VerifyAssertion(challenge, public.CredentialID, public.PublicKeyDER, previous-1, assertion, now); err == nil {
			t.Fatal("tampered signature was accepted")
		}
	}
}

func TestInvitedDevice(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := openPrivate(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	input := options{Config: "invited-human", Origin: "https://localhost", RPID: "localhost", Invited: true}
	public, err := create(root, input)
	if err != nil {
		t.Fatal(err)
	}
	if public.CredentialID == api.SoftwareAuthenticatorCredentialID || public.CredentialID != api.InvitedCredentialID(public.RawCredentialID) {
		t.Fatal("invited device reused the baseline identity")
	}
	input.Mode, input.Method, input.Target = "sign", "human.session", string(public.PrincipalID)
	input.Origin, input.RPID, input.Invited = "", "", false
	intent, err := operationIntent(input, []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	challenge := api.HumanChallenge{ID: "invited-challenge", Config: input.Config, Method: intent.Method, TargetID: intent.TargetID,
		RequestSHA256: intent.RequestSHA256, Origin: public.Origin, RPID: public.RPID, Challenge: make([]byte, 32), ExpiresAt: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))}
	if _, err := rand.Read(challenge.Challenge); err != nil {
		t.Fatal(err)
	}
	assertion, err := sign(root, input, intent, challengeBytes(t, challenge), time.Now())
	if err != nil {
		t.Fatal("invited device could not sign its own actual challenge", err)
	}
	if _, err := identity.VerifyAssertion(challenge, public.CredentialID, public.PublicKeyDER, 0, assertion, time.Now()); err != nil {
		t.Fatal("invited device signature did not verify", err)
	}
}

func TestSignerRejectsChangedIntent(t *testing.T) {
	for _, field := range []string{"config", "method", "target", "digest", "base", "origin", "rp", "expired"} {
		t.Run(field, func(t *testing.T) {
			root, input, _, intent, challenge, now := keyFixture(t)
			switch field {
			case "config":
				challenge.Config = "another-config"
			case "method":
				challenge.Method = "ticket.issue"
			case "target":
				challenge.TargetID = "another-principal"
			case "digest":
				challenge.RequestSHA256 = "different-digest"
			case "base":
				challenge.BaseGeneration++
			case "origin":
				challenge.Origin = "https://another.invalid"
			case "rp":
				challenge.RPID = "another.invalid"
			case "expired":
				challenge.ExpiresAt = api.Timestamp(now.Add(-time.Second).Format(time.RFC3339Nano))
			}
			if _, err := sign(root, input, intent, challengeBytes(t, challenge), now); err == nil {
				t.Fatal("changed challenge was signed")
			}
			counter, err := readPrivate(root, "counter")
			if err != nil || !bytes.Equal(counter, make([]byte, 4)) {
				t.Fatal("rejected intent changed counter")
			}
		})
	}
}

func TestPrivateKeyNeverEntersPublicOutput(t *testing.T) {
	root, _, public, _, _, _ := keyFixture(t)
	private, err := readPrivate(root, "key.der")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	output, err := json.Marshal(public)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(output, private) || bytes.Contains(output, []byte(base64.StdEncoding.EncodeToString(private))) || public.Enrolled {
		t.Fatal("private bytes or enrollment authority entered public output")
	}
	for _, name := range []string{"key.der", "counter", "public.json"} {
		info, err := root.Stat(name)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("authenticator state is not private")
		}
	}
}

func TestUnsafePrivateStateRefuses(t *testing.T) {
	root, input, _, intent, challenge, now := keyFixture(t)
	if err := os.Chmod(filepath.Join(root.Name(), "key.der"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := sign(root, input, intent, challengeBytes(t, challenge), now); err == nil {
		t.Fatal("shared private key was used")
	}
	if err := os.Chmod(filepath.Join(root.Name(), "key.der"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root.Name(), 0755); err != nil {
		t.Fatal(err)
	}
	if reopened, err := openPrivate(root.Name()); err == nil {
		reopened.Close()
		t.Fatal("shared private directory was accepted")
	}
	if err := os.Chmod(root.Name(), 0700); err != nil {
		t.Fatal(err)
	}
}
