//go:build linux

package service

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	release "laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/identity"
	"laneboss.io/laneboss/internal/v2/identity/input"
	"laneboss.io/laneboss/internal/v2/store"
)

// Registration attestation, confirmation signatures, identity, dispatch and
// store commits are real. Prior-state intake and native peer facts are explicit
// component boundaries; this does not claim an installed hardware ceremony.
func TestEdRegistrationConfirm(t *testing.T) {
	edConfirmation(t, false)
}

func TestEdLegacyConfirm(t *testing.T) {
	edConfirmation(t, true)
}

func edConfirmation(t *testing.T, legacy bool) {
	t.Helper()
	ctx := context.Background()
	directory := privateHostDirectory(t)
	state, err := store.New(store.Dependencies{Config: "service-fixture", Directory: directory, Clock: fixtureClock{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := state.Close(); err != nil {
			t.Error(err)
		}
	})
	actor := api.Actor{Kind: "human", ID: fixtureID(t)}
	registration := testinput.EdRegistration(t, "service-fixture", actor.ID, fixtureClock{})
	enrollment := registration.Install.Enrollment
	credential := enrollment.Credentials[0]
	// The primary case preserves the producer's exact label on a RED tree.
	// The second case models a retained legacy row, with the same actual key.
	if legacy {
		enrollment.Credentials[0].Algorithm = "Ed25519"
	}
	grantsFlowProjection(t, directory, "enrollment", actor.ID, enrollment)
	binding := api.InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision,
		Protocol: api.Protocol, APISchema: api.SchemaVersion, Config: enrollment.Config, Class: api.EndpointHuman,
		InstallationGeneration: 1, EndpointGeneration: 1, ServiceVersion: release.Version,
		ServiceUID: uint32(os.Geteuid()), ServiceGID: uint32(os.Getegid()), Socket: filepath.Join(directory, "human.sock"),
		ArtifactSHA256: digestBytes([]byte("Ed registration component")), Backend: "linux-bwrap-landlock"}
	a, b := net.Pipe()
	connection, err := newConnection(a, binding, fixtureClock{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { connection.Close(); b.Close() })
	setup := api.Scope{Config: binding.Config, Actor: api.Actor{Kind: "service", ID: fixtureID(t)}, Source: "service"}
	intent := api.InternalIntent{ID: fixtureID(t), Kind: api.InternalOrgBootstrap, Config: setup.Config, Actor: setup.Actor, RequestedBy: setup.Actor}
	policy := api.EffectivePolicy{Generation: 1, SHA256: digestBytes([]byte("Ed registration policy"))}
	if _, err := state.Transact(ctx, api.Transaction{Scope: setup, Internal: &intent, Writes: api.StateWrites{Policy: &policy}}); err != nil {
		t.Fatal(err)
	}
	auth := &authFixture{scope: api.Scope{Config: binding.Config, Actor: actor, EndpointGeneration: 1, PolicyGeneration: 1}}
	if _, err := auth.Authenticate(ctx, connection); err != nil {
		t.Fatal(err)
	}
	identities, err := identity.New(identity.Dependencies{Peers: &grantsFlowPorts{}, Registry: &grantsFlowPorts{}, Store: state, Sessions: state, Clock: fixtureClock{}})
	if err != nil {
		t.Fatal(err)
	}
	host := fixtureServer(t)
	host.deps.Store, host.deps.Binding = state, binding
	host.deps.Authenticator = grantsFlowAuth{authFixture: auth, identity: identities}
	if err := identities.Register(host); err != nil {
		t.Fatal(err)
	}
	call := func(method api.Method, body any, result any) api.Scope {
		t.Helper()
		request := requestFor(t, method, body)
		frame := sessionDispatchFrame{raw: fixtureJSON(t, request)}
		raw, scope, err := host.dispatch(context.WithValue(ctx, requestFrameKey{}, api.FrameContext(frame)), connection, request)
		if err != nil {
			t.Fatalf("production registration %s failed: %v", method, err)
		}
		if err := wire.Decode(raw, result); err != nil {
			t.Fatal(err)
		}
		return scope
	}
	intentRequest := requestFor(t, "human.session", api.HumanSessionRequest{})
	target := api.HumanChallengeRequest{Method: intentRequest.Method, TargetID: actor.ID, RequestSHA256: intentRequest.RequestSHA256}
	var challenge api.HumanChallenge
	call("human.challenge", target, &challenge)
	client, err := json.Marshal(map[string]any{"type": "webauthn.get", "origin": enrollment.Origin,
		"challenge": base64.RawURLEncoding.EncodeToString(challenge.Challenge), "crossOrigin": false})
	if err != nil {
		t.Fatal(err)
	}
	authData := make([]byte, 37)
	rp := sha256.Sum256([]byte(enrollment.RPID))
	copy(authData, rp[:])
	authData[32] = 0x05
	binary.BigEndian.PutUint32(authData[33:], 1)
	clientHash := sha256.Sum256(client)
	confirmation := api.HumanConfirmRequest{ChallengeID: challenge.ID, CredentialID: credential.ID, ClientDataJSON: client,
		AuthenticatorData: authData, Signature: ed25519.Sign(registration.Private, append(append([]byte(nil), authData...), clientHash[:]...))}
	var proof api.ProofRef
	scope := call("human.confirm", confirmation, &proof)
	stored, err := state.Proof(ctx, scope, proof.ID)
	if err != nil || stored.Ref != proof || stored.CredentialID != credential.ID || stored.PrincipalID != actor.ID {
		t.Fatal("real confirmation did not retain its exact credential proof", err)
	}
	actual, err := state.Enrollment(ctx, scope)
	if err != nil || actual.Credentials[0].Algorithm != "EdDSA" || actual.Credentials[0].Counter != 1 {
		t.Fatal("confirmation lost its canonical key or signature counter", err)
	}
}
