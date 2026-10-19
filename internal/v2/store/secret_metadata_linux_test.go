//go:build linux

package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	release "laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/identity"
	"laneboss.io/laneboss/internal/v2/secrets"
	"laneboss.io/laneboss/internal/v2/secrets/native"
)

type metadataCase struct {
	state         *Service
	secrets       *secrets.Service
	backend       *native.Service
	human         api.Scope
	session       api.StoredReadSession
	identities    *identity.Service
	proofTemplate api.VerifiedHumanProof
}

// Enrollment, session authority and verified assertions are explicit component
// inputs. Mutations, events, snapshots and encrypted records use actual owners.
// This is neither a hardware ceremony nor installed-service acceptance.
func newMetadataCase(t *testing.T) *metadataCase {
	t.Helper()
	s, scope, session := sessionFixture(t)
	scope.PolicyGeneration = 1
	i, err := identity.New(identity.Dependencies{Peers: &sessionPeerTripwire{}, Registry: &sessionRegistryTripwire{}, Store: s, Sessions: s, Clock: s.deps.Clock})
	if err != nil {
		t.Fatal(err)
	}
	connection := scope.Connection.(*scopeConnection)
	connection.binding = api.InstalledBinding{Schema: "laneboss.binding.v2", Protocol: api.Protocol, APISchema: api.SchemaVersion, ContractRevision: api.ContractRevision,
		Config: s.deps.Config, Class: api.EndpointHuman, InstallationGeneration: 1, EndpointGeneration: scope.EndpointGeneration,
		ServiceUID: uint32(os.Geteuid()), ServiceGID: uint32(os.Getegid()), Socket: "/run/fixture/metadata.sock", ServiceVersion: release.Version,
		ArtifactSHA256: testDigest([]byte("metadata component binding")), Backend: "linux-bwrap-landlock"}
	// Retain synthetic assertion input through a real causal object write. The
	// older session fixture seeds an orphan object and cannot certify Verify.
	setup := api.Scope{Config: s.deps.Config, Actor: api.Actor{Kind: "service", ID: testID(t)}, Source: "service"}
	input := []byte("verified component assertion " + string(testID(t)))
	object := api.ObjectWrite{ObjectKey: testID(t), Class: "artifact", Bytes: input, SHA256: testDigest(input), Origin: "service",
		ACL: api.ObjectACL{Config: s.deps.Config, Owner: setup.Actor, Audience: "owner", Generation: 1}}
	intent := api.InternalIntent{ID: testID(t), Kind: api.InternalOrgBootstrap, Config: s.deps.Config, Actor: setup.Actor, RequestedBy: setup.Actor}
	policy := api.EffectivePolicy{Generation: 1, SHA256: testDigest([]byte("metadata component policy"))}
	if _, err := s.Transact(context.Background(), api.Transaction{Scope: setup, Internal: &intent, Writes: api.StateWrites{Objects: []api.ObjectWrite{object}, Policy: &policy}}); err != nil {
		t.Fatal(err)
	}
	metadata, _, err := objectRow(context.Background(), s.db, object.ObjectKey)
	if err != nil {
		t.Fatal(err)
	}
	proof := api.VerifiedHumanProof{Config: s.deps.Config, PrincipalID: scope.Actor.ID, CredentialID: session.CredentialID, NonceID: testID(t),
		ConnectionID: connection.ID(), EndpointClass: api.EndpointHuman, EndpointGeneration: scope.EndpointGeneration, AssertionEvidence: metadata.Ref}
	directory := filepath.Join(s.deps.Directory, "secret-records")
	b, err := native.New(native.Dependencies{Directory: directory, Config: s.deps.Config, KeyHandle: "metadata-key", Clock: s.deps.Clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := b.Close(); err != nil {
			t.Error(err)
		}
	})
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	if err := b.Unlock(context.Background(), "metadata-key", bytes.NewReader(key)); err != nil {
		t.Fatal(err)
	}
	module, err := secrets.New(secrets.Dependencies{Config: s.deps.Config, Backend: b, Store: s, Human: i, ProjectionIdentity: i, Clock: s.deps.Clock})
	if err != nil {
		t.Fatal(err)
	}
	return &metadataCase{state: s, secrets: module, backend: b, human: scope, session: session, identities: i, proofTemplate: proof}
}

func (c *metadataCase) scope(t *testing.T, method api.Method, body any, confirmed bool) api.Scope {
	t.Helper()
	scope := c.human
	scope.Request = testRequest(t, method, body)
	scope.Frame = &sessionCommitFrame{raw: enrollmentJSON(t, scope.Request)}
	if confirmed {
		target, err := c.state.AuthorizationTarget(context.Background(), scope, scope.Request)
		if err != nil {
			t.Fatal(err)
		}
		proof := c.proofTemplate
		// A verified assertion is fixture input, as in the session fixture.
		// This does not perform or credit another human confirmation.
		proof.ConsumedBy, proof.Target = "", target
		proof.VerifiedAt = api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))
		proof.Ref = api.ProofRef{ID: testID(t), RequestSHA256: scope.Request.RequestSHA256,
			ExpiresAt: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))}
		fixtureProjection(t, c.state, "proof", proof.Ref.ID, 1, proof)
		scope.Request.Proof = &proof.Ref
	}
	scope.Frame = &sessionCommitFrame{raw: enrollmentJSON(t, scope.Request)}
	return scope
}

func (c *metadataCase) importSecret(t *testing.T, name string, value []byte) api.SecretInfo {
	t.Helper()
	stage := c.stageSecret(t, name, "one", value)
	request := api.SecretImportRequest{Name: name, Version: "one", SealedUploadID: stage.ID}
	scope := c.scope(t, "secret.import", request, true)
	info, err := c.secrets.SecretImport(context.Background(), scope, request)
	if err != nil {
		t.Fatal("real-store secret import failed", err)
	}
	replayed, err := c.secrets.SecretImport(context.Background(), scope, request)
	if err != nil || replayed != info {
		t.Fatal("real-store secret import replay changed its original source", err)
	}
	return info
}

func (c *metadataCase) stageSecret(t *testing.T, name, version string, value []byte) api.SecretStage {
	t.Helper()
	ctx := context.Background()
	key, err := c.secrets.SecretKey(ctx, c.scope(t, "secret.key", api.Empty{}, false), api.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := secrets.SealStage(c.state.deps.Config, key, name, version, api.SecretMaterial{Bytes: value}, c.state.deps.Clock)
	if err != nil {
		t.Fatal(err)
	}
	stage, err := c.secrets.SecretStage(ctx, c.scope(t, "secret.stage", sealed, false), sealed)
	if err != nil {
		t.Fatal(err)
	}
	return stage
}

func TestSecretMetadataRealStore(t *testing.T) {
	c := newMetadataCase(t)
	scope := c.scope(t, "secret.list", api.Empty{}, false)
	empty, err := c.secrets.SecretList(context.Background(), scope, api.Empty{})
	if err != nil || empty.Secrets == nil || len(empty.Secrets) != 0 {
		t.Fatal("empty real-store secret inventory failed", err)
	}
	value := make([]byte, 73)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	defer clear(value)
	info := c.importSecret(t, "metadata.canary", value)
	for range 2 {
		actual, err := c.secrets.SecretList(context.Background(), scope, api.Empty{})
		if err != nil || !reflect.DeepEqual(actual.Secrets, []api.SecretInfo{info}) {
			t.Fatal("metadata list lost its committed source or exact replay", err)
		}
		encoded, err := json.Marshal(actual)
		if err != nil || bytes.Contains(encoded, value) {
			t.Fatal("metadata list exposed material")
		}
	}
	stage := c.stageSecret(t, info.Name, "two", []byte(testID(t)))
	rotation := api.SecretRotateRequest{Name: info.Name, ExpectedVersion: info.Version, SealedUploadID: stage.ID}
	rotateScope := c.scope(t, "secret.rotate", rotation, true)
	rotated, err := c.secrets.SecretRotate(context.Background(), rotateScope, rotation)
	if err != nil || rotated.SourceHandle == info.SourceHandle || rotated.Version != "two" {
		t.Fatal("real-store rotation lost its new immutable source", err)
	}
	if again, err := c.secrets.SecretRotate(context.Background(), rotateScope, rotation); err != nil || again != rotated {
		t.Fatal("real-store rotation replay changed its source", err)
	}
	listed, err := c.secrets.SecretList(context.Background(), scope, api.Empty{})
	if err != nil || !reflect.DeepEqual(listed.Secrets, []api.SecretInfo{rotated}) {
		t.Fatal("human metadata list retained a stale rotation head", err)
	}
	info = rotated
	request := api.SecretRevokeRequest{Name: info.Name, ExpectedVersion: info.Version}
	if _, err := c.secrets.SecretRevoke(context.Background(), c.scope(t, "secret.revoke", request, true), request); err != nil {
		t.Fatal(err)
	}
	actual, err := c.secrets.SecretList(context.Background(), scope, api.Empty{})
	info.Revoked = true
	if err != nil || !reflect.DeepEqual(actual.Secrets, []api.SecretInfo{info}) {
		t.Fatal("metadata list omitted its committed revocation", err)
	}
	files, err := os.ReadDir(filepath.Join(c.state.deps.Directory, "secret-records"))
	if err != nil || len(files) == 0 {
		t.Fatal("real encrypted source was not retained", err)
	}
	verified, err := c.state.Verify(context.Background(), api.VerifyRequest{Scope: "all"})
	if err != nil || !verified.OK {
		t.Fatal("secret metadata corrupted the durable store", err)
	}
}

func TestSecretMetadataRealStoreFences(t *testing.T) {
	for _, fault := range []string{"foreign", "stale-session", "revoked-session", "uncommitted-source", "locked"} {
		t.Run(fault, func(t *testing.T) {
			c := newMetadataCase(t)
			scope := c.scope(t, "secret.list", api.Empty{}, false)
			want := api.CodeUnauthenticated
			switch fault {
			case "foreign":
				scope.Config = "other"
			case "stale-session":
				c.session.Generation++
				fixtureProjection(t, c.state, "read_session", c.session.Session.ID, c.session.Generation, c.session)
				want = api.CodeConflict
			case "revoked-session":
				c.session.Revoked = true
				fixtureProjection(t, c.state, "read_session", c.session.Session.ID, c.session.Generation, c.session)
			case "uncommitted-source":
				published := c.importSecret(t, "partially-rotated", []byte(testID(t)))
				if _, err := c.backend.Store(context.Background(), api.SecretInfo{Name: published.Name, Version: "two"}, api.SecretMaterial{Bytes: []byte(testID(t))}); err != nil {
					t.Fatal(err)
				}
				want = api.CodeConflict
			case "locked":
				c.backend.Lock()
				want = api.CodePrerequisite
			}
			actual, err := c.secrets.SecretList(context.Background(), scope, api.Empty{})
			expectCode(t, err, want)
			if len(actual.Secrets) != 0 {
				t.Fatal("refused metadata returned source names")
			}
		})
	}
}

func TestSecretMetadataPrivateEnrollment(t *testing.T) {
	c := newMetadataCase(t)
	info := c.importSecret(t, "published", []byte(testID(t)))
	private, err := c.backend.Store(context.Background(), api.SecretInfo{Name: "admin-profile-source", Version: "one"}, api.SecretMaterial{Bytes: []byte(testID(t))})
	if err != nil {
		t.Fatal(err)
	}
	actual, err := c.secrets.SecretList(context.Background(), c.scope(t, "secret.list", api.Empty{}, false), api.Empty{})
	if err != nil || !reflect.DeepEqual(actual.Secrets, []api.SecretInfo{info}) {
		t.Fatal("unpublished private enrollment blocked or leaked into the public secret inventory", err)
	}
	var meta secretMetadata
	if err := storedProjection(context.Background(), c.state.db, "secret_source", private.SourceHandle, &meta); err == nil {
		t.Fatal("metadata read published an uncommitted enrollment")
	}
}

func TestSecretMutationRequestFence(t *testing.T) {
	for _, fault := range []string{"stale-base", "foreign-name", "missing-event"} {
		t.Run(fault, func(t *testing.T) {
			c := newMetadataCase(t)
			info := c.importSecret(t, "request-fence", []byte(testID(t)))
			request := api.SecretRevokeRequest{Name: info.Name, ExpectedVersion: info.Version}
			if fault == "stale-base" {
				request.ExpectedVersion = "retired"
			}
			if fault == "foreign-name" {
				request.Name = "foreign"
			}
			scope := c.scope(t, "secret.revoke", request, true)
			target, err := c.state.AuthorizationTarget(context.Background(), scope, scope.Request)
			if err != nil {
				t.Fatal(err)
			}
			event := api.Event{Schema: api.SchemaVersion, ID: testID(t), Config: scope.Config, Kind: "secret.revoked", Actor: scope.Actor, RequestedBy: scope.Actor, Origin: "service", StarterChain: []api.ID{},
				Payload: enrollmentJSON(t, api.SecretEvent{Names: []string{info.Name}, Versions: []string{info.Version}, GrantIDs: []api.ID{}, KeyID: info.KeyID, Outcome: "revoked"})}
			input := api.Transaction{Scope: scope, RawRequest: scope.Frame.Bytes(), Reply: &api.RPCReply{Result: enrollmentJSON(t, api.Operation{})}, Events: []api.Event{event},
				Guards: []api.TransactionGuard{{Proof: &api.ProofUse{Proof: *scope.Request.Proof, Target: target}}}}
			if fault == "missing-event" {
				input.Events = nil
			}
			if _, err := c.state.Transact(context.Background(), input); err == nil {
				t.Fatal("secret writer accepted metadata outside its exact mutation intent")
			}
			var retained secretMetadata
			if err := storedProjection(context.Background(), c.state.db, "secret_head", secretNameID(info.Name), &retained); err != nil || retained.Info != info {
				t.Fatal("refused metadata mutation changed its committed source", err)
			}
			var proof api.VerifiedHumanProof
			if err := storedProjection(context.Background(), c.state.db, "proof", scope.Request.Proof.ID, &proof); err != nil || proof.ConsumedBy != "" {
				t.Fatal("refused metadata mutation consumed its proof", err)
			}
		})
	}
}

func TestSecretMetadataProjectionIntegrity(t *testing.T) {
	c := newMetadataCase(t)
	info := c.importSecret(t, "integrity-source", []byte(testID(t)))
	var head secretMetadata
	if err := storedProjection(context.Background(), c.state.db, "secret_head", secretNameID(info.Name), &head); err != nil {
		t.Fatal(err)
	}
	head.Info.Version = "forged"
	// Simulate damaged protected metadata including its generic checksum
	// history. Only reconstruction from the immutable secret journal can catch
	// this; no production port accepts this fixture mutation.
	fixtureProjection(t, c.state, "secret_head", secretNameID(info.Name), head.Generation+1, head)
	verification, err := c.state.Verify(context.Background(), api.VerifyRequest{Scope: "all"})
	if err == nil || verification.OK {
		t.Fatal("state verification accepted secret metadata outside its immutable journal")
	}
	expectCode(t, err, api.CodeIntegrity)
}
