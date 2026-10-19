package nativecase

import (
	"context"
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
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/identity"
	peerlinux "laneboss.io/laneboss/internal/v2/peer/linux"
)

// This controlled store records real identity transactions and proof/counter
// handoffs in memory. Native peers, socket writers and assertion cryptography
// are real; this does not claim the installed durable service/store adapter.
type nativeSessionStore struct {
	*nativeProjectionStore
	t         *testing.T
	challenge api.StoredChallenge
	proof     api.VerifiedHumanProof
	session   api.StoredReadSession
	commit    *identity.SessionCommit
	sequence  api.Sequence
	stale     bool
	reads     int
	private   int
}

func (s *nativeSessionStore) AuthorizationTarget(_ context.Context, _ api.Scope, _ api.Request) (api.HumanChallengeRequest, error) {
	if s.proof.Ref.ID == "" {
		return api.HumanChallengeRequest{}, &api.Error{Code: api.CodeNotFound}
	}
	return s.proof.Target, nil
}
func (s *nativeSessionStore) Challenge(_ context.Context, _ api.Scope, id api.ID) (api.StoredChallenge, error) {
	if id != s.challenge.Challenge.ID {
		return api.StoredChallenge{}, &api.Error{Code: api.CodeNotFound}
	}
	return s.challenge, nil
}
func (s *nativeSessionStore) Proof(_ context.Context, _ api.Scope, id api.ID) (api.VerifiedHumanProof, error) {
	if id != s.proof.Ref.ID {
		return api.VerifiedHumanProof{}, &api.Error{Code: api.CodeNotFound}
	}
	return s.proof, nil
}
func (s *nativeSessionStore) Transact(_ context.Context, tx api.Transaction) (api.Commit, error) {
	if err := api.ValidateTransactionShape(tx); err != nil {
		return api.Commit{}, err
	}
	s.sequence++
	operation := api.Operation{ID: nativeID(s.t), Status: "succeeded", FirstSeq: s.sequence, LastSeq: s.sequence}
	switch tx.Scope.Request.Method {
	case "human.challenge":
		if len(tx.Writes.Challenges) != 1 {
			return api.Commit{}, &api.Error{Code: api.CodeIntegrity}
		}
		s.challenge = tx.Writes.Challenges[0]
	case "human.confirm":
		if s.challenge.Consumed || len(tx.Writes.Challenges) != 1 || len(tx.Writes.Proofs) != 1 || len(tx.Writes.Counters) != 1 ||
			!tx.Writes.Challenges[0].Consumed || tx.Writes.Counters[0].Before != s.enrollment.Credentials[0].Counter ||
			tx.Writes.Counters[0].After <= tx.Writes.Counters[0].Before {
			return api.Commit{}, &api.Error{Code: api.CodeIntegrity}
		}
		s.challenge, s.proof = tx.Writes.Challenges[0], tx.Writes.Proofs[0]
		s.enrollment.Credentials[0].Counter = tx.Writes.Counters[0].After
		s.enrollment.Credentials[0].Generation++
	case "human.session":
		if len(tx.Writes.ReadSessions) != 1 || len(tx.Guards) != 1 || tx.Guards[0].Proof == nil || s.proof.ConsumedBy != "" ||
			tx.Guards[0].Proof.Proof != s.proof.Ref || tx.Guards[0].Proof.Target != s.proof.Target {
			return api.Commit{}, &api.Error{Code: api.CodeUnauthenticated}
		}
		s.session, s.proof.ConsumedBy = tx.Writes.ReadSessions[0], operation.ID
		s.commit = &identity.SessionCommit{Session: s.session, Enrollment: s.enrollment, Proof: s.proof,
			Receipt: api.MutationReceipt{Config: tx.Scope.Config, Actor: tx.Scope.Actor, PolicyGeneration: tx.Scope.PolicyGeneration,
				Key:        api.RequestKey{Method: tx.Scope.Request.Method, IdempotencyKey: tx.Scope.Request.IdempotencyKey, RequestSHA256: tx.Scope.Request.RequestSHA256},
				RawRequest: append([]byte(nil), tx.RawRequest...), Operation: operation, Reply: tx.Reply, FirstSeq: s.sequence, LastSeq: s.sequence,
				RecordedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}}
	default:
		return api.Commit{}, &api.Error{Code: api.CodeUnsupported}
	}
	return api.Commit{Operation: operation, Reply: tx.Reply, FirstSeq: s.sequence, LastSeq: s.sequence}, nil
}
func (s *nativeSessionStore) ReadSessionCommit(_ context.Context, _ api.Scope) (identity.SessionCommit, error) {
	s.private++
	if s.commit == nil {
		return identity.SessionCommit{}, &api.Error{Code: api.CodeNotFound}
	}
	result := *s.commit
	if s.stale {
		result.Session.Generation++
	}
	return result, nil
}
func (s *nativeSessionStore) ReadSession(ctx context.Context, scope api.Scope, id api.ID) (api.StoredReadSession, error) {
	s.reads++
	authority, err := scope.Connection.ReadAuthority(ctx)
	if err != nil {
		return api.StoredReadSession{}, err
	}
	if authority.SessionID != id || id != s.session.Session.ID || authority != api.ReadAuthorityFromSession(s.session) {
		return api.StoredReadSession{}, &api.Error{Code: api.CodeUnauthenticated}
	}
	return s.session, nil
}

func (s *nativeSessionStore) RefreshReadSession(ctx context.Context, scope api.Scope, request api.ReadSessionRefreshRequest) (api.StoredReadSession, error) {
	authority, err := scope.Connection.ReadAuthority(ctx)
	if err != nil {
		return api.StoredReadSession{}, err
	}
	if request.SessionID != s.session.Session.ID || request.ExpectedGeneration != s.session.Generation || authority != api.ReadAuthorityFromSession(s.session) {
		return api.StoredReadSession{}, &api.Error{Code: api.CodeConflict}
	}
	before, after := s.session, s.session
	now := time.Now().UTC()
	abs, err := time.Parse(time.RFC3339Nano, string(before.Session.ExpiresAt))
	if err != nil {
		return api.StoredReadSession{}, err
	}
	deadline := now.Add(5 * time.Minute)
	if abs.Before(deadline) {
		deadline = abs
	}
	after.Generation++
	after.Session.IdleExpiresAt = api.Timestamp(deadline.Format(time.RFC3339Nano))
	if err := api.ValidateReadSessionRefresh(scope, before, after, now); err != nil {
		return api.StoredReadSession{}, err
	}
	s.session = after
	return after, nil
}

func (c *nativeConnection) RefreshReadAuthority(_ context.Context, update api.ReadAuthorityUpdate) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return &api.Error{Code: api.CodeUnauthenticated}
	}
	if err := api.ValidateReadAuthorityUpdate(c.authority, update); err != nil {
		return err
	}
	c.authority = update.After
	return nil
}

func nativeSessionSetup(t *testing.T, store *nativeSessionStore, digest api.Digest) (*identity.Service, func() (api.Scope, *nativeConnection, *net.UnixConn)) {
	t.Helper()
	registry, err := peerlinux.NewRegistry()
	if err != nil {
		t.Fatalf("fixture setup: native registry unavailable: %v", err)
	}
	t.Cleanup(func() {
		if err := registry.Close(); err != nil {
			t.Error(err)
		}
	})
	peers, err := peerlinux.New(registry)
	if err != nil {
		t.Fatalf("fixture setup: native verifier unavailable: %v", err)
	}
	t.Cleanup(func() {
		if err := peers.Close(); err != nil {
			t.Error(err)
		}
	})
	service, err := identity.New(identity.Dependencies{Peers: peers, Registry: registry, Store: store, Sessions: store, Clock: nativeClock{}})
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "rpc")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := listener.Close(); err != nil {
			t.Error(err)
		}
	})
	raw, err := listener.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var optionErr error
	if err := raw.Control(func(fd uintptr) { optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1) }); err != nil || optionErr != nil {
		t.Fatalf("fixture setup: listening credentials unavailable: %v", errors.Join(err, optionErr))
	}
	return service, func() (api.Scope, *nativeConnection, *net.UnixConn) {
		if err := listener.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
			t.Fatal(err)
		}
		client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := client.Close(); err != nil {
				t.Error(err)
			}
		})
		server, err := listener.AcceptUnix()
		if err != nil {
			t.Fatal(err)
		}
		connection := &nativeConnection{id: nativeID(t), raw: server, binding: api.InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision,
			Protocol: api.Protocol, APISchema: api.SchemaVersion, Config: "fixture", Class: api.EndpointHuman,
			InstallationGeneration: 1, EndpointGeneration: 1, ServiceUID: 1234, ServiceGID: 1234, Socket: path,
			ArtifactSHA256: digest, ServiceVersion: "fixture", Backend: "linux-bwrap-landlock"}}
		t.Cleanup(func() {
			if err := connection.Close(); err != nil {
				t.Error(err)
			}
		})
		if err := server.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if err := client.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
			t.Fatal(err)
		}
		scope, err := service.Authenticate(context.Background(), connection)
		if err != nil {
			t.Fatalf("fixture setup: native human authentication failed: %v", err)
		}
		return scope, connection, client
	}
}

func nativeSessionFrame(t *testing.T, scope api.Scope, connection *nativeConnection, client *net.UnixConn, request api.Request) api.Scope {
	t.Helper()
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	wire := make([]byte, 4, len(payload)+4)
	binary.BigEndian.PutUint32(wire, uint32(len(payload)))
	wire = append(wire, payload...)
	if n, err := client.Write(wire); err != nil || n != len(wire) {
		t.Fatalf("fixture setup: native session frame write failed: %v", err)
	}
	scope.Frame, scope.Request, scope.Source = nativeReadFrame(t, connection), request, "cli"
	return scope
}

func nativeSessionRequest(t *testing.T, method api.Method, body any) api.Request {
	t.Helper()
	params, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: "fixture", Method: method, Params: params, RequestID: nativeID(t), IdempotencyKey: nativeID(t)}
	request.RequestSHA256, err = api.RequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func TestNativeSession(t *testing.T) {
	for _, rule := range []string{"current", "stale", "foreign"} {
		t.Run(rule, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			public, err := x509.MarshalPKIXPublicKey(key.Public())
			if err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256(public)
			principal, credential := nativeID(t), nativeID(t)
			store := &nativeSessionStore{t: t, nativeProjectionStore: &nativeProjectionStore{enrollment: api.HumanEnrollment{Config: "fixture", PrincipalID: principal,
				Origin: "https://fixture.example", RPID: "fixture.example", Generation: 1,
				Credentials: []api.HumanCredential{{ID: credential, RawCredentialID: hash[:], PublicKeyDER: public, Algorithm: "ES256", Counter: 10, Generation: 1}}}}}
			service, connect := nativeSessionSetup(t, store, api.Digest(hex.EncodeToString(hash[:])))
			scope, connection, client := connect()
			sessionRequest := nativeSessionRequest(t, "human.session", api.HumanSessionRequest{})
			target := api.HumanChallengeRequest{Method: "human.session", TargetID: "root", RequestSHA256: sessionRequest.RequestSHA256, BaseGeneration: 1}
			scope = nativeSessionFrame(t, scope, connection, client, nativeSessionRequest(t, "human.challenge", target))
			challenge, err := service.HumanChallenge(context.Background(), scope, target)
			if err != nil {
				t.Fatalf("fixture setup: native challenge failed: %v", err)
			}
			clientData, err := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": base64.RawURLEncoding.EncodeToString(challenge.Challenge), "origin": challenge.Origin, "crossOrigin": false})
			if err != nil {
				t.Fatal(err)
			}
			rp := sha256.Sum256([]byte(challenge.RPID))
			auth := make([]byte, 37)
			copy(auth, rp[:])
			auth[32] = 5
			binary.BigEndian.PutUint32(auth[33:], 11)
			clientHash := sha256.Sum256(clientData)
			signed := append(append([]byte(nil), auth...), clientHash[:]...)
			signingHash := sha256.Sum256(signed)
			signature, err := ecdsa.SignASN1(rand.Reader, key, signingHash[:])
			if err != nil {
				t.Fatal(err)
			}
			assertion := api.HumanConfirmRequest{ChallengeID: challenge.ID, CredentialID: credential, ClientDataJSON: clientData, AuthenticatorData: auth, Signature: signature}
			scope = nativeSessionFrame(t, scope, connection, client, nativeSessionRequest(t, "human.confirm", assertion))
			proof, err := service.HumanConfirm(context.Background(), scope, assertion)
			if err != nil {
				t.Fatalf("fixture setup: native assertion verification failed: %v", err)
			}
			sessionRequest.Proof = &proof
			scope = nativeSessionFrame(t, scope, connection, client, sessionRequest)
			store.stale = rule == "stale"
			session, err := service.HumanSession(context.Background(), scope, api.HumanSessionRequest{})
			if rule == "foreign" {
				if err != nil {
					t.Fatalf("fixture setup: original session failed: %v", err)
				}
				other, otherConnection, otherClient := connect()
				other = nativeSessionFrame(t, other, otherConnection, otherClient, sessionRequest)
				session, err = service.FinalizeHumanSession(context.Background(), other)
				connection = otherConnection
			}
			if rule != "current" {
				if connection.readAttempts != 0 {
					t.Fatalf("fixture check: native %s session reached transport binding", rule)
				}
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != api.CodeUnauthenticated {
					t.Fatalf("fixture check: native %s session was not refused: %v", rule, err)
				}
				if session != (api.HumanSession{}) || connection.authority.SessionID != "" {
					t.Fatal("fixture check: stale or foreign native session gained authority")
				}
				return
			}
			if err != nil || session.ID == "" || store.private != 1 || store.reads != 0 || store.proof.ConsumedBy == "" {
				t.Fatalf("fixture check: native same-socket session finalization failed: %v", err)
			}
			scope = nativeSessionFrame(t, scope, connection, client, nativeSessionRequest(t, "identity.self", api.Empty{}))
			if err := service.Authorize(context.Background(), scope, scope.Request); err != nil {
				t.Fatalf("fixture check: native first read was not authorized: %v", err)
			}
			view, err := service.IdentitySelf(context.Background(), scope, api.Empty{})
			if err != nil || view.Actor.ID != principal || store.reads != 2 || store.enrollment.Credentials[0].Counter != 11 ||
				view.Connection != nil || view.ReadAuthority != nil {
				t.Fatalf("fixture check: native same socket could not perform the first public read: %v", err)
			}
		})
	}
}
