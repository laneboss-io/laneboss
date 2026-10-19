package nativecase

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/identity"
	peerlinux "laneboss.io/laneboss/internal/v2/peer/linux"
)

// Supporting kernel composition fixture only. Enrollment/policy are controlled
// store projections here; this is not the installed serve caller or acceptance.
type nativeProjectionStore struct {
	api.StateStore
	enrollment api.HumanEnrollment
}

func (s *nativeProjectionStore) Enrollment(ctx context.Context, scope api.Scope) (api.HumanEnrollment, error) {
	if scope.Connection == nil || scope.Connection.Peer() == nil {
		return api.HumanEnrollment{}, &api.Error{Code: api.CodeUnauthenticated}
	}
	if _, err := scope.Connection.Peer().Facts(ctx); err != nil {
		return api.HumanEnrollment{}, err
	}
	return s.enrollment, nil
}
func (s *nativeProjectionStore) Policy(ctx context.Context, scope api.Scope) (api.EffectivePolicy, error) {
	if scope.Config != s.enrollment.Config || scope.Connection == nil || scope.Connection.Peer() == nil {
		return api.EffectivePolicy{}, &api.Error{Code: api.CodeUnauthenticated}
	}
	if err := scope.Connection.Peer().Alive(ctx); err != nil {
		return api.EffectivePolicy{}, err
	}
	return api.EffectivePolicy{Generation: s.enrollment.Generation}, nil
}

func (s *nativeProjectionStore) HumanPolicyGeneration(ctx context.Context, connection api.ConnectionContext, principal api.ID) (api.Generation, error) {
	if connection == nil || connection.Peer() == nil || connection.Binding().Class != api.EndpointHuman ||
		connection.Binding().Config != s.enrollment.Config || principal != s.enrollment.PrincipalID || s.enrollment.Generation == 0 {
		return 0, &api.Error{Code: api.CodeUnauthenticated}
	}
	policy, err := s.Policy(ctx, api.Scope{Connection: connection, Config: s.enrollment.Config,
		Actor: api.Actor{Kind: "human", ID: principal}})
	return policy.Generation, err
}

type nativeClock struct{}

func (nativeClock) Now() time.Time { return time.Now().UTC() }

type nativeConnection struct {
	mu           sync.Mutex
	id           api.ID
	raw          *net.UnixConn
	binding      api.InstalledBinding
	peer         api.VerifiedPeer
	authority    api.ReadAuthority
	readAttempts int
	closed       bool
}

func (c *nativeConnection) ID() api.ID                    { return c.id }
func (c *nativeConnection) Conn() net.Conn                { return c.raw }
func (c *nativeConnection) Binding() api.InstalledBinding { return c.binding }
func (c *nativeConnection) Peer() api.VerifiedPeer        { c.mu.Lock(); defer c.mu.Unlock(); return c.peer }
func (c *nativeConnection) BindPeer(peer api.VerifiedPeer) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || peer == nil || c.peer != nil {
		return &api.Error{Code: api.CodeConflict}
	}
	c.peer = peer
	return nil
}
func (c *nativeConnection) BindReadAuthority(authority api.ReadAuthority) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readAttempts++
	if c.closed || c.peer == nil || c.authority.SessionID != "" || authority.ConnectionID == "" || authority.ConnectionID != c.ID() ||
		authority.Config != c.binding.Config || authority.EndpointGeneration != c.binding.EndpointGeneration {
		return &api.Error{Code: api.CodeUnauthenticated}
	}
	c.authority = authority
	return nil
}
func (c *nativeConnection) ReadAuthority(context.Context) (api.ReadAuthority, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.authority.SessionID == "" {
		return api.ReadAuthority{}, &api.Error{Code: api.CodeUnauthenticated}
	}
	return c.authority, nil
}
func (c *nativeConnection) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	peer := c.peer
	c.mu.Unlock()
	var err error
	if peer != nil {
		err = peer.Close()
	}
	return errors.Join(err, c.raw.Close())
}

type nativeFrame struct {
	raw        []byte
	writers    []unix.Ucred
	connection api.ID
}

func (f *nativeFrame) Bytes() []byte { return append([]byte(nil), f.raw...) }
func (f *nativeFrame) Verify(ctx context.Context, connection api.ConnectionContext) error {
	if f.connection != connection.ID() || len(f.writers) == 0 {
		return &api.Error{Code: api.CodeUnauthenticated}
	}
	facts, err := connection.Peer().Facts(ctx)
	if err != nil {
		return err
	}
	for _, writer := range f.writers {
		if int(writer.Pid) != facts.HostPID || writer.Uid != facts.HostUID || writer.Gid != facts.HostGID {
			return &api.Error{Code: api.CodeUnauthenticated}
		}
	}
	return connection.Peer().Alive(ctx)
}

func nativeID(t *testing.T) api.ID {
	t.Helper()
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		t.Fatal(err)
	}
	return api.ID(hex.EncodeToString(value[:]))
}

func nativeReadFrame(t *testing.T, connection *nativeConnection) *nativeFrame {
	t.Helper()
	frame := &nativeFrame{connection: connection.ID()}
	var wire []byte
	want := 4
	for len(wire) < want {
		data := make([]byte, want-len(wire))
		control := make([]byte, unix.CmsgSpace(unix.SizeofUcred)+unix.CmsgSpace(4))
		n, count, flags, _, err := connection.raw.ReadMsgUnix(data, control)
		if err != nil || n <= 0 {
			t.Fatalf("fixture setup: credential recvmsg failed: %v", err)
		}
		messages, err := unix.ParseSocketControlMessage(control[:count])
		if err != nil {
			t.Fatalf("fixture setup: invalid control data: %v", err)
		}
		var credential *unix.Ucred
		unexpected := flags&^unix.MSG_CMSG_CLOEXEC != 0
		for _, message := range messages {
			if message.Header.Level == unix.SOL_SOCKET && message.Header.Type == unix.SCM_RIGHTS {
				fds, err := unix.ParseUnixRights(&message)
				if err != nil {
					t.Fatalf("fixture setup: rights decode failed: %v", err)
				}
				for _, fd := range fds {
					if err := unix.Close(fd); err != nil {
						t.Fatal(err)
					}
				}
				unexpected = true
			} else if message.Header.Level == unix.SOL_SOCKET && message.Header.Type == unix.SCM_CREDENTIALS && credential == nil {
				credential, err = unix.ParseUnixCredentials(&message)
				if err != nil {
					t.Fatalf("fixture setup: credentials decode failed: %v", err)
				}
			} else {
				unexpected = true
			}
		}
		if unexpected || credential == nil || len(messages) != 1 {
			t.Fatal("fixture setup: missing, truncated or extra frame credentials")
		}
		frame.writers = append(frame.writers, *credential)
		wire = append(wire, data[:n]...)
		if len(wire) == 4 {
			size := binary.BigEndian.Uint32(wire)
			if size == 0 || size > api.MaxFrameBytes {
				t.Fatal("fixture setup: invalid native frame bound")
			}
			want = 4 + int(size)
		}
	}
	frame.raw = append([]byte(nil), wire[4:]...)
	return frame
}

func TestNativeAuthentication(t *testing.T) {
	registry, err := peerlinux.NewRegistry()
	if err != nil {
		t.Fatalf("fixture setup: cgroup v2 unavailable: %v", err)
	}
	t.Cleanup(func() {
		if err := registry.Close(); err != nil {
			t.Error(err)
		}
	})
	peers, err := peerlinux.New(registry)
	if err != nil {
		t.Fatalf("fixture check: native peer constructor refused the kernel: %v", err)
	}
	t.Cleanup(func() {
		if err := peers.Close(); err != nil {
			t.Error(err)
		}
	})
	store := &nativeProjectionStore{}
	service, err := identity.New(identity.Dependencies{Peers: peers, Registry: registry, Store: store, Clock: nativeClock{}})
	if err != nil {
		t.Fatalf("fixture check: real peer dependency did not construct identity: %v", err)
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "rpc")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("fixture setup: Unix listener failed: %v", err)
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
	if err := listener.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var previous api.ID
	for index := 0; index < 2; index++ {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(public)
		principal := api.ID(hex.EncodeToString(sum[:16]))
		store.enrollment = api.HumanEnrollment{Config: "fixture", PrincipalID: principal, Origin: "https://fixture.example", RPID: "fixture.example", Generation: api.Generation(index + 1),
			Credentials: []api.HumanCredential{{ID: principal, RawCredentialID: sum[:], PublicKeyDER: public, Algorithm: "ES256", Generation: 1}}}
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
			InstallationGeneration: 1, EndpointGeneration: 1, ServiceUID: 1234, ServiceGID: 1234,
			Socket: path, ArtifactSHA256: api.Digest(hex.EncodeToString(sum[:])), ServiceVersion: "fixture", Backend: "linux-bwrap-landlock"}}
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
			t.Fatalf("fixture check: native authentication failed: %v", err)
		}
		facts, err := connection.Peer().Facts(context.Background())
		if err != nil || facts.HostPID != os.Getpid() || facts.HostUID != uint32(os.Getuid()) || facts.HostGID != uint32(os.Getgid()) ||
			scope.Actor.ID != principal || scope.Actor.ID == previous || scope.Actor.Kind != "human" || scope.Connection != connection {
			t.Fatal("fixture check: scope differs from native facts or current enrolled key")
		}
		previous = principal
		for _, method := range []api.Method{"health", "human.session"} {
			var body any = api.HumanSessionRequest{}
			if method == "health" {
				body = api.HealthRequest{ClientVersion: "fixture", ArtifactSHA256: connection.binding.ArtifactSHA256}
			}
			params, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			request := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: "fixture", Method: method,
				Params: params, RequestID: nativeID(t), IdempotencyKey: nativeID(t)}
			request.RequestSHA256, err = api.RequestDigest(request)
			if err != nil {
				t.Fatal(err)
			}
			payload, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			wire := make([]byte, 4, 4+len(payload))
			binary.BigEndian.PutUint32(wire, uint32(len(payload)))
			wire = append(wire, payload...)
			if n, err := client.Write(wire); err != nil || n != len(wire) {
				t.Fatalf("fixture setup: native frame write failed: %v", err)
			}
			scope.Frame, scope.Request = nativeReadFrame(t, connection), request
			err = service.Authorize(context.Background(), scope, request)
			if method == "health" {
				if err != nil {
					t.Fatalf("fixture check: genuine credential frame was refused: %v", err)
				}
			} else {
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != api.CodeUnauthenticated {
					t.Fatal("fixture check: human UID/enrollment conferred mutation authority without proof")
				}
			}
		}
		peer := connection.Peer()
		if err := connection.Close(); err != nil {
			t.Fatal(err)
		}
		if err := peer.Alive(context.Background()); err == nil {
			t.Fatal("fixture check: closed transport retained native peer authority")
		}
	}
}
