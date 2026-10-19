//go:build linux && laneboss_root_canary && laneboss_gate_integration

package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	release "laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	peerlinux "laneboss.io/laneboss/internal/v2/peer/linux"
	"laneboss.io/laneboss/internal/v2/secrets"
	"laneboss.io/laneboss/internal/v2/secrets/native"
	"laneboss.io/laneboss/internal/v2/secrets/testdir"
)

// Only the previously verified human/session facts are component inputs.
// The installed-binding client, kernel peer/frame checks, production secret
// key/stage owner and client-side sealing are real. No human ceremony,
// persistent secret import, system installation or model request is credited.
type flowNoStore struct {
	api.StateStore
	stages testdir.StageLedger
}

func (s *flowNoStore) Transact(ctx context.Context, input api.Transaction) (api.Commit, error) {
	return s.stages.Transact(ctx, input)
}

func (s *flowNoStore) CommitSecretStage(ctx context.Context, input api.Transaction, allocated api.SecretStage) (api.Commit, error) {
	return s.stages.CommitSecretStage(ctx, input, allocated)
}

type flowNoHuman struct{ api.HumanVerifier }
type flowNoProjection struct {
	api.CredentialProjectionIdentity
}
type flowNoRegistry struct{ api.ContainmentRegistry }

type flowHandlers map[api.Method]api.Handler

func (r flowHandlers) Register(method api.Method, handler api.Handler) error {
	if r[method] != nil || handler == nil {
		return &api.Error{Code: api.CodeInvalid, Message: "duplicate or absent flow handler"}
	}
	r[method] = handler
	return nil
}

func (r flowHandlers) RegisterStream(api.Method, api.StreamHandler) error {
	return api.NotImplemented("lb-v2-secrets", "native staging fixture stream")
}

func init() {
	if len(os.Args) > 2 && os.Args[1] == "human" && os.Args[2] == "session" {
		os.Exit(RunContext(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
	}
}

type flowClock struct{}

func (flowClock) Now() time.Time { return time.Now() }

type flowWireConn struct {
	api.ConnectionContext
	id        api.ID
	conn      net.Conn
	binding   api.InstalledBinding
	peer      api.VerifiedPeer
	authority api.ReadAuthority
}

func (c *flowWireConn) ID() api.ID                    { return c.id }
func (c *flowWireConn) Conn() net.Conn                { return c.conn }
func (c *flowWireConn) Binding() api.InstalledBinding { return c.binding }
func (c *flowWireConn) Peer() api.VerifiedPeer        { return c.peer }
func (c *flowWireConn) ReadAuthority(ctx context.Context) (api.ReadAuthority, error) {
	if err := c.peer.Alive(ctx); err != nil {
		return api.ReadAuthority{}, err
	}
	if c.authority.SessionID == "" {
		return api.ReadAuthority{}, &api.Error{Code: api.CodeUnauthenticated}
	}
	return c.authority, nil
}

func flowWireServer(t *testing.T, root string) {
	t.Helper()
	ctx := context.Background()
	var binding api.InstalledBinding
	raw, err := os.ReadFile(filepath.Join(root, "binding.json"))
	if err != nil || api.DecodeObject(raw, &binding) != nil || uint32(os.Geteuid()) != binding.ServiceUID {
		t.Fatal("native flow server identity differs", err)
	}
	backend, err := native.New(native.Dependencies{Config: binding.Config,
		Directory: filepath.Join(root, "service", "secrets"), KeyHandle: "flow-key", Clock: flowClock{}})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	module, err := secrets.New(secrets.Dependencies{Config: binding.Config, Backend: backend,
		Store: &flowNoStore{}, Human: &flowNoHuman{}, ProjectionIdentity: &flowNoProjection{}, Clock: flowClock{}})
	if err != nil {
		t.Fatal(err)
	}
	handlers := make(flowHandlers)
	if err := module.Register(handlers); err != nil {
		t.Fatal(err)
	}
	peers, err := peerlinux.New(&flowNoRegistry{})
	if err != nil {
		t.Fatal(err)
	}
	defer peers.Close()
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: binding.Socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(binding.Socket, 0666); err != nil {
		t.Fatal(err)
	}
	if err := listener.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stdout.Write([]byte("ready\n")); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		conn, err := listener.AcceptUnix()
		if err != nil {
			t.Fatal(err)
		}
		if err := wire.EnableCredentials(conn); err != nil {
			t.Fatal(err)
		}
		peer, err := peers.Verify(ctx, conn, binding)
		if err != nil {
			t.Fatal(err)
		}
		id, err := wire.NewID()
		if err != nil {
			t.Fatal(err)
		}
		current := &flowWireConn{id: id, conn: conn, binding: binding, peer: peer}
		facts, err := wire.PeerCredentials(conn)
		if err != nil {
			t.Fatal(err)
		}
		for {
			frame, err := wire.ReadPinnedFrame(conn, facts)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			var request api.Request
			if err := api.DecodeObject(frame.Bytes(), &request); err != nil {
				t.Fatal(err)
			}
			scope := api.Scope{Config: binding.Config, Actor: api.Actor{Kind: "human", ID: "flow-principal"},
				Connection: current, Frame: frame, Source: "cli", EndpointGeneration: binding.EndpointGeneration, Request: request}
			var value any
			var callErr error
			switch request.Method {
			case "human.session":
				if request.Proof == nil || request.Proof.RequestSHA256 != request.RequestSHA256 || request.Config != binding.Config {
					t.Fatal("component session facts changed")
				}
				sessionID, err := wire.NewID()
				if err != nil {
					t.Fatal(err)
				}
				session := api.HumanSession{ID: sessionID, Config: binding.Config,
					ExpiresAt:     api.Timestamp(time.Now().Add(4 * time.Minute).UTC().Format(time.RFC3339Nano)),
					IdleExpiresAt: api.Timestamp(time.Now().Add(3 * time.Minute).UTC().Format(time.RFC3339Nano)), SimulatedPresence: true}
				current.authority = api.ReadAuthority{ConnectionID: id, SessionID: session.ID, PrincipalID: scope.Actor.ID,
					CredentialID: "flow-credential", Config: binding.Config, EndpointGeneration: binding.EndpointGeneration,
					Generation: 1, ExpiresAt: session.ExpiresAt, IdleExpiresAt: session.IdleExpiresAt, SimulatedPresence: true}
				value = session
			case "secret.key", "secret.stage":
				value, callErr = handlers[request.Method](ctx, scope, request.Params)
			default:
				t.Fatal("unexpected public flow request")
			}
			response := api.Response{Protocol: api.Protocol, Schema: api.SchemaVersion, RequestID: request.RequestID}
			if callErr != nil {
				if !errors.As(callErr, &response.Error) {
					t.Fatal(callErr)
				}
			} else {
				response.Result, err = json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
			}
			encoded, err := json.Marshal(response)
			if err != nil || wire.WriteFrame(conn, encoded) != nil {
				t.Fatal("native flow response failed", err)
			}
		}
		if err := errors.Join(peer.Close(), conn.Close()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSessionWire(t *testing.T) {
	if len(os.Args) > 2 && os.Args[len(os.Args)-2] == "flow-wire-server" {
		flowWireServer(t, os.Args[len(os.Args)-1])
		return
	}
	for _, adapter := range []string{"secrets", "grants"} {
		t.Run(adapter, func(t *testing.T) { sessionWire(t, adapter) })
	}
}

func sessionWire(t *testing.T, adapter string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("native session flow requires disposable Linux root")
	}
	prefix := "lb-v2-it2-flow-"
	if adapter == "grants" {
		prefix = "lb-v2-case-grants-flow-"
	}
	root, err := os.MkdirTemp("/opt", prefix)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	})
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	serviceRoot := filepath.Join(root, "service")
	if err := os.Mkdir(serviceRoot, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(serviceRoot, 61000, 61000); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "canary")
	if err := os.WriteFile(binary, data, 0555); err != nil {
		t.Fatal(err)
	}
	var sealer string
	if adapter == "grants" {
		sealer = filepath.Join(root, "grants-seal.input")
		buildContext, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		build := exec.CommandContext(buildContext, "go", "build", "-trimpath", "-mod=readonly", "-o", sealer, "./scripts/v2-serve/grants_seal")
		build.Dir = filepath.Join("..", "..", "..")
		build.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off")
		if output, err := build.CombinedOutput(); err != nil {
			t.Fatal("actual grants sealer build failed", err, string(output))
		}
		if retained := os.Getenv("LB_GRANTS_UPLOAD_EVIDENCE"); retained != "" {
			body, err := os.ReadFile(sealer)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(retained, "grants-seal.input"), body, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	digest, err := wire.ArtifactDigest()
	if err != nil {
		t.Fatal(err)
	}
	binding := api.InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision,
		Protocol: api.Protocol, APISchema: api.SchemaVersion, Config: "flow-native", Class: api.EndpointHuman,
		InstallationGeneration: 1, EndpointGeneration: 1, ServiceUID: 61000, ServiceGID: 61000,
		MappedServiceUID: 61000, MappedServiceGID: 61000, Socket: filepath.Join(serviceRoot, "rpc.sock"),
		ArtifactSHA256: digest, ServiceVersion: release.Version, Backend: "linux-bwrap-landlock"}
	bindingFile := integrateFixtureFile(t, root, "binding.json", binding)
	if err := os.Chmod(bindingFile, 0644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "-test.run=^TestSessionWire$", "--", "flow-wire-server", root)
	command.Env = []string{}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 61000, Gid: 61000, Groups: []uint32{}}}
	ready, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var serverErrors bytes.Buffer
	command.Stderr = &serverErrors
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	t.Cleanup(func() {
		if !waited {
			cancel()
			if err := command.Wait(); err != nil {
				t.Log("native child collected after failed check")
			}
		}
	})
	var greeting [6]byte
	if _, err := io.ReadFull(ready, greeting[:]); err != nil || string(greeting[:]) != "ready\n" {
		t.Fatal("native flow server did not become ready", err)
	}
	proofDigest, err := api.RequestDigest(api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion,
		Config: binding.Config, Method: "human.session", Params: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	proof := api.ProofRef{ID: "flow-proof", RequestSHA256: proofDigest,
		ExpiresAt: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)), SimulatedPresence: true}
	proofFile := integrateFixtureFile(t, root, "proof.json", proof)
	integrateFixtureFile(t, root, "empty.json", api.Empty{})
	evidence := filepath.Join(root, "evidence")
	if err := os.Mkdir(evidence, 0700); err != nil {
		t.Fatal(err)
	}
	plan := integrateFixtureFile(t, evidence, "flow.json", sessionPlan{Schema: "laneboss.client-flow.v2", Steps: []sessionStep{
		{Name: "key", Method: "secret.key", Request: filepath.Join(root, "empty.json")},
		{Name: "stage", Method: "secret.stage", Request: filepath.Join(root, "stage.json"), IdempotencyKey: api.ID(strings.Repeat("k", 32))},
	}})
	var value []byte
	if adapter == "secrets" {
		value = make([]byte, 64)
		if _, err := rand.Read(value); err != nil {
			t.Fatal(err)
		}
	}
	defer clear(value)
	probe, err := filepath.Abs("../../../e2e/v2/cases/secrets/flow_probe.py")
	if err != nil {
		t.Fatal(err)
	}
	if adapter == "grants" {
		probe, err = filepath.Abs("../../../e2e/v2/cases/grants/upload_probe.py")
		if err != nil {
			t.Fatal(err)
		}
	}
	steps := []sessionStep{
		{Name: "human-session", Method: "human.session", Request: "empty.json", Proof: "proof.json", IdempotencyKey: api.ID(strings.Repeat("s", 32))},
		{Name: "key", Method: "secret.key", Request: "empty.json"},
		{Name: "stage", Method: "secret.stage", Request: "stage.json", IdempotencyKey: api.ID(strings.Repeat("k", 32))},
	}
	input := integrateFixtureFile(t, root, "probe.json", map[string]any{
		"context": map[string]string{"binary": binary, "config": binding.Config, "binding_file": bindingFile,
			"test_root": root, "evidence_root": evidence}, "steps": steps, "plan": plan, "sealer": sealer,
	})
	actor := exec.CommandContext(ctx, "python3", probe, input)
	actor.Env = []string{"PATH=/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE=1"}
	if overlay := os.Getenv("LB_GRANTS_CORE"); overlay != "" {
		actor.Env = append(actor.Env, "LB_GRANTS_CORE="+overlay)
	}
	var actorOutput bytes.Buffer
	actor.Stdout, actor.Stderr = &actorOutput, &actorOutput
	if err := actor.Start(); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- actor.Wait() }()
	actorWaited := false
	t.Cleanup(func() {
		if !actorWaited {
			cancel()
			if err := <-finished; err != nil {
				t.Log("flow adapter collected after failed check")
			}
		}
	})
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	var key api.SecretKey
	for adapter == "secrets" && key.ID == "" {
		select {
		case err := <-finished:
			actorWaited = true
			t.Fatal("installed adapter ended before its key handoff", err, actorOutput.String())
		case <-deadline.C:
			t.Fatal("installed adapter did not publish its live key handoff")
		case <-tick.C:
			body, err := os.ReadFile(filepath.Join(evidence, "human-1-response.json"))
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			var response api.Response
			if err := json.Unmarshal(body, &response); err != nil || response.Error != nil {
				t.Fatal("native key handoff was not successful", err)
			}
			if err := api.DecodeObject(response.Result, &key); err != nil {
				t.Fatal(err)
			}
		}
	}
	if adapter == "secrets" {
		sealed, err := secrets.SealStage(binding.Config, key, "flow.canary", "one", api.SecretMaterial{Bytes: value})
		if err != nil {
			t.Fatal(err)
		}
		integrateFixtureFile(t, root, "stage.json", sealed)
	}
	if err := <-finished; err != nil {
		actorWaited = true
		if adapter == "grants" {
			t.Fatal("actual grants staging failed", err, actorOutput.String())
		}
		t.Fatal("native CLI adapter failed", err, actorOutput.String())
	}
	actorWaited = true
	if adapter == "grants" {
		body, err := os.ReadFile(filepath.Join(evidence, "human-1-response.json"))
		if err != nil {
			t.Fatal(err)
		}
		var response api.Response
		if err := json.Unmarshal(body, &response); err != nil || response.Error != nil {
			t.Fatal("native key handoff was not successful", err)
		}
		if err := api.DecodeObject(response.Result, &key); err != nil {
			t.Fatal(err)
		}
	}
	output, err := os.ReadFile(filepath.Join(evidence, "human-client.out"))
	if err != nil {
		t.Fatal(err)
	}
	var diagnostic bytes.Buffer
	if adapter == "secrets" && bytes.Contains(output, value) {
		t.Fatal("native flow printed material")
	}
	var records []json.RawMessage
	for _, line := range bytes.Split(bytes.TrimSpace(output), []byte{'\n'}) {
		var record map[string]json.RawMessage
		if err := json.Unmarshal(line, &record); err != nil {
			t.Fatal(err)
		}
		if record["wait"] == nil {
			records = append(records, line)
		}
	}
	if len(records) != 3 {
		t.Fatal("native flow lost an actual response")
	}
	var final struct {
		Response api.Response `json:"response"`
	}
	if err := json.Unmarshal(records[2], &final); err != nil {
		t.Fatal(err)
	}
	var staged api.SecretStage
	if err := api.DecodeObject(final.Response.Result, &staged); err != nil || staged.ID == "" || staged.Name != "flow.canary" {
		t.Fatal("native stage lacks its real receipt", err)
	}
	if adapter == "grants" {
		raw, err := os.ReadFile(filepath.Join(root, "stage.json"))
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("actual grants staging input sha256=%x bytes_base64=%s", sha256.Sum256(raw), base64.StdEncoding.EncodeToString(raw))
		var input api.SecretStageRequest
		if err := wire.Decode(raw, &input); err != nil || input.KeyID != key.ID || input.Name != staged.Name || input.Version != staged.Version {
			t.Fatal("actual grants staging input lost its key or decoder shape", err)
		}
	}
	// A fresh connection cannot use the previous connection's actual key.
	diagnostic.Reset()
	args := []string{"secret", "stage", "--config", binding.Config, "--binding", bindingFile, "--proof", proofFile,
		"--idempotency-key", strings.Repeat("r", 32), "--request", filepath.Join(root, "stage.json")}
	code := RunContext(ctx, args, strings.NewReader(""), io.Discard, &diagnostic)
	var refusal api.Error
	if err := json.Unmarshal(diagnostic.Bytes(), &refusal); err != nil || code != 2 || refusal.Code != api.CodeNotFound ||
		refusal.Message != "upload key is absent for this live human read session" || refusal.Owner != "lb-v2-secrets" {
		t.Fatal("new connection reused the native upload key", code, err)
	}
	if err := command.Wait(); err != nil {
		t.Fatal("native flow server failed", err, serverErrors.String())
	}
	waited = true
}
