//go:build linux

package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	release "laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/identity"
	"laneboss.io/laneboss/internal/v2/identity/input"
	"laneboss.io/laneboss/internal/v2/secrets"
	"laneboss.io/laneboss/internal/v2/secrets/native"
	"laneboss.io/laneboss/internal/v2/store"
)

type grantsFlowPorts struct {
	api.PeerVerifier
	api.ContainmentRegistry
}

type grantsFlowAuth struct {
	*authFixture
	identity *identity.Service
}

func (a grantsFlowAuth) FinalizeHumanSession(ctx context.Context, scope api.Scope) (api.HumanSession, error) {
	return a.identity.FinalizeHumanSession(ctx, scope)
}

// Prior enrollment and peer facts are component inputs. The test key signs
// actual challenge responses; confirmation, each flow mutation, dispatcher,
// SQLite writer, proof guard and encrypted backend are real. No hardware/OS
// entry or installed-service acceptance is credited by this test.
func TestGrantsFlowDispatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
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
	host := fixtureServer(t)
	actor := api.Actor{Kind: "human", ID: fixtureID(t)}
	binding := api.InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision,
		Protocol: api.Protocol, APISchema: api.SchemaVersion, Config: "service-fixture", Class: api.EndpointHuman,
		InstallationGeneration: 1, EndpointGeneration: 1, ServiceVersion: release.Version,
		ServiceUID: uint32(os.Geteuid()), ServiceGID: uint32(os.Getegid()), Socket: filepath.Join(directory, "human.sock"),
		ArtifactSHA256: digestBytes([]byte("declared component executable")), Backend: "linux-bwrap-landlock"}
	a, b := net.Pipe()
	connection, err := newConnection(a, binding, fixtureClock{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := connection.Close(); err != nil {
			t.Error(err)
		}
		if err := b.Close(); err != nil {
			t.Error(err)
		}
	})
	auth := &authFixture{scope: api.Scope{Config: binding.Config, Actor: actor, EndpointGeneration: 1, PolicyGeneration: 1}}
	scope, err := auth.Authenticate(ctx, connection)
	if err != nil {
		t.Fatal(err)
	}
	setup := api.Scope{Config: binding.Config, Actor: api.Actor{Kind: "service", ID: fixtureID(t)}, Source: "service"}
	intent := api.InternalIntent{ID: fixtureID(t), Kind: api.InternalOrgBootstrap, Config: setup.Config, Actor: setup.Actor, RequestedBy: setup.Actor}
	policy := api.EffectivePolicy{Generation: 1, SHA256: digestBytes([]byte("component upload policy"))}
	if _, err := state.Transact(ctx, api.Transaction{Scope: setup, Internal: &intent, Writes: api.StateWrites{Policy: &policy}}); err != nil {
		t.Fatal(err)
	}
	registration := testinput.EdRegistration(t, binding.Config, actor.ID, fixtureClock{})
	private := registration.Private
	enrollment := registration.Install.Enrollment
	credential := enrollment.Credentials[0]
	grantsFlowProjection(t, directory, "enrollment", actor.ID, enrollment)
	installed, err := state.HumanEnrollments(ctx, binding.Config)
	if err != nil || len(installed) != 1 || installed[0].PrincipalID != actor.ID {
		t.Fatal("declared prior enrollment is not valid for production startup", err)
	}
	identities, err := identity.New(identity.Dependencies{Peers: &grantsFlowPorts{}, Registry: &grantsFlowPorts{}, Store: state, Sessions: state, Clock: fixtureClock{}})
	if err != nil {
		t.Fatal(err)
	}
	backend, err := native.New(native.Dependencies{Config: binding.Config, Directory: filepath.Join(directory, "secrets"), KeyHandle: "dispatch-key", Clock: fixtureClock{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := backend.Close(); err != nil {
			t.Error(err)
		}
	})
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	if err := backend.Unlock(ctx, "dispatch-key", bytes.NewReader(key)); err != nil {
		t.Fatal(err)
	}
	owner, err := secrets.New(secrets.Dependencies{Config: binding.Config, Backend: backend, Store: state, Human: identities,
		ProjectionIdentity: identities, Clock: fixtureClock{}})
	if err != nil {
		t.Fatal(err)
	}
	host.deps.Store, host.deps.Binding = state, binding
	host.deps.Authenticator = grantsFlowAuth{authFixture: auth, identity: identities}
	if err := identities.Register(host); err != nil {
		t.Fatal(err)
	}
	if err := owner.Register(host); err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	tool := filepath.Join(directory, "grants-seal.input")
	build := exec.CommandContext(ctx, "go", "build", "-trimpath", "-mod=readonly", "-o", tool, "./scripts/v2-serve/grants_seal")
	build.Dir = root
	build.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatal("grants dispatcher sealer build:", err, string(output))
	}
	retainedInputs, err := os.MkdirTemp("", "lb-v2-case-grants-dispatch-")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("retained dispatcher inputs: %s", retainedInputs)
	toolBytes, err := os.ReadFile(tool)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(retainedInputs, "grants-seal.input"), toolBytes, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(retainedInputs, "sealer.json"), fixtureJSON(t, map[string]any{
		"sha256": digestBytes(toolBytes), "bytes": len(toolBytes)}), 0600); err != nil {
		t.Fatal(err)
	}
	var selected struct {
		Schema string `json:"schema"`
		Steps  []struct {
			Name           string     `json:"name"`
			Method         api.Method `json:"method"`
			RequestID      api.ID     `json:"request_id"`
			IdempotencyKey api.ID     `json:"idempotency_key"`
		} `json:"steps"`
	}
	if err := json.Unmarshal(grantsFlowInput(t, ctx, root, retainedInputs, "plan", nil), &selected); err != nil {
		t.Fatal(err)
	}
	if selected.Schema != "laneboss.client-flow.v2" || len(selected.Steps) != 3 {
		t.Fatal("actual grants dispatcher plan changed")
	}
	if api.Methods["secret.key"].Mutation {
		t.Fatal("secret key advertisement entered the mutation reply path")
	}
	var counter uint32
	var call func(api.Method, []byte, api.ID, api.ID, bool) json.RawMessage
	call = func(method api.Method, raw []byte, requestID, retry api.ID, proof bool) json.RawMessage {
		t.Helper()
		request, err := client.PrepareRequest(api.Request{Config: binding.Config, Method: method, Params: raw, RequestID: requestID, IdempotencyKey: retry})
		if err != nil {
			t.Fatal(err)
		}
		if proof {
			scope.Request, scope.Frame, scope.Source = request, sessionDispatchFrame{raw: fixtureJSON(t, request)}, "cli"
			target, err := state.AuthorizationTarget(ctx, scope, request)
			if err != nil {
				t.Fatal(err)
			}
			var challenge api.HumanChallenge
			challengeRaw := call("human.challenge", fixtureJSON(t, target), fixtureID(t), fixtureID(t), false)
			if err := wire.Decode(challengeRaw, &challenge); err != nil {
				t.Fatal(err)
			}
			clientData := fixtureJSON(t, map[string]any{"type": "webauthn.get", "origin": enrollment.Origin,
				"challenge": base64.RawURLEncoding.EncodeToString(challenge.Challenge), "crossOrigin": false})
			authData := make([]byte, 37)
			rp := sha256.Sum256([]byte(enrollment.RPID))
			copy(authData, rp[:])
			authData[32] = 0x05
			counter++
			binary.BigEndian.PutUint32(authData[33:], counter)
			clientHash := sha256.Sum256(clientData)
			signature := ed25519.Sign(private, append(append([]byte(nil), authData...), clientHash[:]...))
			confirmation := api.HumanConfirmRequest{ChallengeID: challenge.ID, CredentialID: credential.ID,
				ClientDataJSON: clientData, AuthenticatorData: authData, Signature: signature}
			var ref api.ProofRef
			if err := wire.Decode(call("human.confirm", fixtureJSON(t, confirmation), fixtureID(t), fixtureID(t), false), &ref); err != nil {
				t.Fatal(err)
			}
			request.Proof = &ref
		}
		frame := sessionDispatchFrame{raw: fixtureJSON(t, request)}
		request, err = wire.DecodeRequest(frame.raw)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("flow request method=%s input_base64=%s", method, base64.StdEncoding.EncodeToString(raw))
		reply, current, err := host.dispatch(context.WithValue(ctx, requestFrameKey{}, api.FrameContext(frame)), connection, request)
		if err != nil {
			t.Fatalf("grants flow %s: %v", method, err)
		}
		if api.Methods[method].Mutation {
			key := api.RequestKey{Method: method, IdempotencyKey: retry, RequestSHA256: request.RequestSHA256}
			retained, err := state.LookupReceipt(ctx, current, key)
			if err != nil || retained.Reply == nil || retained.Reply.Error != nil || retained.Operation.Status != "succeeded" ||
				!bytes.Equal(retained.RawRequest, frame.raw) || !bytes.Equal(retained.Reply.Result, reply) {
				t.Fatalf("grants flow %s lost its exact durable reply: %v", method, err)
			}
			if method == "secret.stage" && (retained.FirstSeq != 0 || retained.LastSeq != 0 ||
				retained.Operation.FirstSeq != 0 || retained.Operation.LastSeq != 0) {
				t.Fatal("grants flow stage lost its eventless operation range")
			}
			if method == "secret.import" && (retained.FirstSeq == 0 || retained.LastSeq < retained.FirstSeq ||
				retained.FirstSeq != retained.Operation.FirstSeq || retained.LastSeq != retained.Operation.LastSeq) {
				t.Fatal("grants flow import lost its actual operation event range")
			}
			if method == "secret.stage" || method == "secret.import" {
				// Replay the original proof/frame, with an owner tripwire. A
				// fresh confirmation or another allocation cannot satisfy this.
				ownerCalls := 0
				host.mu.Lock()
				original := host.handlers[method]
				host.handlers[method] = func(context.Context, api.Scope, json.RawMessage) (json.RawMessage, error) {
					ownerCalls++
					return nil, api.NotImplemented("lb-v2-service", "unexpected secret owner replay")
				}
				host.mu.Unlock()
				again, replayScope, replayErr := host.dispatch(context.WithValue(ctx, requestFrameKey{}, api.FrameContext(frame)), connection, request)
				host.mu.Lock()
				host.handlers[method] = original
				host.mu.Unlock()
				if replayErr != nil || ownerCalls != 0 || !bytes.Equal(again, reply) {
					t.Fatalf("grants flow %s replay reran its owner or changed its committed reply: %v", method, replayErr)
				}
				replayed, err := state.LookupReceipt(ctx, replayScope, key)
				if err != nil || !bytes.Equal(fixtureJSON(t, replayed), fixtureJSON(t, retained)) {
					t.Fatalf("grants flow %s replay changed its durable operation or input: %v", method, err)
				}
			}
		}
		t.Logf("flow method=%s input_base64=%s reply_base64=%s", method, base64.StdEncoding.EncodeToString(raw), base64.StdEncoding.EncodeToString(reply))
		return reply
	}
	call("human.session", []byte("{}"), fixtureID(t), fixtureID(t), true)
	if authority, err := connection.ReadAuthority(ctx); err != nil || authority.SessionID == "" {
		t.Fatal("flow session did not bind its actual connection", err)
	}
	var advertised api.SecretKey
	var staged api.SecretStage
	var imported api.SecretInfo
	var input []byte
	for index, step := range selected.Steps {
		switch index {
		case 0:
			if step.Method != "secret.key" {
				t.Fatal("actual flow did not request its key first")
			}
			input = []byte("{}")
		case 1:
			if step.Method != "secret.stage" {
				t.Fatal("actual flow did not stage its key-bound input")
			}
			input = grantsFlowInput(t, ctx, root, retainedInputs, "stage", map[string]any{"config": binding.Config, "key": advertised, "sealer": tool})
		case 2:
			if step.Method != "secret.import" {
				t.Fatal("actual flow did not import its staged handle")
			}
			input = grantsFlowInput(t, ctx, root, retainedInputs, "import", staged)
		}
		reply := call(step.Method, input, step.RequestID, step.IdempotencyKey, step.Method == "secret.import")
		var result any
		switch index {
		case 0:
			result = &advertised
		case 1:
			result = &staged
		case 2:
			result = &imported
		}
		if err := wire.Decode(reply, result); err != nil {
			t.Fatal(err)
		}
	}
	if !wire.ValidID(string(imported.SourceHandle)) || imported.Name != staged.Name || imported.Version != staged.Version || imported.Revoked {
		t.Fatal("flow import did not retain its actual protected source")
	}
	if err := backend.WithMetadata(ctx, func(rows []api.SecretInfo) error {
		if len(rows) != 1 || rows[0] != imported {
			t.Fatal("flow reply differs from native protected metadata")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func grantsFlowProjection(t *testing.T, directory, kind string, id api.ID, value any) {
	t.Helper()
	// This is the explicitly declared prior enrollment boundary. It seeds no
	// assertion, proof, flow reply, session, stage or imported source.
	db, err := sql.Open("sqlite", filepath.Join(directory, "state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	}()
	transaction, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	raw := fixtureJSON(t, value)
	if _, err := transaction.Exec("INSERT INTO projection_history(kind,id,data,sha256) VALUES(?,?,?,?)", kind, string(id), raw, string(digestBytes(raw))); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Exec("INSERT INTO projections VALUES(?,?,?,?)", kind, string(id), 1, raw); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}
}

func grantsFlowInput(t *testing.T, ctx context.Context, root, directory, phase string, metadata any) []byte {
	t.Helper()
	selected := filepath.Join(directory, phase)
	if err := os.Mkdir(selected, 0700); err != nil {
		t.Fatal(err)
	}
	arguments := []string{"-B", filepath.Join(root, "e2e/v2/cases/grants/dispatcher_input.py"), phase, selected}
	if metadata != nil {
		path := filepath.Join(selected, "metadata.json")
		if err := os.WriteFile(path, fixtureJSON(t, metadata), 0600); err != nil {
			t.Fatal(err)
		}
		arguments = append(arguments, path)
	}
	command := exec.CommandContext(ctx, "python3", arguments...)
	command.Dir = root
	var errors bytes.Buffer
	command.Stderr = &errors
	raw, err := command.Output()
	if err != nil {
		t.Fatal("actual grants flow producer:", err, errors.String())
	}
	if stored, err := os.ReadFile(filepath.Join(selected, phase+".request.json")); err != nil || !bytes.Equal(stored, raw) {
		t.Fatal("flow producer changed its retained input", err)
	}
	return raw
}
