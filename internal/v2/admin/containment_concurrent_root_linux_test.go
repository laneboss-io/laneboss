//go:build linux && laneboss_root_canary

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/identity"
	peerlinux "laneboss.io/laneboss/internal/v2/peer/linux"
)

func TestContainmentLiveConcurrentIdentity(t *testing.T) {
	for _, terminal := range []string{"revoked", "ended"} {
		t.Run(terminal, func(t *testing.T) {
			postExecAuthentication(t, "after-opened-concurrent-"+terminal, false)
		})
	}
}

func init() {
	if len(os.Args) == 4 && os.Args[1] == "admin-concurrent-identity-client" {
		if err := concurrentIdentityClient(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(114)
		}
		os.Exit(0)
	}
	if len(os.Args) == 3 && os.Args[1] == "admin-concurrent-identity-service" {
		if err := concurrentIdentityService(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(115)
		}
		os.Exit(0)
	}
}

type concurrentIdentityInput struct {
	Binding api.InstalledBinding
	Ticket  containmentTicket
	Launch  api.LaunchRecord
	Grants  api.GrantSet
	Policy  api.EffectivePolicy
}

// Immutable authority is fixture data; native peer verification, frame writer
// credentials, identity Authenticate/Authorize/IdentitySelf and helper IPC are
// the real implementations. Unused StateStore operations are never invoked.
type concurrentIdentityStore struct {
	api.StateStore
	input concurrentIdentityInput
}

func (s concurrentIdentityStore) Launch(ctx context.Context, id api.ID) (api.LaunchRecord, error) {
	if err := ctx.Err(); err != nil {
		return api.LaunchRecord{}, err
	}
	if id != s.input.Launch.ID {
		return api.LaunchRecord{}, errors.New("foreign launch selector")
	}
	return s.input.Launch, nil
}

func (s concurrentIdentityStore) Lane(ctx context.Context, scope api.Scope, target api.LifeRef) (api.Lane, error) {
	r := s.input.Launch
	if err := ctx.Err(); err != nil {
		return api.Lane{}, err
	}
	if scope.Config != r.Config || target != r.Target || scope.Actor != r.Actor {
		return api.Lane{}, errors.New("foreign lane selector")
	}
	return api.Lane{LaunchID: r.ID, LifeID: r.Target.LifeID, Run: r.Target.Run, Level: r.Actor.Level, Role: r.Actor.Role,
		GrantSetID: r.GrantSetID, PolicyGeneration: r.PolicyGeneration, ParentLifeID: r.ParentLifeID, RootLifeID: r.RootLifeID,
		StarterEventSeq: r.StarterEventSeq, StarterChain: r.StarterChain}, nil
}

func (s concurrentIdentityStore) Grants(ctx context.Context, id api.ID) (api.GrantSet, error) {
	if err := ctx.Err(); err != nil {
		return api.GrantSet{}, err
	}
	if id != s.input.Grants.ID {
		return api.GrantSet{}, errors.New("foreign grant selector")
	}
	return s.input.Grants, nil
}

func (s concurrentIdentityStore) Policy(ctx context.Context, scope api.Scope) (api.EffectivePolicy, error) {
	if err := ctx.Err(); err != nil {
		return api.EffectivePolicy{}, err
	}
	if scope.Config != s.input.Launch.Config || scope.Actor != s.input.Launch.Actor {
		return api.EffectivePolicy{}, errors.New("foreign policy selector")
	}
	return s.input.Policy, nil
}

type concurrentIdentityClock struct{}

func (concurrentIdentityClock) Now() time.Time { return time.Now() }

type concurrentIdentityConnection struct {
	api.ConnectionContext
	id      api.ID
	conn    *net.UnixConn
	binding api.InstalledBinding
	peer    api.VerifiedPeer
	closed  bool
}

func (c *concurrentIdentityConnection) ID() api.ID                    { return c.id }
func (c *concurrentIdentityConnection) Conn() net.Conn                { return c.conn }
func (c *concurrentIdentityConnection) Binding() api.InstalledBinding { return c.binding }
func (c *concurrentIdentityConnection) Peer() api.VerifiedPeer        { return c.peer }
func (c *concurrentIdentityConnection) BindPeer(peer api.VerifiedPeer) error {
	if c.closed || c.peer != nil || peer == nil {
		return errors.New("peer already bound or closed")
	}
	// Match the production transport's live BindPeer checks, including the
	// nested containment calls; do not shorten the storm for this canary.
	if _, err := peer.Facts(context.Background()); err != nil {
		return err
	}
	if err := peer.Alive(context.Background()); err != nil {
		return err
	}
	c.peer = peer
	return nil
}
func (c *concurrentIdentityConnection) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	err := c.conn.Close()
	if c.peer != nil {
		err = errors.Join(err, c.peer.Close())
	}
	return err
}

type concurrentIdentityResult struct {
	Stage     string
	ElapsedMS int64
	Error     string
}

func concurrentIdentityService(config string) error {
	b, err := loadInstallation(config)
	if err != nil {
		return err
	}
	var input concurrentIdentityInput
	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
		return err
	}
	registry, err := New(Dependencies{Config: b.Config, ServiceUID: b.Service.UID, ArtifactSHA256: b.Artifact.SHA256,
		Version: b.Release.Version, Protocol: api.Protocol, Schema: api.SchemaVersion})
	if err != nil {
		return err
	}
	directory := os.NewFile(5, "registered-containment")
	defer directory.Close()
	ticket := input.Ticket
	registry.containments = map[api.ID]*containmentEntry{ticket.Lease.ContainmentID: {
		Ticket: ticket, Binding: api.ContainmentBinding{Config: ticket.Config, Lease: ticket.Lease, Target: ticket.Target,
			BootID: ticket.BootID, Generation: ticket.Generation, Backend: input.Binding.Backend, Directory: directory},
	}}
	verifier, err := peerlinux.New(registry)
	if err != nil {
		return err
	}
	defer verifier.Close()
	identities, err := identity.New(identity.Dependencies{Peers: verifier, Registry: registry,
		Store: concurrentIdentityStore{input: input}, Clock: concurrentIdentityClock{}})
	if err != nil {
		return err
	}
	file := os.NewFile(3, "identity-listener")
	listener, err := net.FileListener(file)
	file.Close()
	if err != nil {
		return err
	}
	defer listener.Close()
	ready := os.NewFile(4, "identity-ready")
	if _, err := ready.Write([]byte{'r'}); err != nil {
		return err
	}
	ready.Close()
	results := make(chan concurrentIdentityResult, 20)
	var requests sync.WaitGroup
	for range 20 {
		conn, err := listener.(*net.UnixListener).AcceptUnix()
		if err != nil {
			return err
		}
		requests.Add(1)
		go func() {
			defer requests.Done()
			start := time.Now()
			result := concurrentIdentityResult{Stage: "authenticate"}
			defer func() { result.ElapsedMS = time.Since(start).Milliseconds(); results <- result }()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn.SetDeadline(start.Add(5 * time.Second))
			id, err := wire.NewID()
			if err != nil {
				result.Error = err.Error()
				conn.Close()
				return
			}
			connection := &concurrentIdentityConnection{id: api.ID(id), conn: conn, binding: input.Binding}
			defer connection.Close()
			scope, err := identities.Authenticate(ctx, connection)
			if err != nil {
				result.Error = err.Error()
				return
			}
			result.Stage = "frame"
			writer, err := wire.PeerCredentials(conn)
			if err != nil {
				result.Error = err.Error()
				return
			}
			frame, err := wire.ReadPinnedFrame(conn, writer)
			if err != nil {
				result.Error = err.Error()
				return
			}
			var request api.Request
			if err := api.DecodeObject(frame.Bytes(), &request); err != nil {
				result.Error = err.Error()
				return
			}
			scope.Frame, scope.Request = frame, request
			result.Stage = "authorize"
			if err := identities.Authorize(ctx, scope, request); err != nil {
				result.Error = err.Error()
				return
			}
			result.Stage = "identity.self"
			projection, err := identities.IdentitySelf(ctx, scope, api.Empty{})
			if err != nil {
				result.Error = err.Error()
				return
			}
			if err := writeFrame(conn, projection); err != nil {
				result.Error = err.Error()
				return
			}
			result.Stage = "complete"
		}()
	}
	requests.Wait()
	close(results)
	var report []concurrentIdentityResult
	for result := range results {
		report = append(report, result)
	}
	return json.NewEncoder(os.Stdout).Encode(report)
}

func concurrentIdentityClient(socket string) error {
	connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		return err
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	id, err := wire.NewID()
	if err != nil {
		return err
	}
	request := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: "admin-case", Method: "identity.self",
		RequestID: api.ID(id), IdempotencyKey: api.ID(id), Params: json.RawMessage(`{}`)}
	request.RequestSHA256, err = api.RequestDigest(request)
	if err != nil {
		return err
	}
	if err := writeFrame(connection, request); err != nil {
		return err
	}
	raw, err := wire.ReadFrame(connection)
	if err != nil {
		return err
	}
	var scope api.Scope
	if err := json.Unmarshal(raw, &scope); err != nil {
		return err
	}
	if scope.Actor.Kind != "lane" || scope.Config != request.Config || scope.LaunchID == "" || scope.PolicyGeneration == 0 {
		return errors.New("identity.self did not return an authenticated lane")
	}
	return nil
}

func concurrentIdentityAuthentication(t *testing.T, manager *leaseManager, registration gateOpenRegistration, endpoint containmentEndpoint,
	listener *net.UnixListener, gate *nativeGate, reader, input *os.File, phase string) {
	t.Helper()
	records, err := manager.records()
	if err != nil || len(records) != 1 || !openedContainment(records[0]) {
		t.Fatal("concurrent identity fixture has no real opened gate", err)
	}
	record := records[0]
	ticket, err := endpoint.query(record.Lease.ID)
	if err != nil {
		t.Fatal(err)
	}
	b := endpoint.binding
	r := registration.Binding.Record
	binding := api.InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision, Protocol: api.Protocol,
		APISchema: api.SchemaVersion, Config: b.Config, Class: api.EndpointLane, InstallationGeneration: b.Generation,
		EndpointGeneration: r.EndpointGeneration, ServiceUID: b.Service.UID, ServiceGID: b.Service.GID,
		Socket: listener.Addr().String(), ArtifactSHA256: b.Artifact.SHA256, ServiceVersion: b.Release.Version,
		Backend: "linux-bwrap-landlock", LaunchID: r.ID, Target: &r.Target}
	fixture := concurrentIdentityInput{Binding: binding, Ticket: ticket, Launch: r, Grants: record.Spec.Handoff.Spec.Grants, Policy: registration.Policy}
	encoded, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	listenFile, err := listener.File()
	if err != nil {
		t.Fatal(err)
	}
	defer listenFile.Close()
	directory, err := os.Open(manager.binding.cgroupPath() + "/" + string(record.Lease.ContainmentID))
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readyRead.Close()
	defer readyWrite.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	service := exec.CommandContext(ctx, b.binaryPath(), "admin-concurrent-identity-service", b.Config)
	service.Env = []string{}
	service.ExtraFiles = []*os.File{listenFile, readyWrite, directory}
	service.Stdin = bytes.NewReader(encoded)
	service.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: b.Service.UID, Gid: b.Service.GID, Groups: []uint32{}},
		UseCgroupFD: true, CgroupFD: int(endpoint.group.Fd())}
	var output, diagnostic bytes.Buffer
	service.Stdout, service.Stderr = &output, &diagnostic
	if err := service.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			cancel()
			if err := service.Wait(); err != nil && ctx.Err() == nil {
				t.Error(err)
			}
		}
	}()
	if err := readyRead.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var ready [1]byte
	if _, err := io.ReadFull(readyRead, ready[:]); err != nil || ready[0] != 'r' {
		t.Fatal("resident identity service did not become ready", err)
	}
	start := time.Now()
	if n, err := input.Write([]byte{'a'}); err != nil || n != 1 {
		t.Fatal(err)
	}
	err = service.Wait()
	waited = true
	if err != nil {
		t.Fatal("resident identity service failed", err, diagnostic.String())
	}
	var results []concurrentIdentityResult
	if err := json.Unmarshal(output.Bytes(), &results); err != nil || len(results) != 20 {
		t.Fatal("missing concurrent identity results", err)
	}
	passed, failed := 0, 0
	var maximum int64
	for _, result := range results {
		if result.ElapsedMS > maximum {
			maximum = result.ElapsedMS
		}
		if result.Error != "" || result.Stage != "complete" {
			failed++
			t.Logf("identity refused stage=%s elapsed_ms=%d error=%s", result.Stage, result.ElapsedMS, result.Error)
		} else {
			passed++
		}
	}
	t.Logf("parallel identity.self passed=%d failed=%d max_ms=%d total_ms=%d deadline_ms=5000", passed, failed, maximum, time.Since(start).Milliseconds())
	if failed != 0 {
		t.Fatal("concurrent in-lane identity calls missed the unchanged authentication/request deadline")
	}
	if err := reader.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	actual := make([]byte, len(gate.token))
	if _, err := io.ReadFull(reader, actual); err != nil || string(actual) != gate.token {
		t.Fatal("runner did not observe all real CLI children succeeding", err)
	}
	// Warm the exact same read before a terminal journal transition. No service
	// registry invalidation is supplied: the helper must refuse its old ticket.
	if _, err := endpoint.query(record.Lease.ID); err != nil {
		t.Fatal(err)
	}
	wantCode := api.CodeContainmentUnknown
	if strings.HasSuffix(phase, "-revoked") {
		_, unlock := manager.lockHelperOperation(context.Background(), false)
		// This is revokeNativeContainmentOwned's durable first transition,
		// while its original runner is still live. No registry-side tombstone
		// or process death can conceal a stale helper record here.
		record.Revoked = true
		err = manager.save(record)
		unlock()
		if err != nil {
			t.Fatal(err)
		}
	} else {
		wantCode = api.CodeUnauthenticated
		if err := input.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-gate.done:
		case <-ctx.Done():
			t.Fatal("native runner did not exit")
		}
		ctx, unlock := manager.lockHelperOperation(context.Background(), false)
		observation, observeErr := manager.observeGate(ctx, api.HelperObserveRequest{LeaseID: record.Lease.ID, Handle: gateHandle(record)})
		unlock()
		if observeErr != nil || observation.State != "exited" {
			t.Fatal("real native end was not journaled", observeErr)
		}
	}
	start = time.Now()
	_, err = endpoint.query(record.Lease.ID)
	if err == nil || !strings.Contains(err.Error(), string(wantCode)+":") {
		t.Fatal("terminal journal transition retained its authenticated containment", err)
	}
	if wantCode == api.CodeUnauthenticated && !strings.Contains(err.Error(), "peer containment has no consumed open gate") {
		t.Fatal("ended containment did not refuse on its actual gate state", err)
	}
	if time.Since(start) >= time.Second {
		t.Fatal("terminal containment refusal waited instead of invalidating immediately")
	}
	t.Logf("terminal=%s retained binding refused immediately elapsed_ms=%d", phase, time.Since(start).Milliseconds())
}
