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
	"sort"
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

func TestContainmentStartRead(t *testing.T) {
	postExecAuthentication(t, "after-opened-concurrent-start", false)
}

func TestContainmentFirstRequest(t *testing.T) {
	postExecAuthentication(t, "after-opened-concurrent-first", false)
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
	Peer    api.PeerFacts
	Ticket  containmentTicket
	Launch  api.LaunchRecord
	Grants  api.GrantSet
	Policy  api.EffectivePolicy
	Recheck bool
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
	id         api.ID
	conn       *net.UnixConn
	binding    api.InstalledBinding
	peer       api.VerifiedPeer
	closed     bool
	beforeBind func()
}

func (c *concurrentIdentityConnection) ID() api.ID                    { return c.id }
func (c *concurrentIdentityConnection) Conn() net.Conn                { return c.conn }
func (c *concurrentIdentityConnection) Binding() api.InstalledBinding { return c.binding }
func (c *concurrentIdentityConnection) Peer() api.VerifiedPeer        { return c.peer }
func (c *concurrentIdentityConnection) BindPeer(peer api.VerifiedPeer) error {
	if c.closed || c.peer != nil || peer == nil {
		return errors.New("peer already bound or closed")
	}
	if c.beforeBind != nil {
		c.beforeBind()
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

type terminalIdentityResult struct {
	ElapsedUS int64
	Code      api.ErrorCode
	Error     string
}

type cacheIdentityResult struct {
	State  string
	Checks int
}

func concurrentIdentityService(config string) error {
	b, err := loadInstallation(config)
	if err != nil {
		return err
	}
	var input concurrentIdentityInput
	decoder := json.NewDecoder(os.Stdin)
	if err := decoder.Decode(&input); err != nil {
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
	var initial sync.WaitGroup
	initial.Add(20)
	recheck := make(chan struct{})
	var requests sync.WaitGroup
	for range 20 {
		conn, err := listener.(*net.UnixListener).AcceptUnix()
		if err != nil {
			return err
		}
		requests.Add(1)
		go func() {
			defer requests.Done()
			var initialOnce sync.Once
			arrived := func() { initialOnce.Do(initial.Done) }
			defer arrived()
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
			if input.Recheck {
				connection.beforeBind = func() {
					arrived()
					select {
					case <-recheck:
					case <-ctx.Done():
					}
				}
			}
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
	if input.Recheck {
		initial.Wait()
		if err := json.NewEncoder(os.Stdout).Encode("initial"); err != nil {
			return err
		}
		var command string
		if err := decoder.Decode(&command); err != nil {
			return err
		}
		if command != "recheck" {
			return errors.New("missing first-request recheck command")
		}
		close(recheck)
	}
	requests.Wait()
	close(results)
	var report []concurrentIdentityResult
	for result := range results {
		report = append(report, result)
	}
	encoder := json.NewEncoder(os.Stdout)
	if err := encoder.Encode(report); err != nil {
		return err
	}
	var command string
	if err := decoder.Decode(&command); err != nil || command != "warm" {
		return errors.New("missing retained-cache warm command")
	}
	// Cross several expiry boundaries under continuous real native checks.
	// This catches a cache hit aging out during kernel verification, without
	// substituting timer-only fixture calls for the production resolver.
	churnEnd := time.Now().Add(250 * time.Millisecond)
	checks := 0
	for time.Now().Before(churnEnd) {
		binding, err := registry.ResolveContainment(context.Background(), input.Peer, input.Binding)
		if err != nil {
			return fmt.Errorf("native cache churn: %w", err)
		}
		if err := binding.Directory.Close(); err != nil {
			return err
		}
		checks++
	}
	if err := encoder.Encode(cacheIdentityResult{State: "churn", Checks: checks}); err != nil {
		return err
	}
	// Populate the same production cache immediately before the external
	// terminal transition. The resident service receives no invalidation.
	time.Sleep(120 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	query := containmentQuery{LeaseID: ticket.Lease.ID, Opened: true}
	if _, err := registry.liveContainment(ctx, ticket.Lease.ContainmentID, query); err != nil {
		return err
	}
	if err := encoder.Encode(cacheIdentityResult{State: "warm", Checks: checks}); err != nil {
		return err
	}
	if err := decoder.Decode(&command); err != nil || command != "terminal" {
		return errors.New("missing external terminal transition")
	}
	start := time.Now()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		_, err := registry.liveContainment(ctx, ticket.Lease.ContainmentID, query)
		if err != nil {
			var refusal *api.Error
			if !errors.As(err, &refusal) {
				return err
			}
			return encoder.Encode(terminalIdentityResult{ElapsedUS: time.Since(start).Microseconds(), Code: refusal.Code, Error: refusal.Message})
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
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
	fixture.Recheck = strings.HasSuffix(phase, "-first")
	gate.mu.Lock()
	fixture.Peer = api.PeerFacts{HostPID: gate.innerPID, HostUID: ticket.Lease.UID, HostGID: ticket.Lease.GID,
		ProcessGeneration: gate.innerGeneration, ContainmentID: ticket.Lease.ContainmentID}
	gate.mu.Unlock()
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
	serviceInput, err := service.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer serviceInput.Close()
	serviceOutput, err := service.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	service.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: b.Service.UID, Gid: b.Service.GID, Groups: []uint32{}},
		UseCgroupFD: true, CgroupFD: int(endpoint.group.Fd())}
	var diagnostic bytes.Buffer
	service.Stderr = &diagnostic
	if err := service.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := serviceInput.Write(append(encoded, '\n')); err != nil {
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
	turnsBefore := containmentTurns(endpoint.journal.snapshot())
	if strings.HasSuffix(phase, "-start") {
		// Start has released the real native process. Its first identity read
		// races the helper's final serialized publication, as on the fresh box.
		// Hold that actual lock for 100 ms; the existing 5 s request budget
		// must survive this ordering without a retry or a cached pre-start read.
		_, release := manager.lockHelperOperation(ctx, false)
		go func() {
			timer := time.NewTimer(100 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
			}
			release()
		}()
	}
	start := time.Now()
	if n, err := input.Write([]byte{'a'}); err != nil || n != 1 {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(serviceOutput)
	if fixture.Recheck {
		var state string
		if err := decoder.Decode(&state); err != nil || state != "initial" {
			t.Fatal("first request did not obtain its initial native observation", err)
		}
		// The first request has already observed its real released process.
		// Cross cache expiry before its nested native recheck, then serialize
		// publication on the real helper lock for longer than ReadWait.
		time.Sleep(120 * time.Millisecond)
		_, release := manager.lockHelperOperation(ctx, false)
		go func() {
			time.Sleep(100 * time.Millisecond)
			release()
		}()
		if err := json.NewEncoder(serviceInput).Encode("recheck"); err != nil {
			t.Fatal(err)
		}
	}
	var results []concurrentIdentityResult
	if err := decoder.Decode(&results); err != nil || len(results) != 20 {
		t.Fatal("missing concurrent identity results", err)
	}
	elapsed := time.Since(start)
	turns := containmentTurns(endpoint.journal.snapshot()) - turnsBefore
	passed, failed := 0, 0
	latencies := make([]int64, 0, len(results))
	var maximum int64
	for _, result := range results {
		latencies = append(latencies, result.ElapsedMS)
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
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	t.Logf("gate_enabled=true native_identity count=%d helper_calls=%d helper_rate=%.2f p50_ms=%d p99_ms=%d elapsed_ms=%d",
		len(results), turns, float64(turns)/elapsed.Seconds(), latencies[len(latencies)/2], latencies[len(latencies)*99/100], elapsed.Milliseconds())
	if turns > 20 {
		t.Error("production containment source repeated helper reads inside concurrent identity requests", turns)
	}
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
	encoder := json.NewEncoder(serviceInput)
	// A real journal generation change or helper restart needs a cold full
	// decode. Keep that cost in the source/expiry exercise, not just warm hits.
	manager.operationMu.Lock()
	manager.containmentSnapshot = nil
	manager.operationMu.Unlock()
	cacheStart := time.Now()
	cacheTurns := containmentTurns(endpoint.journal.snapshot())
	if err := encoder.Encode("warm"); err != nil {
		t.Fatal(err)
	}
	readCache := func(state string) cacheIdentityResult {
		t.Helper()
		var result cacheIdentityResult
		if err := decoder.Decode(&result); err != nil || result.State != state || result.Checks < 2 {
			closeErr := serviceInput.Close()
			waitErr := service.Wait()
			waited = true
			t.Fatal("resident production cache stage failed", state, errors.Join(err, closeErr, waitErr), diagnostic.String())
		}
		return result
	}
	churn := readCache("churn")
	cacheCalls := containmentTurns(endpoint.journal.snapshot()) - cacheTurns
	t.Logf("native cache churn checks=%d helper_calls=%d helper_rate=%.2f gate_enabled=true", churn.Checks,
		cacheCalls, float64(cacheCalls)/time.Since(cacheStart).Seconds())
	readCache("warm")
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
	if err := encoder.Encode("terminal"); err != nil {
		t.Fatal(err)
	}
	var terminal terminalIdentityResult
	if err := decoder.Decode(&terminal); err != nil || terminal.Code != wantCode {
		t.Fatal("terminal journal transition retained its cached containment", err, terminal)
	}
	if wantCode == api.CodeUnauthenticated && !strings.Contains(terminal.Error, "peer containment has no consumed open gate") {
		t.Fatal("ended containment did not refuse on its actual gate state", terminal)
	}
	if time.Since(start) > 188*time.Millisecond {
		t.Fatal("terminal cached containment was not refused within 188 ms", terminal)
	}
	t.Logf("terminal=%s retained_cache_refusal_us=%d round_trip_us=%d bound_ms=188", phase, terminal.ElapsedUS, time.Since(start).Microseconds())
	err = service.Wait()
	waited = true
	if err != nil {
		t.Fatal("resident identity service failed", err, diagnostic.String())
	}
}

func containmentTurns(journal string) int {
	turns := 0
	for _, line := range strings.Split(journal, "\n") {
		var entry struct{ Operation, Stage string }
		if json.Unmarshal([]byte(line), &entry) == nil && entry.Operation == "containment_live" && entry.Stage == "turn" {
			turns++
		}
	}
	return turns
}
