//go:build linux

package service

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/messaging"
	"laneboss.io/laneboss/internal/v2/pollgate"
	"laneboss.io/laneboss/internal/v2/store"
)

// The registry is a declared component port, using the same fresh-read gate
// as the helper. Every Facts/Alive still checks the port, including the checks
// in the actual frame verifier, mail handler and SQLite scope/read path.
type mailPollPeer struct {
	*peerFixture
	gate   *pollgate.Gate
	calls  *atomic.Int64
	wait   *atomic.Int64
	checks *atomic.Int64
	memo   *pollgate.Memo[api.ID]
}

func (p *mailPollPeer) Facts(ctx context.Context) (api.PeerFacts, error) {
	if p.checks != nil {
		p.checks.Add(1)
	}
	if p.memo != nil {
		_, proof, err := p.memo.EvalTimed(ctx, p.peerFixture.facts.ContainmentID, func(ctx context.Context) (api.ID, time.Time, error) {
			facts, err := p.read(ctx)
			return facts.ContainmentID, time.Now().Add(pollgate.VerdictAge), err
		})
		if err != nil {
			return api.PeerFacts{}, err
		}
		facts, err := p.peerFixture.Facts(ctx)
		if err == nil {
			err = p.memo.Check(proof)
		}
		return facts, err
	}
	return p.read(ctx)
}

func (p *mailPollPeer) read(ctx context.Context) (api.PeerFacts, error) {
	if p.gate != nil {
		began := time.Now()
		retire, err := p.gate.Enter(ctx, string(p.peerFixture.facts.ContainmentID))
		if p.wait != nil {
			p.wait.Add(int64(time.Since(began)))
		}
		if err != nil {
			return api.PeerFacts{}, err
		}
		defer retire()
	}
	p.calls.Add(1)
	return p.peerFixture.Facts(ctx)
}

type mailStageStats struct {
	mu   sync.Mutex
	rows map[string][]time.Duration
}

func (s *mailStageStats) add(stage string, began time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows[stage] = append(s.rows[stage], time.Since(began))
}

type mailStageAuth struct {
	*mailLoadAuth
	stats *mailStageStats
}

func (a *mailStageAuth) Authenticate(ctx context.Context, c api.ConnectionContext) (api.Scope, error) {
	defer a.stats.add("authentication", time.Now())
	return a.mailLoadAuth.Authenticate(ctx, c)
}

func (a *mailStageAuth) CurrentConnectionScope(ctx context.Context, c api.ConnectionContext) (api.Scope, error) {
	return a.Authenticate(ctx, c)
}

type mailStageStore struct {
	*store.Service
	stats *mailStageStats
}

func (s *mailStageStore) BeginRead(ctx context.Context, scope api.Scope) (api.ReadView, error) {
	defer s.stats.add("snapshot", time.Now())
	return s.Service.BeginRead(ctx, scope)
}

func (p *mailPollPeer) Alive(ctx context.Context) error {
	if _, err := p.Facts(ctx); err != nil {
		return err
	}
	return p.peerFixture.Alive(ctx)
}

func TestMailPollLoad(t *testing.T) {
	for _, bounded := range []bool{false, true} {
		t.Run(map[bool]string{false: "unbounded", true: "bounded"}[bounded], func(t *testing.T) {
			mailPollLoad(t, map[bool]string{false: "unbounded", true: "bounded"}[bounded])
		})
	}
}

func TestMailSourceGate(t *testing.T) { mailPollLoad(t, "cached") }

func mailPollLoad(t *testing.T, mode string) {
	t.Helper()
	bounded, cached := mode != "unbounded", mode == "cached"
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
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
	scope, _ := socketRecord(t, &state, directory)
	wanted := mailLoadInput(t, directory, scope)
	launch, err := state.Launch(ctx, scope.LaunchID)
	if err != nil {
		t.Fatal(err)
	}
	host := fixtureServer(t)
	stats := &mailStageStats{rows: map[string][]time.Duration{}}
	host.deps.Store = &mailStageStore{Service: state, stats: stats}
	host.verified, host.bound = true, true
	var polls, pollWait, checks atomic.Int64
	auth := &mailLoadAuth{scope: scope, group: launch.ContainmentID, pollCalls: &polls, pollWait: &pollWait, peerCalls: &checks}
	if bounded {
		auth.gate = &pollgate.Gate{}
	}
	if cached {
		auth.pollMemo = &pollgate.Memo[api.ID]{}
	}
	host.deps.Authenticator = &mailStageAuth{mailLoadAuth: auth, stats: stats}
	binding := host.deps.Binding
	binding.Config, binding.LaunchID, binding.EndpointGeneration = scope.Config, scope.LaunchID, scope.EndpointGeneration
	binding.Target = &api.LifeRef{LifeID: scope.Actor.LifeID, Run: 1}
	binding.ContractRevision = api.ContractRevision
	mail, err := messaging.New(messaging.Dependencies{Store: state, Clock: fixtureClock{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := mail.Register(host); err != nil {
		t.Fatal(err)
	}
	actualHandler := host.handlers["mail.list"]
	host.handlers["mail.list"] = func(ctx context.Context, scope api.Scope, raw json.RawMessage) (json.RawMessage, error) {
		defer stats.add("handler", time.Now())
		return actualHandler(ctx, scope, raw)
	}
	path := filepath.Join(t.TempDir(), "mail-load.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if err := wire.EnableCredentials(listener); err != nil {
		t.Fatal(err)
	}
	const workers, rounds = 8, 4
	var clients sync.WaitGroup
	start := make(chan struct{})
	latencies := make(chan time.Duration, workers*rounds)
	failures := make(chan error, workers)
	var connections []net.Conn
	inode, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	entry := &laneEndpoint{binding: binding, cancel: cancel, done: make(chan struct{})}
	host.laneEndpoints = map[api.ID]*laneEndpoint{binding.LaunchID: entry}
	host.workers.Add(1)
	go host.serveLaneEndpoint(ctx, listener, path, inode, entry)
	defer func() {
		cancel()
		for _, c := range connections {
			c.Close()
		}
		host.workers.Wait()
	}()
	for range workers {
		c, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, c)
		clients.Add(1)
		go func(c net.Conn) {
			defer clients.Done()
			<-start
			for range rounds {
				began := time.Now()
				request := requestFor(t, "mail.list", api.ListRequest{LifeID: scope.Actor.LifeID, Limit: 200})
				if err := c.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
					failures <- err
					return
				}
				if err := wire.WriteFrame(c, publicFrame(t, request)); err != nil {
					failures <- err
					return
				}
				data, err := wire.ReadFrame(c)
				if err != nil {
					failures <- err
					return
				}
				response, err := wire.DecodeResponse(data, request)
				if err != nil {
					failures <- err
					return
				}
				if response.Error != nil {
					failures <- response.Error
					return
				}
				var page api.MailPage
				if err := json.Unmarshal(response.Result, &page); err != nil {
					failures <- err
					return
				}
				if len(page.Messages) != 1 || !reflect.DeepEqual(page.Messages[0], wanted) {
					failures <- serviceError(api.CodeIntegrity, "actual mailbox lost its input")
					return
				}
				latencies <- time.Since(began)
			}
		}(c)
	}
	var before, after syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &before); err != nil {
		t.Fatal(err)
	}
	began := time.Now()
	close(start)
	clients.Wait()
	elapsed := time.Since(began)
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &after); err != nil {
		t.Fatal(err)
	}
	close(failures)
	close(latencies)
	for err := range failures {
		t.Error(err)
	}
	if t.Failed() {
		return
	}
	var measured []time.Duration
	for value := range latencies {
		measured = append(measured, value)
	}
	if len(measured) != workers*rounds {
		t.Fatal("mail load did not finish all actual requests")
	}
	sort.Slice(measured, func(i, j int) bool { return measured[i] < measured[j] })
	cpu := time.Duration(after.Utime.Nano() + after.Stime.Nano() - before.Utime.Nano() - before.Stime.Nano())
	t.Logf("service mode=%s mail=%d fresh_checks=%d helper_reads=%d elapsed_ms=%d rate=%.2f/s cpu_ms=%d", mode, len(measured), checks.Load(), polls.Load(), elapsed.Milliseconds(), float64(polls.Load())/elapsed.Seconds(), cpu.Milliseconds())
	t.Logf("mail.list p50_ms=%d p99_ms=%d producers=%d", measured[len(measured)/2].Milliseconds(), measured[len(measured)*99/100].Milliseconds(), workers)
	var total time.Duration
	for _, latency := range measured {
		total += latency
	}
	wait := time.Duration(pollWait.Load())
	t.Logf("poll gate wait_sum_ms=%d share_pct=%.2f mean_rpc_ms=%d outside_gate_mean_ms=%d", wait.Milliseconds(),
		100*float64(wait)/float64(total), (wait / time.Duration(len(measured))).Milliseconds(), ((total - wait) / time.Duration(len(measured))).Milliseconds())
	stats.mu.Lock()
	for _, stage := range []string{"authentication", "snapshot", "handler"} {
		rows := stats.rows[stage]
		if len(rows) == 0 {
			t.Error("no measured actual stage", stage)
			continue
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i] < rows[j] })
		t.Logf("stage=%s count=%d p50_us=%d p99_us=%d", stage, len(rows), rows[len(rows)/2].Microseconds(), rows[len(rows)*99/100].Microseconds())
	}
	stats.mu.Unlock()
	if bounded && elapsed < time.Duration(polls.Load()-1)*8*time.Millisecond {
		t.Fatal("service containment checks exceeded the 125/s bound")
	}
	if measured[len(measured)-1] > 5*time.Second {
		t.Fatal("mail.list exceeded its component latency bound under the same load")
	}
	if cached && (float64(wait)/float64(total) > .05 || measured[len(measured)/2] > 100*time.Millisecond) {
		t.Fatal("poll gate regulates the unchanged eight-producer workload after the source cut")
	}
}
