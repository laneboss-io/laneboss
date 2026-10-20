//go:build linux

package service

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// Principal/containment membership is explicit input. Native credentials,
// framing, both production accept loops and admission/refusal code execute.
type acceptLoadAuth struct{ *authFixture }

func (a *acceptLoadAuth) Authenticate(ctx context.Context, c api.ConnectionContext) (api.Scope, error) {
	if err := ctx.Err(); err != nil {
		return api.Scope{}, err
	}
	if c.Peer() == nil {
		peer, err := wire.PeerCredentials(c.Conn().(*net.UnixConn))
		if err != nil {
			return api.Scope{}, err
		}
		if err := c.BindPeer(&peerFixture{facts: api.PeerFacts{HostPID: peer.PID, HostUID: peer.UID, HostGID: peer.GID,
			ProcessGeneration: "accept-load-peer", ContainmentID: c.ID()}}); err != nil {
			return api.Scope{}, err
		}
	}
	scope := a.scope
	scope.Connection = c
	return scope, c.Peer().Alive(ctx)
}

func (a *acceptLoadAuth) CurrentConnectionScope(ctx context.Context, c api.ConnectionContext) (api.Scope, error) {
	return a.Authenticate(ctx, c)
}

type acceptJournal struct {
	mu     sync.Mutex
	counts map[string]int
	wake   chan struct{}
}

func captureAcceptJournal(t *testing.T) *acceptJournal {
	t.Helper()
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stderr
	os.Stderr = write
	j := &acceptJournal{counts: map[string]int{}, wake: make(chan struct{}, 1)}
	done := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(read)
		for scanner.Scan() {
			var entry struct {
				Stage   string `json:"stage"`
				Message string `json:"message"`
			}
			if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
				done <- err
				return
			}
			j.mu.Lock()
			j.counts[entry.Stage+":"+entry.Message]++
			j.mu.Unlock()
			select {
			case j.wake <- struct{}{}:
			default:
			}
		}
		done <- scanner.Err()
	}()
	t.Cleanup(func() {
		os.Stderr = original
		write.Close()
		if err := <-done; err != nil {
			t.Error(err)
		}
		read.Close()
	})
	return j
}

func (j *acceptJournal) count(prefix string) int {
	j.mu.Lock()
	defer j.mu.Unlock()
	count := 0
	for key, n := range j.counts {
		if strings.HasPrefix(key, prefix) {
			count += n
		}
	}
	return count
}

func (j *acceptJournal) wait(t *testing.T, prefix string, want int) {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for j.count(prefix) < want {
		select {
		case <-j.wake:
		case <-timer.C:
			t.Fatalf("accept loop did not reach %s", prefix)
		}
	}
}

func TestAcceptOverload(t *testing.T) {
	for _, lane := range []bool{false, true} {
		t.Run(map[bool]string{false: "host", true: "lane"}[lane], func(t *testing.T) { acceptOverload(t, lane) })
	}
}

func acceptOverload(t *testing.T, lane bool) {
	t.Helper()
	journal := captureAcceptJournal(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	host := fixtureServer(t)
	host.verified, host.bound = true, true
	auth := &acceptLoadAuth{authFixture: host.deps.Authenticator.(*authFixture)}
	host.deps.Authenticator = auth
	if err := host.Register("identity.self", identityHandler); err != nil {
		t.Fatal(err)
	}
	var path, message string
	limit := 128
	done := make(chan struct{})
	stopListener := cancel
	if lane {
		laneHostFixture(t, host)
		spec, lease := laneSpecFixture(t, host)
		auth.scope.LaunchID, auth.scope.Actor.LifeID = spec.LaunchID, spec.Target.LifeID
		if err := host.prepareLaneEndpoint(ctx, spec, lease); err != nil {
			t.Fatal(err)
		}
		path = filepath.Join(filepath.Dir(host.deps.Binding.Socket), "lanes", string(spec.LaunchID)+".sock")
		message, limit = "lane connection admission limit reached", 16
		host.mu.RLock()
		stopListener = host.laneEndpoints[spec.LaunchID].cancel
		host.mu.RUnlock()
		go func() { host.workers.Wait(); close(done) }()
	} else {
		path = filepath.Join(t.TempDir(), "accept.sock")
		listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		if err := wire.EnableCredentials(listener); err != nil {
			t.Fatal(err)
		}
		host.deps.Binding.Socket = path
		message = "service connection admission limit reached"
		go func() {
			defer close(done)
			err := host.Serve(ctx, listener)
			if ctx.Err() == nil {
				t.Error(err)
			}
		}()
	}
	var held []net.Conn
	t.Cleanup(func() {
		cancel()
		stopListener()
		for _, c := range held {
			c.Close()
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("accept load did not drain")
		}
	})
	dial := func() net.Conn {
		t.Helper()
		c, err := net.DialTimeout("unix", path, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
		return c
	}
	call := func(c net.Conn) api.Response {
		t.Helper()
		if err := c.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		request := requestFor(t, "identity.self", api.Empty{})
		if err := wire.WriteFrame(c, publicFrame(t, request)); err != nil {
			t.Fatal(err)
		}
		data, err := wire.ReadFrame(c)
		if err != nil {
			t.Fatal(err)
		}
		reply, err := wire.DecodeResponse(data, request)
		if err != nil {
			t.Fatal(err)
		}
		return reply
	}
	for range limit {
		reply := call(dial())
		var scope api.Scope
		if reply.Error != nil || json.Unmarshal(reply.Result, &scope) != nil || scope.Actor != auth.scope.Actor {
			t.Fatal("accept load did not retain an authenticated connection", reply.Error)
		}
	}
	prefix := "admission:" + message
	var measured []time.Duration
	for range 4 {
		before := journal.count(prefix)
		slow := dial()
		journal.wait(t, prefix, before+1)
		began := time.Now()
		probe := dial()
		reply := call(probe)
		measured = append(measured, time.Since(began))
		if reply.Error == nil || reply.Error.Code != api.CodeUnavailable || len(reply.Result) != 0 {
			t.Fatal("overloaded listener lost its correlated refusal", reply.Error)
		}
		probe.Close()
		slow.Close()
	}
	sort.Slice(measured, func(i, j int) bool { return measured[i] < measured[j] })
	t.Logf("accept lane=%t held=%d silent_peers=4 p50_us=%d p99_us=%d", lane, limit, measured[2].Microseconds(), measured[3].Microseconds())
	if measured[3] > 250*time.Millisecond {
		t.Fatal("a refusal ran on the accept goroutine")
	}
	// With all refusal workers occupied, further peers must be closed promptly
	// rather than growing a goroutine/queue for each silent connection.
	var readers sync.WaitGroup
	closed := make(chan bool, 16)
	deadline := time.Now().Add(250 * time.Millisecond)
	for range 16 {
		c := dial()
		readers.Add(1)
		go func() {
			defer readers.Done()
			if err := c.SetReadDeadline(deadline); err != nil {
				closed <- false
				return
			}
			var one [1]byte
			n, err := c.Read(one[:])
			var timeout net.Error
			closed <- n == 0 && err != nil && !(errors.As(err, &timeout) && timeout.Timeout())
			c.Close()
		}()
	}
	readers.Wait()
	close(closed)
	count := 0
	for value := range closed {
		if value {
			count++
		}
	}
	if count < 8 {
		t.Fatal("full refusal pool did not promptly close excess peers", count)
	}
	journal.wait(t, "admission:overload refusal pool is full", 1)
	t.Logf("full refusal pool promptly closed=%d/16", count)
}
