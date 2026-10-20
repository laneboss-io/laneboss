//go:build linux

package service

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	release "laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/messaging"
	"laneboss.io/laneboss/internal/v2/pollgate"
	"laneboss.io/laneboss/internal/v2/store"
)

func init() {
	if len(os.Args) != 2 || os.Args[1] != "mail-load-client" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	binding, err := wire.ReadBinding(wire.LaneBindingPath, "service-fixture", release.Version)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(110)
	}
	c, err := client.Open(ctx, client.Options{Config: binding.Config, BindingFile: wire.LaneBindingPath})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(111)
	}
	if _, err := fmt.Fprintln(os.Stdout, "mail-client-ready"); err != nil {
		os.Exit(112)
	}
	var ready [1]byte
	if _, err := io.ReadFull(os.Stdin, ready[:]); err != nil {
		os.Exit(113)
	}
	params, err := json.Marshal(api.ListRequest{LifeID: binding.Target.LifeID, Limit: 200})
	if err != nil {
		os.Exit(114)
	}
	response, err := c.Call(ctx, api.Request{Config: binding.Config, Method: "mail.list", Params: params})
	if err != nil && response.Error == nil {
		var typed *api.Error
		if !errors.As(err, &typed) || json.NewEncoder(os.Stdout).Encode(typed) != nil {
			os.Exit(115)
		}
		os.Exit(69)
	}
	if err := c.Close(); err != nil || json.NewEncoder(os.Stdout).Encode(response) != nil {
		os.Exit(116)
	}
	os.Exit(0)
}

// Peer and containment facts are explicit component inputs. The native lane
// endpoint, sealed client binding, frame checks, mail handler and store run.
type mailLoadAuth struct {
	api.Authenticator
	scope         api.Scope
	group         api.ID
	denied        bool
	observeCancel bool
	gate          *pollgate.Gate
	pollCalls     *atomic.Int64
	pollWait      *atomic.Int64
	peerCalls     *atomic.Int64
	pollMemo      *pollgate.Memo[api.ID]
	entered       chan struct{}
	release       <-chan struct{}
}

func (a *mailLoadAuth) Authenticate(ctx context.Context, c api.ConnectionContext) (api.Scope, error) {
	if a.release != nil {
		select {
		case <-a.release:
		default:
			select {
			case a.entered <- struct{}{}:
			case <-ctx.Done():
				return api.Scope{}, ctx.Err()
			}
			select {
			case <-a.release:
			case <-ctx.Done():
				if a.observeCancel {
					// Observe the cancellation's transport effect before returning
					// the auth failure, rather than racing the refusal writer.
					var pending [1]byte
					if n, err := c.Conn().Read(pending[:]); n != 0 || err == nil {
						return api.Scope{}, serviceError(api.CodeIntegrity, "cancel control received unexpected input")
					}
				}
				return api.Scope{}, errors.Join(ctx.Err(), c.Close())
			}
		}
	}
	if a.denied {
		return api.Scope{}, errors.Join(serviceError(api.CodeUnauthenticated, "component lane has no current authority"), c.Close())
	}
	if c.Peer() == nil {
		peer, err := wire.PeerCredentials(c.Conn().(*net.UnixConn))
		if err != nil {
			return api.Scope{}, err
		}
		facts := &peerFixture{facts: api.PeerFacts{HostPID: peer.PID, HostUID: peer.UID, HostGID: peer.GID,
			ProcessGeneration: "mail-component-peer", ContainmentID: a.group}}
		var verified api.VerifiedPeer = facts
		if a.pollCalls != nil {
			verified = &mailPollPeer{peerFixture: facts, gate: a.gate, calls: a.pollCalls, wait: a.pollWait,
				checks: a.peerCalls, memo: a.pollMemo}
		}
		if err := c.BindPeer(verified); err != nil {
			return api.Scope{}, err
		}
	}
	result := a.scope
	result.Connection = c
	return result, c.Peer().Alive(ctx)
}

func (a *mailLoadAuth) CurrentConnectionScope(ctx context.Context, c api.ConnectionContext) (api.Scope, error) {
	return a.Authenticate(ctx, c)
}

func (a *mailLoadAuth) Authorize(ctx context.Context, scope api.Scope, request api.Request) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if scope.Actor != a.scope.Actor || scope.LaunchID != a.scope.LaunchID || request.Config != scope.Config || request.Proof != nil {
		return serviceError(api.CodeUnauthenticated, "mail component changed its current actor")
	}
	return nil
}

func TestMailLoadReply(t *testing.T)  { mailLoadReply(t, "load") }
func TestMailAuthTwin(t *testing.T)   { mailLoadReply(t, "denied") }
func TestMailLiveReply(t *testing.T)  { mailLoadReply(t, "live") }
func TestMailWorkCancel(t *testing.T) { mailLoadReply(t, "cancel") }

func mailLoadReply(t *testing.T, mode string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	serverCtx, stopServer := context.WithCancel(ctx)
	defer stopServer()
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
	host.deps.Store = state
	host.verified, host.bound = true, true
	auth := &mailLoadAuth{scope: scope, group: launch.ContainmentID, denied: mode == "denied", observeCancel: mode == "cancel"}
	host.deps.Authenticator = auth
	mail, err := messaging.New(messaging.Dependencies{Store: state, Clock: fixtureClock{}})
	if err != nil || mail.Register(host) != nil {
		t.Fatal("actual mailbox registration failed", err)
	}
	path := filepath.Join(t.TempDir(), "mail.sock")
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
	digest, err := wire.ArtifactDigest()
	if err != nil {
		t.Fatal(err)
	}
	target := api.LifeRef{LifeID: scope.Actor.LifeID, Run: 1}
	binding := api.InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision,
		Protocol: api.Protocol, APISchema: api.SchemaVersion, Config: scope.Config, Class: api.EndpointLane,
		InstallationGeneration: 1, EndpointGeneration: scope.EndpointGeneration, LaunchID: scope.LaunchID, Target: &target,
		ServiceUID: uint32(os.Geteuid()), ServiceGID: uint32(os.Getegid()), MappedServiceUID: uint32(os.Geteuid()),
		MappedServiceGID: uint32(os.Getegid()), Socket: wire.LaneSocketPath, ArtifactSHA256: digest,
		ServiceVersion: release.Version, Backend: "linux-bwrap-landlock"}
	host.deps.Binding = binding
	command, input, output := mailLoadClient(t, ctx, binding, path)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	reader := bufio.NewReader(output)
	line, err := reader.ReadString('\n')
	if err != nil || line != "mail-client-ready\n" {
		t.Fatal("sealed client did not open its actual endpoint", err, line)
	}
	if err := listener.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	accepted, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	var load []net.Conn
	release := make(chan struct{})
	var once sync.Once
	defer func() {
		once.Do(func() { close(release) })
		cancel()
		accepted.Close()
		for _, c := range load {
			c.Close()
		}
		workers.Wait()
	}()
	if mode == "load" || mode == "cancel" {
		auth.release, auth.entered = release, make(chan struct{}, 8)
		count := 8
		if mode == "cancel" {
			count = 6
		}
		for range count {
			c, err := net.Dial("unix", path)
			if err != nil {
				t.Fatal(err)
			}
			load = append(load, c)
			native, err := listener.AcceptUnix()
			if err != nil {
				t.Fatal(err)
			}
			workers.Add(1)
			go func() { defer workers.Done(); host.serveBoundConnection(serverCtx, native, binding) }()
			request := requestFor(t, "mail.list", api.ListRequest{LifeID: target.LifeID, Limit: 200})
			if err := wire.WriteFrame(c, publicFrame(t, request)); err != nil {
				t.Fatal(err)
			}
		}
		for range count {
			select {
			case <-auth.entered:
			case <-ctx.Done():
				t.Fatal("authentication load did not enter", ctx.Err())
			}
		}
	}
	if _, err := input.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	// Let the real client queue a complete request before the loaded worker
	// examines admission. This models a runnable request behind busy workers.
	raw, err := accepted.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var pollErr error
	if err := raw.Control(func(fd uintptr) {
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		_, pollErr = unix.Poll(fds, 5000)
	}); err != nil || pollErr != nil {
		t.Fatal(err, pollErr)
	}
	workers.Add(1)
	go func() { defer workers.Done(); host.serveBoundConnection(serverCtx, accepted, binding) }()
	if mode == "cancel" {
		select {
		case <-auth.entered:
		case <-ctx.Done():
			t.Fatal("mail request did not enter the loaded authentication path")
		}
		stopServer()
	}
	body, readErr := io.ReadAll(reader)
	runErr := command.Wait()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if runErr != nil {
		if mode == "cancel" && !bytes.Contains(body, []byte("service connection closed before a complete response at response_read")) {
			t.Fatalf("cancellation did not reproduce the exact installed close: %v\n%s", runErr, body)
		}
		t.Fatalf("real lane mail client: %v\n%s", runErr, body)
	}
	var response api.Response
	if err := api.DecodeObject(body, &response); err != nil {
		t.Fatal(err, string(body))
	}
	if mode == "live" {
		var page api.MailPage
		if response.Error != nil || api.DecodeObject(response.Result, &page) != nil || len(page.Messages) != 1 || !reflect.DeepEqual(page.Messages[0], wanted) {
			t.Fatal("actual lane mailbox did not return its page", response.Error)
		}
	} else {
		want := api.CodeUnauthenticated
		if mode == "load" {
			want = api.CodeUnavailable
		}
		if mode == "cancel" {
			want = api.CodeCancelled
		}
		if response.Error == nil || response.Error.Code != want || response.Error.Owner != "lb-v2-service" || len(response.Result) != 0 {
			t.Fatal("lane mail did not receive its complete named refusal", string(body))
		}
		if bytes.Contains(body, []byte(wanted.ID)) {
			t.Fatal("refused mail request disclosed its mailbox input")
		}
	}
	t.Logf("native mail.list mode=%s complete_response=true", mode)
}

// Prior mailbox metadata is an explicit input, not an enqueue/delivery claim.
// Compare the actual read against it, so an empty constant cannot pass.
func mailLoadInput(t *testing.T, directory string, scope api.Scope) api.Mail {
	t.Helper()
	data := []byte("mail component input " + string(fixtureID(t)))
	mail := api.Mail{ID: fixtureID(t), Generation: 1, Artifacts: []api.BlobRef{},
		Sender: api.Actor{Kind: "human", ID: fixtureID(t)}, RecipientLifeID: scope.Actor.LifeID,
		Content: api.BlobRef{ID: fixtureID(t), Class: "report", Bytes: int64(len(data)), SHA256: digestBytes(data)},
		Source:  "cli", Status: "queued", QueuedSeq: 1}
	grantsFlowProjection(t, directory, "mail", mail.ID, mail)
	return mail
}

func mailLoadClient(t *testing.T, ctx context.Context, binding api.InstalledBinding, socketPath string) (*exec.Cmd, *os.File, io.ReadCloser) {
	t.Helper()
	fd, err := unix.MemfdCreate("mail-client-binding", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		t.Fatal(err)
	}
	meta := os.NewFile(uintptr(fd), "binding")
	t.Cleanup(func() { meta.Close() })
	data, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := meta.Write(data); err != nil || meta.Chmod(0444) != nil {
		t.Fatal("test binding write", err)
	}
	const seals = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if _, err := unix.FcntlInt(meta.Fd(), unix.F_ADD_SEALS, seals); err != nil {
		t.Fatal(err)
	}
	endpoint, err := unix.Open(socketPath, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	socket := os.NewFile(uintptr(endpoint), "socket")
	t.Cleanup(func() { socket.Close() })
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { null.Close() })
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	argv := []string{"--die-with-parent", "--unshare-user", "--unshare-pid", "--uid", strconv.Itoa(os.Geteuid()),
		"--gid", strconv.Itoa(os.Getegid()), "--ro-bind", "/", "/", "--proc", "/proc", "--tmpfs", "/run",
		"--dir", "/run/laneboss", "--ro-bind", binary, wire.LaneClientPath,
		"--symlink", "/proc/self/fd/6", wire.LaneBindingPath, "--symlink", "/proc/self/fd/7", wire.LaneSocketPath,
		"--clearenv", wire.LaneClientPath, "mail-load-client"}
	command := exec.CommandContext(ctx, "bwrap", argv...)
	command.ExtraFiles = []*os.File{null, null, null, meta, socket}
	read, input, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { read.Close(); input.Close() })
	command.Stdin = read
	var diagnostic bytes.Buffer
	command.Stderr = &diagnostic
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if diagnostic.Len() != 0 {
			t.Log("native client diagnostic:", diagnostic.String())
		}
	})
	return command, input, output
}
