//go:build linux

package service_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	release "laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/cli"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/service"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

func init() {
	if handled, code := admin.RunBootstrapEntry(context.Background(), os.Args[1:]); handled {
		os.Exit(code)
	}
	if filepath.Base(os.Args[0]) == "client" {
		os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
	}
}

type relayLiveAuth struct {
	api.Authenticator
	scope api.Scope
	group api.ID
}

func (a relayLiveAuth) Authenticate(ctx context.Context, c api.ConnectionContext) (api.Scope, error) {
	if c.Peer() == nil {
		peer, err := wire.PeerCredentials(c.Conn().(*net.UnixConn))
		if err != nil {
			return api.Scope{}, err
		}
		if err := c.BindPeer(&fx.Peer{FactsValue: api.PeerFacts{HostPID: peer.PID, HostUID: peer.UID, HostGID: peer.GID,
			ProcessGeneration: "relay-component-peer", ContainmentID: a.group}}); err != nil {
			return api.Scope{}, err
		}
	}
	scope := a.scope
	scope.Connection = c
	return scope, c.Peer().Alive(ctx)
}

func (a relayLiveAuth) CurrentConnectionScope(ctx context.Context, c api.ConnectionContext) (api.Scope, error) {
	return a.Authenticate(ctx, c)
}

func (a relayLiveAuth) Authorize(ctx context.Context, scope api.Scope, request api.Request) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if scope.Actor != a.scope.Actor || scope.LaunchID != a.scope.LaunchID || scope.Request.Method != request.Method {
		return errors.New("relay component changed its actor or method")
	}
	return nil
}

func TestRelayDispatch(t *testing.T) {
	relayDispatch(t, false)
}

func TestRelayBootstrap(t *testing.T) {
	if os.Geteuid() == 0 {
		relayRoot(t)
		return
	}
	relayDispatch(t, true)
}

func relayDispatch(t *testing.T, native bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	f := fx.New(t, "service-fixture")
	f.Reserve(t)
	f.Source(t)
	f.BuildPlan(t, true)
	f.Spec(t)
	f.Bind(t)
	f.Opened(t)
	scope := f.LaneScope(t)
	root := filepath.Join("..", "..", "..")
	actor := filepath.Join(f.Deps.Directory, "actor")
	if native && len(os.Args) > 2 && os.Args[len(os.Args)-2] == "relay-boot-child" {
		actor = os.Args[len(os.Args)-1]
	} else {
		build := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", actor, "./scripts/v2-serve/grants_actor")
		build.Dir = root
		if output, err := build.CombinedOutput(); err != nil {
			t.Fatalf("real relay build: %v\n%s", err, output)
		}
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	rawSelf, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	auth := relayLiveAuth{scope: scope, group: f.Binding.Record.ContainmentID}
	core, err := service.New(service.Dependencies{Store: f.State, Clock: f.Deps.Clock, Authenticator: auth})
	if err != nil {
		t.Fatal(err)
	}
	var mail []api.Mail
	inputs, nonces := map[api.ID]bool{}, map[string]string{}
	for i, command := range []string{"identity self", "fixture exit"} {
		nonce := string(fx.ID(t))
		nonces[command] = nonce
		raw := fx.JSON(t, map[string]any{"schema": "laneboss.item-rpc.v1", "nonce": nonce,
			"command": command, "request": map[string]any{}, "request_id": string(fx.ID(t)), "idempotency_key": string(fx.ID(t))})
		f.Human = scope
		begin := api.BlobBeginRequest{Class: "report", Bytes: int64(len(raw)), SHA256: fx.Digest(raw)}
		f.Admit(t, "blob.begin", begin)
		upload, err := core.BlobBegin(ctx, f.Human, begin)
		if err != nil {
			t.Fatal("relay instruction begin", err)
		}
		part := api.BlobChunk{ObjectID: upload.ObjectID, Data: raw, SHA256: fx.Digest(raw)}
		f.Admit(t, "blob.chunk", part)
		if _, err := core.BlobChunk(ctx, f.Human, part); err != nil {
			t.Fatal("relay instruction chunk", err)
		}
		commit := api.BlobCommitRequest{ObjectID: upload.ObjectID, SHA256: fx.Digest(raw)}
		f.Admit(t, "blob.commit", commit)
		ref, err := core.BlobCommit(ctx, f.Human, commit)
		if err != nil {
			t.Fatal("relay instruction commit", err)
		}
		inputs[ref.ID] = true
		mail = append(mail, api.Mail{ID: fx.ID(t), Sender: api.Actor{Kind: "human", ID: fx.ID(t)}, RecipientLifeID: f.Reservation.Target.LifeID,
			Content: ref, Artifacts: []api.BlobRef{}, Generation: 1, QueuedSeq: api.Sequence(i + 1), Status: "queued", Source: "cli"})
	}
	binding := api.InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision, Protocol: api.Protocol,
		APISchema: api.SchemaVersion, Config: scope.Config, Class: api.EndpointHuman, InstallationGeneration: 1,
		EndpointGeneration: scope.EndpointGeneration, ServiceUID: uint32(os.Geteuid()), ServiceGID: uint32(os.Getegid()),
		MappedServiceUID: uint32(os.Geteuid()), MappedServiceGID: uint32(os.Getegid()), Socket: filepath.Join(f.Deps.Directory, "control.sock"),
		ArtifactSHA256: fx.Digest(rawSelf), ServiceVersion: release.Version, Backend: "linux-bwrap-landlock"}
	lane := binding
	uid, gid := os.Geteuid(), os.Getegid()
	target := f.Reservation.Target
	lane.Class, lane.Socket, lane.LaunchID, lane.Target = api.EndpointLane, wire.LaneSocketPath, scope.LaunchID, &target
	host, socketPath := service.RelayTestHost(t, ctx, service.Dependencies{Store: f.State, Clock: f.Deps.Clock, Binding: binding, Authenticator: auth}, lane, scope, mail)
	defer func() {
		if err := host.Close(); err != nil {
			t.Error(err)
		}
	}()
	fd, err := unix.MemfdCreate("relay-binding", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		t.Fatal(err)
	}
	input := os.NewFile(uintptr(fd), "binding")
	defer input.Close()
	if _, err := input.Write(fx.JSON(t, lane)); err != nil {
		t.Fatal(err)
	}
	if err := input.Chmod(0444); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(input.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL); err != nil {
		t.Fatal(err)
	}
	socketFD, err := unix.Open(socketPath, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	socket := os.NewFile(uintptr(socketFD), "socket")
	defer socket.Close()
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	command := exec.CommandContext(ctx, "bwrap", "--die-with-parent", "--unshare-user", "--unshare-pid", "--uid", strconv.Itoa(uid),
		"--gid", strconv.Itoa(gid), "--ro-bind", "/", "/", "--proc", "/proc", "--tmpfs", "/tmp", "--tmpfs", "/run",
		"--dir", "/run/laneboss", "--ro-bind", self, wire.LaneClientPath, "--symlink", "/proc/self/fd/6", wire.LaneBindingPath,
		"--symlink", "/proc/self/fd/7", wire.LaneSocketPath, "--clearenv", actor,
		"--config", lane.Config, "--client", wire.LaneClientPath, "--binding", wire.LaneBindingPath,
		"--life", string(target.LifeID), "--run", strconv.FormatUint(uint64(target.Run), 10), "--wait-ms", "90000")
	command.ExtraFiles = []*os.File{null, null, null, input, socket}
	command.Stdin = strings.NewReader("actual relay launch prompt\n")
	if native {
		relayBootstrap(t, command, actor, lane.Config, uid, gid, input, socket)
	}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("real relay dispatcher refused or stalled: %v\n%s", err, output)
	}
	page, err := f.State.Events(ctx, f.Execution, api.EventTailRequest{LifeID: target.LifeID, Run: target.Run})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	kinds := map[string]int{}
	for _, event := range page.Events {
		if event.Kind != "blob.committed" || event.Actor != scope.Actor {
			continue
		}
		if event.RequestedBy != scope.Actor || event.Origin != "observation" {
			t.Fatal("relay report changed its authenticated provenance")
		}
		var committed api.BlobRef
		if err := json.Unmarshal(event.Payload, &committed); err != nil || committed.Class != "report" {
			t.Fatal("relay report commit is malformed", err)
		}
		if inputs[committed.ID] {
			continue // This is the input instruction, not an actor-produced report.
		}
		chunk, err := f.State.Blob(ctx, f.Execution, api.BlobReadRequest{ObjectID: committed.ID, Limit: api.MaxChunkBytes})
		if err != nil || fx.Digest(chunk.Data) != committed.SHA256 || int64(len(chunk.Data)) != committed.Bytes {
			t.Fatal("relay committed bytes differ", err)
		}
		var report struct {
			Schema  string          `json:"schema"`
			Message json.RawMessage `json:"message"`
		}
		if err := json.Unmarshal(chunk.Data, &report); err != nil || report.Schema != "laneboss.relay-report.v1" {
			t.Fatal("relay report envelope differs", err)
		}
		var message struct{ Type, Nonce string }
		if err := json.Unmarshal(report.Message, &message); err != nil {
			t.Fatal(err)
		}
		kinds[message.Type]++
		if message.Type == "grants.reply" && message.Nonce != nonces["identity self"] ||
			message.Type == "grants.exiting" && message.Nonce != nonces["fixture exit"] {
			t.Fatal("real relay reply lost its request nonce")
		}
		matches := 0
		for _, line := range strings.Split(string(output), "\n") {
			if line == string(report.Message) {
				matches++
			}
		}
		if matches != 1 {
			t.Fatal("committed report differs from the actual actor stdout", matches)
		}
		count++
	}
	if count != 3 || kinds["grants.ready"] != 1 || kinds["grants.reply"] != 1 || kinds["grants.exiting"] != 1 {
		t.Fatal("real actor did not commit all report kinds", count, kinds)
	}
	t.Logf("real relay dispatcher committed reports=%d", count)
}
