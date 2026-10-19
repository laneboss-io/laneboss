//go:build linux

package main

import (
	"bytes"
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
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/cli"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/service"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

func init() {
	if len(os.Args) > 1 && os.Args[1] == "actor-native" {
		os.Args = append(os.Args[:1], os.Args[2:]...)
		main()
		os.Exit(0)
	}
	if filepath.Base(os.Args[0]) == "client" {
		os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
	}
}

// Identity and mailbox delivery are explicit component inputs. The actual
// actor, child CLI, descriptor handoff, Unix frames and blob writer execute.
type actorAuth struct{ api.Authenticator }

func (actorAuth) Authorize(ctx context.Context, scope api.Scope, request api.Request) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if scope.Actor.Kind != "lane" || scope.Request.Method != request.Method {
		return errors.New("actor component changed its bound scope")
	}
	return nil
}

func TestActorCLI(t *testing.T) {
	for _, fault := range []bool{false, true} {
		t.Run(strconv.FormatBool(fault), func(t *testing.T) {
			actorCLI(t, fault)
		})
	}
}

func actorCLI(t *testing.T, fault bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	f := fx.Ready(t, true)
	f.Opened(t)
	f.Human = f.LaneScope(t)
	core, err := service.New(service.Dependencies{Store: f.State, Clock: f.Deps.Clock, Authenticator: actorAuth{}})
	if err != nil {
		t.Fatal(err)
	}
	target := f.Reservation.Target
	rawExit := fx.JSON(t, envelope{Schema: "laneboss.item-rpc.v1", Nonce: string(fx.ID(t)),
		Command: "fixture exit", Request: json.RawMessage(`{}`), RequestID: string(fx.ID(t)), Key: string(fx.ID(t))})
	begin := api.BlobBeginRequest{Class: "report", Bytes: int64(len(rawExit)), SHA256: hash(rawExit)}
	f.Admit(t, "blob.begin", begin)
	opened, err := core.BlobBegin(ctx, f.Human, begin)
	if err != nil {
		t.Fatal("control input upload", err)
	}
	chunk := api.BlobChunk{ObjectID: opened.ObjectID, Data: rawExit, SHA256: hash(rawExit)}
	f.Admit(t, "blob.chunk", chunk)
	if _, err := core.BlobChunk(ctx, f.Human, chunk); err != nil {
		t.Fatal("control input chunk", err)
	}
	commit := api.BlobCommitRequest{ObjectID: opened.ObjectID, SHA256: hash(rawExit)}
	f.Admit(t, "blob.commit", commit)
	exitRef, err := core.BlobCommit(ctx, f.Human, commit)
	if err != nil {
		t.Fatal("control input commit", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "service.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	var methods []api.Method
	go func() {
		for {
			connection, err := listener.AcceptUnix()
			if err != nil {
				done <- err
				return
			}
			deadline, _ := ctx.Deadline()
			if err := connection.SetDeadline(deadline); err != nil {
				done <- err
				return
			}
			raw, err := wire.ReadFrame(connection)
			var request api.Request
			if err != nil || api.DecodeObject(raw, &request) != nil {
				done <- errors.New("actor child did not send a complete CLI request")
				return
			}
			methods = append(methods, request.Method)
			f.Human.Request, f.Human.Frame = request, &fx.Frame{Raw: raw}
			if api.Methods[request.Method].Mutation {
				if _, err := f.State.ReserveRequest(ctx, api.RequestReservation{Scope: f.Human, RawRequest: raw, Deadline: fx.Expiry()}); err != nil {
					done <- err
					return
				}
			}
			var value any
			switch request.Method {
			case "identity.self":
				value = f.Human
			case "blob.begin":
				var input api.BlobBeginRequest
				err = api.DecodeObject(request.Params, &input)
				if err == nil {
					if fault {
						input.Class = "manifest" // A lane cannot publish a trusted class.
					}
					value, err = core.BlobBegin(ctx, f.Human, input)
				}
			case "blob.chunk":
				var input api.BlobChunk
				err = api.DecodeObject(request.Params, &input)
				if err == nil {
					value, err = core.BlobChunk(ctx, f.Human, input)
				}
			case "blob.commit":
				var input api.BlobCommitRequest
				err = api.DecodeObject(request.Params, &input)
				if err == nil {
					value, err = core.BlobCommit(ctx, f.Human, input)
				}
			case "blob.read":
				var input api.BlobReadRequest
				err = api.DecodeObject(request.Params, &input)
				if err == nil {
					value, err = core.BlobRead(ctx, f.Human, input)
				}
			case "mail.list":
				value = api.MailPage{Messages: []api.Mail{{ID: fx.ID(t), Sender: api.Actor{Kind: "human", ID: fx.ID(t)},
					RecipientLifeID: target.LifeID, Content: exitRef, Artifacts: []api.BlobRef{},
					Generation: 1, QueuedSeq: 1, Source: "cli", Status: "queued"}}}
			default:
				err = errors.New("actor called an unexpected public method")
			}
			response := api.Response{Protocol: api.Protocol, Schema: api.SchemaVersion, RequestID: request.RequestID}
			if err != nil {
				var typed *api.Error
				if !errors.As(err, &typed) {
					done <- err
					return
				}
				response.Error = typed
				err = nil // The exact native refusal is serialized, not a transport failure.
			} else {
				response.Result, err = json.Marshal(value)
			}
			body, encodeErr := json.Marshal(response)
			if err != nil || encodeErr != nil {
				done <- errors.Join(err, encodeErr)
				return
			}
			if err := wire.WriteFrame(connection, body); err != nil {
				done <- errors.Join(errors.New("actor receipt write"), err)
				return
			}
			if err := connection.Close(); err != nil {
				done <- err
				return
			}
		}
	}()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binaryRaw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	binding := api.InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision,
		Protocol: api.Protocol, APISchema: api.SchemaVersion, Config: f.Deps.Config, Class: api.EndpointLane,
		InstallationGeneration: 1, EndpointGeneration: f.Human.EndpointGeneration,
		ServiceUID: uint32(os.Geteuid()), ServiceGID: uint32(os.Getegid()),
		MappedServiceUID: uint32(os.Geteuid()), MappedServiceGID: uint32(os.Getegid()), Socket: wire.LaneSocketPath,
		ArtifactSHA256: hash(binaryRaw), ServiceVersion: release.Version, Backend: "linux-bwrap-landlock", LaunchID: f.Human.LaunchID, Target: &target}
	fd, err := unix.MemfdCreate("actor-cli-binding", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		t.Fatal(err)
	}
	input := os.NewFile(uintptr(fd), "binding")
	defer input.Close()
	if _, err := input.Write(fx.JSON(t, binding)); err != nil || input.Chmod(0444) != nil {
		t.Fatal("sealed binding write", err)
	}
	const seals = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if _, err := unix.FcntlInt(input.Fd(), unix.F_ADD_SEALS, seals); err != nil {
		t.Fatal(err)
	}
	socketFD, err := unix.Open(path, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
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
	argv := []string{"--die-with-parent", "--unshare-user", "--unshare-pid", "--uid", strconv.Itoa(os.Geteuid()),
		"--gid", strconv.Itoa(os.Getegid()), "--ro-bind", "/", "/", "--proc", "/proc", "--tmpfs", "/tmp", "--tmpfs", "/run",
		"--dir", "/run/laneboss", "--ro-bind", binary, wire.LaneClientPath,
		"--symlink", "/proc/self/fd/6", wire.LaneBindingPath, "--symlink", "/proc/self/fd/7", wire.LaneSocketPath,
		"--clearenv", "--setenv", "PATH", "/usr/bin:/bin", wire.LaneClientPath, "actor-native",
		"--config", binding.Config, "--client", wire.LaneClientPath, "--binding", wire.LaneBindingPath,
		"--life", string(target.LifeID), "--run", strconv.FormatUint(uint64(target.Run), 10), "--wait-ms", "90000",
		"--driver", "codex", "--mode", "lifecycle", "--session", string(fx.ID(t)), "--home", string(fx.ID(t)),
		"--history", string(fx.ID(t)), "--vendor-session", string(fx.ID(t)), "--challenge", string(fx.ID(t)),
		"--model", "1.0.0", "--effort", "low"}
	command := exec.CommandContext(ctx, "bwrap", argv...)
	command.ExtraFiles = []*os.File{null, null, null, input, socket}
	command.Stdin = strings.NewReader("actual installed prompt\n")
	output, runErr := command.CombinedOutput()
	listener.Close()
	serverErr := <-done
	if !errors.Is(serverErr, net.ErrClosed) {
		t.Fatal("actor socket boundary", serverErr, string(output))
	}
	if len(methods) == 0 {
		t.Fatalf("actor did not reach its first installed API: %v\n%s", runErr, output)
	}
	if fault {
		if runErr == nil || !strings.Contains(string(output), "installed CLI blob begin exited 2") ||
			!bytesContains(output, "upload class requires its trusted emitter") || bytesContains(output, "grants.ready") {
			t.Fatalf("report refusal lost its command or native error: %v\n%s", runErr, output)
		}
	} else if runErr != nil {
		t.Fatalf("installed actor/CLI startup failed: %v; methods=%v\n%s", runErr, methods, output)
	}
	page, err := f.State.Events(ctx, f.Execution, api.EventTailRequest{LifeID: target.LifeID, Run: target.Run})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, event := range page.Events {
		if event.Kind == "blob.committed" && event.Actor == f.Human.Actor {
			var ref api.BlobRef
			if err := json.Unmarshal(event.Payload, &ref); err != nil {
				t.Fatal(err)
			}
			if ref.ID != exitRef.ID {
				chunk, err := f.State.Blob(ctx, f.Execution, api.BlobReadRequest{ObjectID: ref.ID, Limit: api.MaxChunkBytes})
				if err != nil || ref.Class != "report" || int64(len(chunk.Data)) != ref.Bytes || hash(chunk.Data) != ref.SHA256 {
					t.Fatal("committed report read-back differs", err)
				}
				var report struct {
					Schema  string          `json:"schema"`
					Message json.RawMessage `json:"message"`
				}
				if err := api.DecodeObject(chunk.Data, &report); err != nil || report.Schema != "laneboss.relay-report.v1" {
					t.Fatal("committed report envelope differs", err)
				}
				matches := 0
				for _, line := range bytes.Split(output, []byte("\n")) {
					if bytes.Equal(line, report.Message) {
						matches++
					}
				}
				if matches != 1 {
					t.Fatal("committed report differs from native stdout", matches)
				}
				count++
			}
		}
	}
	if fault && count != 0 || !fault && (count != 2 || !bytesContains(output, "grants.ready") || !bytesContains(output, "grants.exiting")) {
		t.Fatal("actor reports do not match real blob commits", count, string(output))
	}
	t.Logf("actual actor reports committed and read back: %d", count)
}

func bytesContains(raw []byte, word string) bool { return bytes.Contains(raw, []byte(word)) }

func TestSeatRefusal(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	root := filepath.Join("..", "..", "..")
	probe := filepath.Join("e2e", "v2", "cases", "grants", "lifecycle_test.py")
	command := exec.CommandContext(ctx, "python3", "-B", probe)
	command.Dir = root
	output, err := command.CombinedOutput()
	t.Log(string(output))
	if err != nil {
		t.Fatal("shared-seat refusal or isolated stop twin failed", err)
	}
}

// Remove only the fixture's seat guard in a separate Python process. The
// restored refusal test must fail; production sources and Stop stay intact.
func TestSeatRefusalRed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	const control = `
import ast
import importlib.util
import inspect
from pathlib import Path
import sys
import unittest

path = Path("e2e/v2/cases/grants") / "lifecycle_test.py"
spec = importlib.util.spec_from_file_location("seat_control", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
original = module.GRANTS.finish_lifecycle
tree = ast.parse(inspect.getsource(original))
body = tree.body[0].body
guards = [node for node in body if isinstance(node, ast.Expr)
          and isinstance(node.value, ast.Call)
          and any(isinstance(arg, ast.Constant)
                  and arg.value == "lifecycle stop would quarantine an item seat"
                  for arg in node.value.args)]
if len(guards) != 1:
    raise ValueError("control lacks the exact original seat guard")
body.remove(guards[0])
scope = dict(original.__globals__)
exec(compile(tree, "seat-control", "exec"), scope)
module.GRANTS.finish_lifecycle = scope[original.__name__]
suite = unittest.TestSuite([module.Lifecycle("test_shared_seat_refused")])
result = unittest.TextTestRunner(verbosity=2).run(suite)
sys.exit(0 if result.wasSuccessful() else 1)
`
	command := exec.CommandContext(ctx, "python3", "-B", "-c", control)
	command.Dir = filepath.Join("..", "..", "..")
	output, err := command.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 || !bytesContains(output, "ValueError not raised") {
		t.Fatalf("seat control missed the refusal assertion: %v\n%s", err, output)
	}
	t.Log("RED: removing the seat guard fails the restored refusal test")
	t.Log(string(output))
}
