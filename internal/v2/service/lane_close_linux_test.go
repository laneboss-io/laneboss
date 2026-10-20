//go:build linux

package service

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	release "laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/messaging"
	"laneboss.io/laneboss/internal/v2/store"
)

func TestLaneCloseReply(t *testing.T) {
	for _, closing := range []bool{false, true} {
		t.Run(map[bool]string{false: "live", true: "host-close"}[closing], func(t *testing.T) {
			laneCloseJournal(t, closing)
		})
	}
}

// Authority is a declared component input. The production lane accept loop,
// native sealed client, credential frames, mail handler and SQLite execute.
func laneCloseJournal(t *testing.T, closing bool) {
	t.Helper()
	journal := captureAcceptJournal(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
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
	host.deps.Store, host.verified, host.bound = state, true, true
	auth := &mailLoadAuth{scope: scope, group: launch.ContainmentID}
	if closing {
		auth.release, auth.entered = make(chan struct{}), make(chan struct{}, 1)
	}
	host.deps.Authenticator = auth
	mail, err := messaging.New(messaging.Dependencies{Store: state, Clock: fixtureClock{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := mail.Register(host); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "lane.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
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
	inode, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	laneCtx, stop := context.WithCancel(ctx)
	entry := &laneEndpoint{binding: binding, cancel: stop, done: make(chan struct{})}
	host.laneEndpoints = map[api.ID]*laneEndpoint{binding.LaunchID: entry}
	host.workers.Add(1)
	go host.serveLaneEndpoint(laneCtx, listener, path, inode, entry)
	defer func() {
		if err := host.Close(); err != nil {
			t.Error(err)
		}
	}()
	command, input, output := mailLoadClient(t, ctx, binding, path)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			cancel()
			if err := command.Wait(); err == nil {
				t.Error("cancelled native client unexpectedly succeeded")
			}
		}
	}()
	reader := bufio.NewReader(output)
	if line, err := reader.ReadString('\n'); err != nil || line != "mail-client-ready\n" {
		t.Fatal("native lane client did not open", err)
	}
	if _, err := input.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if closing {
		select {
		case <-auth.entered:
		case <-ctx.Done():
			t.Fatal("native request did not enter lane authentication")
		}
		began := time.Now()
		if err := host.Close(); err != nil {
			t.Fatal(err)
		}
		t.Logf("host close elapsed_us=%d", time.Since(began).Microseconds())
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	runErr := command.Wait()
	waited = true
	if closing {
		if runErr != nil {
			t.Fatalf("host close lost the complete refusal: %v %s", runErr, body)
		}
		var response api.Response
		if api.DecodeObject(body, &response) != nil || response.Error == nil || response.Error.Code != api.CodeCancelled ||
			response.Error.Owner != "lb-v2-service" || len(response.Result) != 0 || bytes.Contains(body, []byte(wanted.ID)) {
			t.Fatalf("host close did not retain its named refusal: %s", body)
		}
		journal.wait(t, "connection:service host closed a lane connection", 1)
		t.Log("actual lane listener returned a complete cancelled refusal on host close")
		return
	}
	var response api.Response
	var page api.MailPage
	if runErr != nil || api.DecodeObject(body, &response) != nil || response.Error != nil ||
		api.DecodeObject(response.Result, &page) != nil || len(page.Messages) != 1 || !reflect.DeepEqual(page.Messages[0], wanted) {
		t.Fatalf("live lane listener lost actual mail: %v %s", runErr, body)
	}
	t.Log("actual lane listener returned the exact prior mailbox input")
}
