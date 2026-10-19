//go:build linux && laneboss_partial && laneboss_e2e_authenticator

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// This proves the stand-in diagnostic can locate a real stalled native read
// without publishing request bytes or absolute source paths. It is not the
// regression for the installed stop's as-yet-unidentified cause.
func TestCredWaitTrace(t *testing.T) {
	client, server := nativePair(t)
	channel := &credentialChannel{connection: client, peer: nativePeer(t, client)}
	serverPeer := nativePeer(t, server)
	canary, err := randomID("private-trace-")
	if err != nil {
		t.Fatal(err)
	}
	params, err := json.Marshal(struct{ Canary api.ID }{canary})
	if err != nil {
		t.Fatal(err)
	}
	request := helperRequest{Protocol: credentialProtocol, Revision: api.ContractRevision,
		Config: "admin-case", Generation: 1, ArtifactSHA256: testDigest("trace"),
		Nonce: "trace-once", Method: "begin_withdrawal", Params: params}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	prior := os.Stderr
	os.Stderr = writer
	defer func() { os.Stderr = prior; writer.Close() }()
	output := make(chan []byte, 1)
	go func() {
		data, err := io.ReadAll(reader)
		if err != nil {
			t.Error(err)
		}
		output <- data
	}()
	finished := make(chan error, 1)
	go func() {
		var result api.Empty
		_, err := channel.exchange(context.Background(), request, &result, nil, false,
			time.Now().Add(2500*time.Millisecond), channel.transportAlive)
		finished <- err
	}()
	data, err := readUnixFrame(server, serverPeer)
	var received helperRequest
	if err != nil || decodeStrict(data, &received) != nil || !bytes.Equal(received.Params, params) {
		t.Fatal("trace control did not write its actual private request", err)
	}
	err = <-finished
	var refused *api.Error
	if !errors.As(err, &refused) || refused.Code != api.CodeUnauthenticated || channel.transportAlive() == nil {
		t.Fatal("trace changed the stalled frame's refusal or stream disposition", err)
	}
	os.Stderr = prior
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	data = <-output
	if bytes.Contains(data, []byte(canary)) || bytes.Contains(data, []byte("/internal/v2/")) {
		t.Fatal("credential wait diagnostic exposed private bytes or an absolute path")
	}
	var event struct {
		Event string `json:"event"`
		Stage string `json:"stage"`
		Waits [][]struct {
			File string `json:"file"`
			Line int    `json:"line"`
		} `json:"waits"`
	}
	if err := json.Unmarshal(data, &event); err != nil || event.Event != "credential_wait" || event.Stage != "exchange" {
		t.Fatal("stalled native read has no credential wait diagnostic", err)
	}
	found := false
	for _, frames := range event.Waits {
		for _, frame := range frames {
			found = found || frame.File == "credwire_linux.go" && frame.Line > 0
		}
	}
	if !found {
		t.Fatal("credential wait diagnostic did not locate the actual native frame reader")
	}
}
