//go:build linux

package service

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func enrollmentSocket(t *testing.T, s *Server, raw []byte) api.AdminEnrollmentReply {
	t.Helper()
	path := filepath.Join(t.TempDir(), "enroll.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := wire.EnableCredentials(listener); err != nil {
		t.Fatal(err)
	}
	client, err := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	connection, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer connection.Close()
		s.serveEnrollment(ctx, connection, s.deps.Binding)
	}()
	if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := wire.WriteFrame(client, raw); err != nil {
		t.Fatal(err)
	}
	data, err := wire.ReadFrame(client)
	if err != nil {
		t.Fatal("administrator refusal reply was silent", err)
	}
	var reply api.AdminEnrollmentReply
	if err := json.Unmarshal(data, &reply); err != nil {
		t.Fatal("administrator refusal was not a typed reply", err)
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("administrator refusal did not quiesce")
	}
	return reply
}

func TestEnrollmentReplies(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Fatal("enrollment wire fixture requires an unprivileged Linux UID")
	}
	for _, mode := range []string{"old_frame", "protocol", "config", "method", "enroll_begin", "enroll_complete", "initial_publish"} {
		t.Run(mode, func(t *testing.T) {
			s := fixtureServer(t)
			e := api.AdminEnrollmentEndpoint{Config: s.options.Config, Socket: "/runtime/enroll.sock", ServiceUID: 1000,
				InstallationGeneration: 1, Origin: "https://enroll.invalid", RPID: "enroll.invalid",
				Helper: api.Executable{ID: "helper", Version: "fixture-v1", SHA256: digestBytes([]byte("component helper"))}}
			s.options.AdminEnrollment = &e
			frame := api.AdminEnrollmentFrame{Protocol: api.AdminEnrollmentProtocol, Revision: api.ContractRevision,
				Config: e.Config, Generation: e.InstallationGeneration, ArtifactSHA256: e.Helper.SHA256,
				Nonce: fixtureID(t), Method: "enroll_begin", Params: json.RawMessage(`{}`)}
			field := mode
			switch mode {
			case "protocol":
				frame.Protocol += "-changed"
			case "config":
				frame.Config += "-changed"
			case "method":
				frame.Method = "unknown"
			case "old_frame":
				field = "protocol"
			default:
				frame.Method, field = mode, "peer_uid"
			}
			raw, err := json.Marshal(frame)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "old_frame" {
				raw = []byte(`{"action":"begin","request":{}}`)
			}
			reply := enrollmentSocket(t, s, raw)
			if err := api.ValidateAdminEnrollmentReply(reply, frame); err != nil || reply.Error == nil || reply.FailureField != field || len(reply.Result) != 0 {
				t.Fatal("administrator refusal lost its wire contract", err, reply.FailureField)
			}
		})
	}
}

func TestEnrollmentDispatch(t *testing.T) {
	s := fixtureServer(t)
	for _, method := range []string{"enroll_begin", "enroll_complete", "initial_publish"} {
		_, err := s.enrollmentResult(&administratorCall{Context: context.Background()}, enrollmentFrame{Method: method, Params: json.RawMessage(`{}`)})
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeInvalid || api.AdminEnrollmentFailedField(err) != "params" {
			t.Fatal("administrator method did not reach its typed decoder", method, err)
		}
	}
}

func TestEnrollmentExpiredWrite(t *testing.T) {
	s := fixtureServer(t)
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	if err := server.SetDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.writeEnrollmentReply(server, enrollmentResponse{Protocol: api.AdminEnrollmentProtocol, Revision: api.ContractRevision}, "frame", context.DeadlineExceeded)
	}()
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	raw, err := wire.ReadFrame(client)
	var reply api.AdminEnrollmentReply
	if err != nil || json.Unmarshal(raw, &reply) != nil || reply.Error == nil || reply.Error.Code != api.CodeDeadline || reply.FailureField != "frame" {
		t.Fatal("expired read deadline made the refusal silent", err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("administrator refusal writer did not stop")
	}
}

func TestEnrollmentReplyBound(t *testing.T) {
	s := fixtureServer(t)
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.writeEnrollmentReply(server, enrollmentResponse{Protocol: api.AdminEnrollmentProtocol, Revision: api.ContractRevision}, "scope",
			serviceError(api.CodeForbidden, strings.Repeat("x", api.MaxFrameBytes+1)))
	}()
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	raw, err := wire.ReadFrame(client)
	var reply api.AdminEnrollmentReply
	if err != nil || json.Unmarshal(raw, &reply) != nil || reply.Error == nil || reply.FailureField != "response" || len(reply.Result) != 0 {
		t.Fatal("administrator reply exceeded its bound", err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("bounded administrator reply did not stop")
	}
}
