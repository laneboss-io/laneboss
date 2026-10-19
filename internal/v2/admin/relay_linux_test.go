//go:build linux

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
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func awaitRelay(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("relay fixture did not finish within its bound")
		return nil
	}
}

// Exercise the production transport/window adapters over two real native
// connections. This is a transport component, not an installed identity proof.
func relayPeerCase(t *testing.T, mode string) {
	t.Helper()
	caller, responder := nativePair(t)
	forwarder, remote := nativePair(t)
	callerPeer := nativePeer(t, caller)
	forwardPeer := nativePeer(t, forwarder)
	remotePeer := nativePeer(t, remote)
	nonce, err := randomID("relay-")
	if err != nil {
		t.Fatal(err)
	}
	value, err := randomID("reply-")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(struct{ Value api.ID }{value})
	if err != nil {
		t.Fatal(err)
	}
	request := helperRequest{Protocol: helperProtocol, Revision: api.ContractRevision, Nonce: nonce, Method: "probe", Params: json.RawMessage(`{}`)}
	requestBytes, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	response := helperResponse{Protocol: helperProtocol, Revision: api.ContractRevision, Nonce: nonce, Result: payload}
	workLimit := time.Second
	if mode == "late" {
		workLimit = 150 * time.Millisecond
	}
	window, err := openHelperWindow(context.Background(), responder, workLimit, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer window.finish()
	stop, err := bindHelperCall(window.work, forwarder)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	remoteResult, relayResult := make(chan error, 1), make(chan error, 1)
	relayDone := make(chan struct{})
	go func() {
		data, err := readUnixFrame(remote, remotePeer)
		if err != nil {
			remoteResult <- err
			return
		}
		if !bytes.Equal(data, requestBytes) {
			remoteResult <- errors.New("remote received different request bytes")
			return
		}
		switch mode {
		case "closed":
			remoteResult <- remote.Close()
			return
		case "late":
			<-window.work.Done()
			<-relayDone // The peer attempts its reply after the timed-out hop closes.
		default:
			timer := time.NewTimer(20 * time.Millisecond)
			defer timer.Stop()
			<-timer.C
		}
		remoteResult <- writeFrame(remote, response)
	}()
	go func() {
		defer close(relayDone)
		defer forwarder.Close()
		if err := writeFrame(forwarder, request); err != nil {
			relayResult <- err
			return
		}
		data, err := readHelperFrame(window.work, forwarder, forwardPeer)
		if err != nil {
			relayResult <- window.refuse(helperProtocol, nonce, err)
			return
		}
		var reply helperResponse
		if err := decodeStrict(data, &reply); err != nil {
			relayResult <- err
			return
		}
		relayResult <- window.write(reply)
	}()
	data, err := readUnixFrame(caller, callerPeer)
	if err != nil {
		t.Fatalf("acceptance: relay timeout refusal was lost: %v", err)
	}
	var reply helperResponse
	if err := decodeStrict(data, &reply); err != nil {
		t.Fatal(err)
	}
	if reply.Nonce != nonce || reply.Protocol != helperProtocol || reply.Revision != api.ContractRevision {
		t.Fatal("relay lost its exact response binding")
	}
	relayErr, remoteErr := awaitRelay(t, relayResult), awaitRelay(t, remoteResult)
	switch mode {
	case "within":
		if reply.Error != nil || !bytes.Equal(reply.Result, payload) || relayErr != nil || remoteErr != nil {
			t.Fatal("acceptance: in-budget peer reply was not preserved")
		}
	case "late":
		if reply.Error == nil || reply.Error.Code != api.CodeDeadline || reply.Error.Owner != owner || len(reply.Result) != 0 {
			t.Fatal("acceptance: relay timeout refusal was lost")
		}
		requireCode(t, relayErr, api.CodeDeadline)
		if remoteErr == nil {
			t.Fatal("acceptance: expired forwarding socket accepted a late reply")
		}
	case "closed":
		if reply.Error == nil || reply.Error.Code != api.CodeUnavailable || reply.Error.Message != "helper frame peer closed" || len(reply.Result) != 0 || remoteErr != nil {
			t.Fatal("acceptance: closed peer refusal was not preserved")
		}
		requireCode(t, relayErr, api.CodeUnavailable)
	}
}

func TestRelaySlowPeer(t *testing.T)  { relayPeerCase(t, "within") }
func TestRelayLateReply(t *testing.T) { relayPeerCase(t, "late") }
func TestRelayClosed(t *testing.T)    { relayPeerCase(t, "closed") }

func TestPeerReceive(t *testing.T) {
	for _, mode := range []string{"timeout", "closed", "partial", "length"} {
		t.Run(mode, func(t *testing.T) {
			reader, writer := nativePair(t)
			peer := nativePeer(t, reader)
			code, message := api.CodeInvalid, "helper frame malformed"
			switch mode {
			case "timeout":
				code, message = api.CodeDeadline, "helper frame receive timeout"
				if err := reader.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
					t.Fatal(err)
				}
			case "closed":
				code, message = api.CodeUnavailable, "helper frame peer closed"
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
			case "partial":
				if _, err := writer.Write([]byte{0, 0}); err != nil {
					t.Fatal(err)
				}
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
			case "length":
				message = "helper frame malformed length"
				if _, err := writer.Write([]byte{0, 0, 0, 0}); err != nil {
					t.Fatal(err)
				}
			}
			_, err := readUnixFrame(reader, peer)
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != code || typed.Message != message || typed.Owner != owner {
				t.Fatal("acceptance: peer receive category was lost")
			}
		})
	}
}

func TestReceiveSanitized(t *testing.T) {
	for _, cause := range []error{os.ErrDeadlineExceeded, io.EOF, io.ErrUnexpectedEOF, errors.New("native-canary")} {
		native := &net.OpError{Op: "native-canary", Net: "unix", Addr: &net.UnixAddr{Name: "/native-canary"}, Err: cause}
		err := helperReceiveError(fmt.Errorf("native-canary: %w", native), false)
		data, encodeErr := json.Marshal(err)
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		if bytes.Contains(data, []byte("native-canary")) || errors.Unwrap(err) != nil {
			t.Fatal("acceptance: helper receive leaked an inner cause")
		}
	}
	refusal := &api.Error{Code: api.CodeDeadline, Owner: "lb-v2-service", Message: "native-canary", Instead: "native-canary"}
	data, err := json.Marshal(helperReplyDiagnostic(refusal))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]string
	if json.Unmarshal(data, &fields) != nil || len(fields) != 3 || fields["stage"] != "response_write" || fields["code"] != string(api.CodeDeadline) || fields["owner"] != "lb-v2-service" || bytes.Contains(data, []byte("native-canary")) {
		t.Fatal("acceptance: undelivered refusal diagnostic lost its safe fields")
	}
}

func TestHelperBudgets(t *testing.T) {
	if serviceCallBudget >= enrollmentForwardTimeout || enrollmentForwardTimeout >= helperWorkTimeout || helperWorkTimeout+helperReplyTimeout >= helperCallTimeout {
		t.Fatal("acceptance: relay hop has no caller reply budget")
	}
	for _, limit := range []time.Duration{helperCallTimeout, 8 * time.Second} {
		parent, cancel := context.WithTimeout(context.Background(), limit)
		reader, _ := nativePair(t)
		window, err := openHelperWindow(parent, reader, helperWorkTimeout, helperReplyTimeout)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		forward, stopForward := helperForwardContext(window.work)
		outer, _ := parent.Deadline()
		transport, _ := window.transport.Deadline()
		work, _ := window.work.Deadline()
		inner, _ := forward.Deadline()
		if transport.After(outer) || transport.Sub(work) < helperReplyTimeout || work.Sub(inner) < helperReplyTimeout {
			t.Fatal("acceptance: shortened parent lost its reserved reply windows")
		}
		if limit == helperCallTimeout {
			if err := helperServiceBudget(forward); err != nil {
				t.Fatal(err)
			}
		} else if err := helperServiceBudget(forward); err == nil {
			t.Fatal("acceptance: shortened relay started work without a service reply budget")
		}
		stopForward()
		window.finish()
		cancel()
	}
}

func TestRelayCancel(t *testing.T) {
	reader, _ := nativePair(t)
	peer := nativePeer(t, reader)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	stop, err := bindHelperCall(ctx, reader)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	done := make(chan error, 1)
	go func() { _, err := readHelperFrame(ctx, reader, peer); done <- err }()
	cancel()
	select {
	case err := <-done:
		requireCode(t, err, api.CodeCancelled)
	case <-time.After(time.Second):
		t.Fatal("acceptance: cancellation did not close the forwarding socket")
	}
}

func TestWindowCancel(t *testing.T) {
	reader, writer := nativePair(t)
	peer := nativePeer(t, reader)
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	window, err := openHelperWindow(parent, writer, helperWorkTimeout, helperReplyTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer window.finish()
	done := make(chan error, 1)
	go func() { _, err := readUnixFrame(reader, peer); done <- err }()
	cancel()
	select {
	case err := <-done:
		requireCode(t, err, api.CodeUnavailable)
	case <-time.After(time.Second):
		t.Fatal("acceptance: parent cancellation kept the reply transport open")
	}
}

func TestReplyBound(t *testing.T) {
	reader, writer := net.Pipe()
	defer reader.Close()
	defer writer.Close()
	window, err := openHelperWindow(context.Background(), writer, time.Second, 30*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer window.finish()
	done := make(chan error, 1)
	go func() {
		done <- window.refuse(helperProtocol, "", failure(api.CodeDeadline, "helper frame receive timeout"))
	}()
	select {
	case err := <-done:
		requireCode(t, err, api.CodeUnavailable)
	case <-time.After(300 * time.Millisecond):
		t.Fatal("acceptance: refusal write exceeded its short reply window")
	}
}

func TestRelayCaller(t *testing.T) {
	for _, method := range []string{enrollmentRelayMethod, "probe", "allocate", "data_open", "initial_publish", "unknown"} {
		for _, root := range []bool{true, false} {
			err := enrollmentCaller(root, method)
			if root == (method == enrollmentRelayMethod) {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("acceptance: relay crossed its fixed native caller boundary")
			}
		}
	}
}

func TestRelayBinding(t *testing.T) {
	_, _, _, _, endpoint := initialEnrollmentFixture(t)
	binding := installation{Config: endpoint.Config, Generation: endpoint.InstallationGeneration, Artifact: api.ReleaseArtifact{SHA256: endpoint.Helper.SHA256}}
	for _, method := range []string{"enroll_begin", "enroll_complete", "initial_publish"} {
		frame, err := newEnrollmentFrame(binding, endpoint, method, json.RawMessage(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		input := enrollmentForward{Endpoint: endpoint, Frame: frame}
		if err := validateEnrollmentForward(input, endpoint); err != nil {
			t.Fatal(err)
		}
		input.Endpoint.Socket += ".foreign"
		if err := validateEnrollmentForward(input, endpoint); err == nil {
			t.Fatal("acceptance: relay trusted a caller-selected endpoint")
		}
		input.Endpoint = endpoint
		input.Frame.Nonce = "short"
		if err := validateEnrollmentForward(input, endpoint); err == nil {
			t.Fatal("acceptance: relay accepted a malformed native envelope")
		}
	}
}
