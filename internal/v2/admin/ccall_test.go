//go:build linux

package admin

import (
	"context"
	"encoding/json"
	"errors"
	"runtime/debug"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// Real socket deadlines and SCM credentials exercise the production exchange.
// This is a transport component, not installed broker/catalog authentication.
func TestCredCallFailure(t *testing.T) {
	// A finalizer must not hide a leaked received descriptor before inventory.
	previous := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(previous)
	for _, mode := range []string{"deadline", "cancel", "decode", "nonce", "refusal", "refusal-fd", "refusal-rights", "refusal-nonce", "refusal-result", "refusal-reason", "refusal-empty-reason"} {
		t.Run(mode, func(t *testing.T) {
			client, server := nativePair(t)
			channel := &credentialChannel{connection: client, peer: nativePeer(t, client)}
			serverPeer := nativePeer(t, server)
			file, _ := credentialCanary(t)
			aliases := credentialAliasCount(t, file)
			request := helperRequest{Protocol: credentialProtocol, Revision: api.ContractRevision, Config: "admin-case", Generation: 1, ArtifactSHA256: testDigest("ordinary-exchange"), Nonce: "exchange-once", Method: "check", Params: json.RawMessage(`{}`)}
			callCtx, cancel := context.WithCancel(context.Background())
			defer cancel()
			exchangeDeadline := time.Now().Add(200 * time.Millisecond)
			if mode == "cancel" {
				exchangeDeadline = time.Now().Add(time.Hour)
			}
			finished := make(chan error, 1)
			go func() {
				channel.mu.Lock()
				defer channel.mu.Unlock()
				var result api.Empty
				_, err := channel.exchange(callCtx, request, &result, nil, mode == "refusal-rights", exchangeDeadline, channel.transportAlive)
				finished <- err
			}()
			data, err := readUnixFrame(server, serverPeer)
			if err != nil {
				t.Fatal("exchange did not write its actual request before refusal")
			}
			var observed helperRequest
			if decodeStrict(data, &observed) != nil || observed.Nonce != request.Nonce {
				t.Fatal("exchange request correlation control failed")
			}
			if mode == "cancel" {
				cancel()
			}
			reply := helperResponse{Protocol: credentialProtocol, Revision: api.ContractRevision, Nonce: observed.Nonce, Result: json.RawMessage(`{}`)}
			if mode != "deadline" && mode != "cancel" {
				switch mode {
				case "decode":
					reply.Result = json.RawMessage(`{"unexpected":true}`)
				case "nonce":
					reply.Nonce = "another-exchange"
				case "refusal", "refusal-fd", "refusal-rights", "refusal-nonce", "refusal-result", "refusal-reason", "refusal-empty-reason":
					reply.Result = nil
					reply.Error = failure(api.CodeUnavailable, "ordinary owner refusal")
					if mode == "refusal-nonce" {
						reply.Nonce = "another-exchange"
					}
					if mode == "refusal-result" {
						reply.Result = json.RawMessage(`{}`)
					}
					if mode == "refusal-reason" {
						reply.Reason = "storage_parent"
					}
				}
				if mode == "refusal-fd" || mode == "refusal-rights" {
					body, err := json.Marshal(reply)
					if err != nil {
						t.Fatal(err)
					}
					data, err := frame(body)
					if err != nil {
						t.Fatal(err)
					}
					rights := unix.UnixRights(int(file.Fd()))
					if n, oob, err := server.WriteMsgUnix(data, rights, nil); err != nil || n != len(data) || oob != len(rights) {
						t.Fatal("cannot send actual refusal with descriptor")
					}
				} else {
					var value any = reply
					if mode == "refusal-empty-reason" {
						value = struct {
							helperResponse
							Reason string `json:"reason"`
						}{helperResponse: reply}
					}
					if err := writeFrame(server, value); err != nil {
						t.Fatal("cannot send actual refused exchange reply")
					}
				}
			}
			if mode == "cancel" {
				select {
				case err = <-finished:
				case <-time.After(2 * time.Second):
					t.Fatal("acceptance: credential cancellation did not interrupt exchange")
				}
			} else {
				err = <-finished
			}
			if credentialAliasCount(t, file) != aliases {
				t.Fatal("acceptance: credential refusal bypassed descriptor disposition")
			}
			if mode == "refusal" {
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != api.CodeUnavailable || channel.transportAlive() != nil {
					t.Fatal("acceptance: correlated refusal consumed the shared stream")
				}
				cancel() // A completed call's cancellation must not affect reuse.
				next := request
				next.Nonce = "exchange-after-refusal"
				go func() {
					channel.mu.Lock()
					defer channel.mu.Unlock()
					var result api.Empty
					_, err := channel.exchange(context.Background(), next, &result, nil, false, time.Now().Add(200*time.Millisecond), channel.transportAlive)
					finished <- err
				}()
				data, err := readUnixFrame(server, serverPeer)
				if err != nil || decodeStrict(data, &observed) != nil || observed.Nonce != next.Nonce {
					t.Fatal("acceptance: correlated refusal prevented the next exchange")
				}
				if err := writeFrame(server, helperResponse{Protocol: credentialProtocol, Revision: api.ContractRevision, Nonce: observed.Nonce, Result: json.RawMessage(`{}`)}); err != nil {
					t.Fatal("acceptance: correlated refusal prevented the next exchange")
				}
				if err := <-finished; err != nil || channel.transportAlive() != nil {
					t.Fatal("acceptance: correlated refusal prevented the next exchange")
				}
				return
			}
			if mode == "refusal-fd" || mode == "refusal-rights" {
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != api.CodeUnauthenticated || channel.transportAlive() == nil {
					t.Fatal("acceptance: credential refusal bypassed descriptor disposition")
				}
			} else if mode == "refusal-nonce" || mode == "refusal-result" || mode == "refusal-reason" || mode == "refusal-empty-reason" {
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != api.CodeUnauthenticated {
					t.Fatal("acceptance: invalid refusal was accepted as correlated")
				}
			}
			// Background remains live: the deadline case must close because of
			// the socket timeout, independently of context cancellation.
			if err == nil || channel.transportAlive() == nil {
				t.Fatal("acceptance: failed credential exchange retained its stream")
			}
			if err := writeFrame(server, helperResponse{Protocol: credentialProtocol, Revision: api.ContractRevision, Nonce: request.Nonce, Result: json.RawMessage(`{}`)}); err == nil {
				t.Fatal("acceptance: late credential reply reached a reused stream")
			}
		})
	}
}

func TestCredInvalidOwner(t *testing.T) {
	for _, endpoint := range []string{"credential-broker.sock", "credential-identity.sock"} {
		t.Run(endpoint, func(t *testing.T) {
			client, server := nativePair(t)
			channel := &credentialChannel{connection: client, peer: nativePeer(t, client), socket: endpoint}
			serverPeer := nativePeer(t, server)
			var invalid api.Empty
			cause := api.DecodeObject([]byte(`{"unexpected":true}`), &invalid)
			var typed *api.Error
			if !errors.As(cause, &typed) || typed.Code != api.CodeInvalid || typed.Owner != "" {
				t.Fatal("control did not produce an anonymous schema refusal", cause)
			}
			request := helperRequest{Protocol: credentialProtocol, Revision: api.ContractRevision, Config: "admin-case", Generation: 1,
				ArtifactSHA256: testDigest("owner-exchange"), Nonce: "owner-once", Method: "check", Params: json.RawMessage(`{}`)}
			finished := make(chan error, 1)
			go func() {
				var result api.Empty
				_, err := channel.exchange(context.Background(), request, &result, nil, false, time.Now().Add(time.Second), channel.transportAlive)
				finished <- err
			}()
			data, err := readUnixFrame(server, serverPeer)
			var observed helperRequest
			if err != nil || decodeStrict(data, &observed) != nil || observed.Nonce != request.Nonce {
				t.Fatal("owner exchange request was not correlated", err)
			}
			if err := writeFrame(server, credentialResponse{Protocol: credentialProtocol, Revision: api.ContractRevision, Nonce: observed.Nonce, Error: typed}); err != nil {
				t.Fatal(err)
			}
			err = <-finished
			component := "secrets"
			if endpoint == "credential-identity.sock" {
				component = "identity"
			}
			if !errors.As(err, &typed) || typed.Code != api.CodeInvalid || typed.Retryable || api.ErrorComponent(err) != component || channel.transportAlive() != nil {
				t.Fatal("correlated credential schema refusal lost its native owner", err)
			}
		})
	}
}
