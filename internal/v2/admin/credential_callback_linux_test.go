//go:build linux

package admin

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// Actual Unix frames, SCM writers and pidfd lifetime exercise the private
// exchange. The callback models a metadata operation taking the helper
// state lock; it performs no credential projection or privileged namespace work.
func TestCredentialMetadataCall(t *testing.T) {
	for _, current := range []bool{true, false} {
		name := "current"
		if !current {
			name = "foreign"
		}
		t.Run(name, func(t *testing.T) {
			client, server := nativePair(t)
			peer, serverPeer := nativePeer(t, client), nativePeer(t, server)
			var operation sync.Mutex
			channel := &credentialChannel{connection: client, peer: peer, operationMu: &operation}
			callback := make(chan error, 1)
			go func() {
				data, err := readUnixFrame(server, serverPeer)
				if err != nil {
					callback <- err
					return
				}
				var request helperRequest
				if err := decodeStrict(data, &request); err != nil {
					callback <- err
					return
				}
				response := helperResponse{Protocol: credentialProtocol, Revision: api.ContractRevision, Nonce: request.Nonce, Result: json.RawMessage(`{}`)}
				if operation.TryLock() {
					operation.Unlock()
				} else {
					response.Result = nil
					response.Error = failure(api.CodeConflict, "native metadata reader stayed blocked")
				}
				callback <- writeFrame(server, response)
			}()
			operation.Lock()
			defer operation.Unlock()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if current {
				ctx = context.WithValue(ctx, credentialOperationKey{}, &operation)
			}
			var result api.Empty
			request := helperRequest{Protocol: credentialProtocol, Revision: api.ContractRevision, Config: "admin-case", Generation: 1, ArtifactSHA256: testDigest("callback-exchange"), Nonce: "callback-live", Method: "component_read", Params: json.RawMessage(`{}`)}
			_, err := channel.exchange(ctx, request, &result, nil, false, time.Now().Add(time.Second), func() error { return errors.Join(channel.transportAlive(), peer.alive()) })
			if current && err != nil {
				t.Fatal("metadata recheck could not run while native owner was pending", err)
			}
			if !current {
				var refused *api.Error
				if !errors.As(err, &refused) || refused.Code != api.CodeConflict {
					t.Fatal("foreign callback context lent helper mutation authority", err)
				}
			}
			if err := <-callback; err != nil {
				t.Fatal(err)
			}
			if operation.TryLock() {
				operation.Unlock()
				t.Fatal("native call resumed mutations without regaining its helper state lock")
			}
		})
	}
}
