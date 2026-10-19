//go:build linux

package admin

import (
	"context"
	"encoding/json"
	"runtime"
	"sync"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// Reproduce the installed lock order: a policy/blob reader owns the store
// RLock while native peer validation calls ResolveContainment. A queued writer
// prevents the broker's CredentialProjection read from entering. Meanwhile
// stop_gate owns the ordinary helper listener and waits on that broker. The
// RWMutex models the store boundary; the existing stall fixture uses actual
// Unix exchanges, the helper's locks and its production method routing. It
// claims no successful installed containment or credential authentication.
func TestStopContainmentCycle(t *testing.T) {
	helper := newStallHelper(t)
	methods := serviceCalls(t, "ResolveContainment")
	// Worker-specific routes return first; the last Service.call is the
	// ordinary lane fallthrough. Use its real method literal and routing.
	method := methods[len(methods)-1]
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	var store sync.RWMutex
	readHeld := make(chan struct{})
	checkPeer := make(chan struct{})
	readDone := make(chan struct{})
	writeDone := make(chan struct{})
	var readErr error
	go func() {
		defer close(readDone)
		store.RLock()
		defer store.RUnlock()
		close(readHeld)
		select {
		case <-checkPeer:
			readErr = helper.send(ctx, method)
		case <-ctx.Done():
			readErr = ctx.Err()
		}
	}()
	<-readHeld
	go func() {
		store.Lock()
		store.Unlock()
		close(writeDone)
	}()
	defer func() {
		cancel()
		<-readDone
		<-writeDone
	}()
	// The original reader still owns RLock, so TryRLock can fail only after
	// the writer has queued. Synchronize that exact order without a sleep.
	for store.TryRLock() {
		store.RUnlock()
		if ctx.Err() != nil {
			t.Fatal("store writer did not queue within the bounded setup")
		}
		runtime.Gosched()
	}
	stallCallback(t, helper, "stop_gate", "begin_withdrawal", func(callCtx context.Context) error {
		// The real credential request has arrived while the helper owns its
		// ordinary listener. Release only the reader's native recheck now.
		close(checkPeer)
		store.RLock()
		defer store.RUnlock()
		select {
		case <-readDone:
			if readErr != nil {
				return readErr
			}
		case <-callCtx.Done():
			return callCtx.Err()
		}
		return callCtx.Err()
	})
	select {
	case <-writeDone:
	case <-ctx.Done():
		t.Fatal("credential callback bypassed the actual queued store writer")
	}
}

func TestLiveContainmentRefusals(t *testing.T) {
	store := &memoryLeases{}
	manager := newLeaseManager(testBinding(), "boot-a", store, &observedResources{})
	for _, sample := range []struct {
		name  string
		input any
		code  api.ErrorCode
	}{
		{"closed", containmentQuery{LeaseID: "absent-lease"}, api.CodeForbidden},
		{"missing", containmentQuery{LeaseID: "absent-lease", Opened: true}, api.CodeNotFound},
		{"invalid", containmentQuery{Opened: true}, api.CodeInvalid},
		{"shape", json.RawMessage(`{"lease_id":"absent-lease","opened":true,"write":true}`), api.CodeInvalid},
	} {
		t.Run(sample.name, func(t *testing.T) {
			raw, err := EncodeWire(sample.input)
			if err != nil {
				t.Fatal(err)
			}
			_, err = manager.dispatch(context.Background(), "containment_live", raw)
			requireCode(t, err, sample.code)
			if store.saveCount != 0 || len(store.records) != 0 {
				t.Fatal("live containment metadata wrote the helper journal")
			}
		})
	}
}
