//go:build linux

package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestWorkerTurnWaitJournal(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		name := "released"
		if cancelled {
			name = "cancelled"
		}
		t.Run(name, func(t *testing.T) {
			host := &Server{}
			lease := api.ID("private-worker-selector")
			release, err := host.workerTurn(context.Background(), lease, "archive_observe")
			if err != nil {
				t.Fatal(err)
			}
			var once sync.Once
			finishOwner := func() { once.Do(release) }
			defer finishOwner()
			var journal bytes.Buffer
			ctx := context.WithValue(context.Background(), workerTurnLogKey{}, &journal)
			ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			after := finishOwner
			if cancelled {
				after = cancel
			}
			timer := time.AfterFunc(1250*time.Millisecond, after)
			defer timer.Stop()
			started := time.Now()
			finish, err := host.workerTurn(ctx, lease, string(api.WorkerInputRead))
			if elapsed := time.Since(started); elapsed < time.Second {
				t.Fatal("worker turn did not actually wait for its live owner")
			}
			if cancelled {
				var typed *api.Error
				if finish != nil || !errors.As(err, &typed) || typed.Code != api.CodeCancelled {
					t.Fatal("wait journal changed the original cancellation result", err)
				}
				host.mu.RLock()
				held := host.flights["worker-call:"+string(lease)] != nil
				host.mu.RUnlock()
				if !held {
					t.Fatal("cancelled waiter released another operation's turn")
				}
			} else {
				if err != nil || finish == nil {
					t.Fatal("wait journal changed the original turn handoff", err)
				}
				finish()
			}
			var entry struct {
				Event     string `json:"event"`
				Stage     string `json:"stage"`
				Operation string `json:"operation"`
				Holder    string `json:"holder"`
				WaitMS    int64  `json:"wait_ms"`
				HoldMS    int64  `json:"hold_ms"`
			}
			if bytes.Count(journal.Bytes(), []byte{'\n'}) != 1 || json.Unmarshal(journal.Bytes(), &entry) != nil ||
				entry.Event != "worker_call" || entry.Stage != "turn_wait" || entry.Operation != "input.read" ||
				entry.Holder != "archive_observe" || entry.WaitMS < 1000 || entry.HoldMS < 1000 || bytes.Contains(journal.Bytes(), []byte(lease)) {
				t.Fatal("worker wait did not capture one bounded turn-wait line naming its holder")
			}
			t.Logf("captured turn-wait line: %s", journal.Bytes())
			finishOwner()
			journal.Reset()
			finish, err = host.workerTurn(ctx, lease, string(api.WorkerInputRead))
			if cancelled {
				if err == nil || finish != nil {
					t.Fatal("cancelled control acquired a new turn")
				}
			} else {
				if err != nil || finish == nil {
					t.Fatal("uncontended control could not acquire its turn", err)
				}
				finish()
			}
			if journal.Len() != 0 {
				t.Fatal("uncontended control emitted a slow-wait line")
			}
		})
	}
}
