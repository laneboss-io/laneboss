//go:build linux

package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/store"
)

// Pause only at the SQL call boundary so a requested stop deterministically
// lands between the reconciler's context check and the real outbox query.
// The query, its error, lane state and store close are production code.
type shutdownOutboxStore struct {
	*store.Service
	entered chan struct{}
	queried chan error
	file    *os.File
	closes  int
}

func (s *shutdownOutboxStore) PendingEffects(ctx context.Context, request api.CursorRequest) ([]api.Effect, error) {
	close(s.entered)
	<-ctx.Done()
	effects, err := s.Service.PendingEffects(ctx, request)
	s.queried <- err
	return effects, err
}

func (s *shutdownOutboxStore) Close() error {
	s.closes++
	err := s.Service.Close()
	if s.file != nil {
		err = errors.Join(err, s.file.Close())
	}
	return err
}

func TestHostCloseAfterOutboxCancel(t *testing.T) {
	for _, mode := range []string{"requested_stop", "store_close_failure", "prior_integrity", "worker_drain_failure"} {
		t.Run(mode, func(t *testing.T) {
			directory := privateHostDirectory(t)
			actual, err := store.New(store.Dependencies{Config: "service-fixture", Directory: directory, Clock: fixtureClock{}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := actual.Close(); err != nil {
					t.Error(err)
				}
			})
			caller, record := socketRecord(t, &actual, directory)
			state := &shutdownOutboxStore{Service: actual, entered: make(chan struct{}), queried: make(chan error, 1)}
			host := fixtureServer(t)
			host.deps.Store = state
			host.deps.Authenticator = &authFixture{scope: caller, store: actual}
			host.deps.Binding.LaunchID = caller.LaunchID
			host.deps.Binding.Target = &api.LifeRef{LifeID: caller.Actor.LifeID, Run: 1}
			host.deps.Binding.Socket = filepath.Join(directory, "lane.sock")
			host.deps.Binding.ServiceUID = uint32(os.Geteuid())
			host.deps.Binding.ServiceGID = uint32(os.Getegid())
			host.verified, host.bound = true, true
			if err := host.Register("records.query", func(ctx context.Context, scope api.Scope, raw json.RawMessage) (json.RawMessage, error) {
				var request api.RecordQuery
				if err := wire.Decode(raw, &request); err != nil {
					return nil, err
				}
				page, err := actual.Records(ctx, scope, request)
				if err != nil {
					return nil, err
				}
				return json.Marshal(page)
			}); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			served := make(chan error, 1)
			go func() { served <- host.ServeInstalled(ctx) }()
			select {
			case <-state.entered:
			case err := <-served:
				t.Fatal("installed host stopped before its outbox read", err)
			case <-time.After(5 * time.Second):
				t.Fatal("reconciler did not reach the actual outbox read")
			}
			// This is an opened lane's real native request and scoped SQLite
			// result, not a host constructed just to call Close on it.
			client, err := net.DialTimeout("unix", host.deps.Binding.Socket, 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			request := requestFor(t, "records.query", api.RecordQuery{Collection: record.Collection, SearchMode: "keyword", Limit: 200})
			input, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			if err := wire.WriteFrame(client, input); err != nil {
				t.Fatal(err)
			}
			output, err := wire.ReadFrame(client)
			if err != nil {
				t.Fatal(err)
			}
			response, err := wire.DecodeResponse(output, request)
			var page api.RecordPage
			if err != nil || response.Error != nil || wire.Decode(response.Result, &page) != nil || len(page.Records) != 1 || page.Records[0].ID != record.ID {
				t.Fatal("shutdown fixture did not serve its opened lane", err, response.Error)
			}
			if mode == "store_close_failure" {
				state.file, err = os.CreateTemp(directory, "owned-close-")
				if err != nil {
					t.Fatal(err)
				}
				if err := state.file.Close(); err != nil {
					t.Fatal(err)
				}
			}
			prior := serviceError(api.CodeIntegrity, "retained runtime integrity failure")
			if mode == "prior_integrity" {
				host.recordFault(prior)
			}
			if mode == "worker_drain_failure" {
				host.workers.Add(1)
				defer host.workers.Done()
			}
			journal, err := os.Create(filepath.Join(directory, "close.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			previous := os.Stderr
			os.Stderr = journal
			closed := host.Close()
			select {
			case err := <-served:
				codeIs(t, err, api.CodeCancelled)
			case <-time.After(5 * time.Second):
				t.Error("installed host did not finish its requested stop")
			}
			os.Stderr = previous
			if err := journal.Close(); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(journal.Name())
			if err != nil {
				t.Fatal(err)
			}
			type closeEvent struct {
				Event   string `json:"event"`
				Closer  string `json:"closer"`
				Code    string `json:"code"`
				Owner   string `json:"owner"`
				Message string `json:"message"`
			}
			var events []closeEvent
			for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte{'\n'}) {
				if len(line) == 0 {
					continue
				}
				var event closeEvent
				if err := json.Unmarshal(line, &event); err != nil {
					t.Fatal("host journal was not JSONL", err)
				}
				if event.Event == "service_close_error" {
					events = append(events, event)
				}
			}
			queryErr := <-state.queried
			if queryErr != context.Canceled {
				t.Errorf("outbox changed requested cancellation into a fault: %v", queryErr)
			}
			if mode == "requested_stop" {
				if closed != nil || len(events) != 0 {
					t.Fatalf("requested stop after serving a lane failed: close=%v journal=%s", closed, raw)
				}
				if state.closes != 1 {
					t.Fatal("requested stop did not close its actual writer exactly once")
				}
			} else {
				if closed == nil {
					t.Fatal("actual cleanup or runtime failure was discarded")
				}
				closer := "store"
				if mode == "store_close_failure" && !errors.Is(closed, os.ErrClosed) {
					t.Fatal("host discarded its actual owned file close failure", closed)
				}
				if mode == "prior_integrity" {
					closer = "prior_fault"
					if !errors.Is(closed, prior) {
						t.Fatal("host discarded its retained integrity failure", closed)
					}
				}
				if mode == "worker_drain_failure" {
					closer = "worker_drain"
					if state.closes != 0 {
						t.Fatal("host closed the store while a worker still owned it")
					}
				}
				if len(events) != 1 {
					t.Fatalf("close failure did not produce exactly one journal event: %s", raw)
				}
				event := events[0]
				if event.Closer != closer || event.Code != "integrity" || event.Owner != "lb-v2-service" || event.Message == "" {
					t.Fatalf("close diagnostic lost its actual source and verdict: %s", raw)
				}
				if bytes.Contains(raw, []byte(directory)) {
					t.Fatal("close journal leaked a native path")
				}
			}
			if repeated := host.Close(); repeated != closed {
				t.Fatal("repeated close changed the retained result")
			}
		})
	}
}
