//go:build linux

package service

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
	"laneboss.io/laneboss/internal/v2/watchdog"
)

// Observe the actual private framer; an optional independent filesystem close
// failure tests that a joined incomplete-framing result cannot hide a fault.
type framingCloseStore struct {
	*store.Service
	stop     context.CancelFunc
	frames   int
	frameErr error
	file     *os.File
	unmarked bool
}

func (s *framingCloseStore) FrameCapture(ctx context.Context, scope api.Scope, id api.ID) ([]api.CaptureRecord, error) {
	records, err := s.Service.FrameCapture(ctx, scope, id)
	s.frames++
	s.frameErr = err
	if s.file != nil {
		err = errors.Join(err, s.file.Close())
	}
	if s.unmarked {
		// The same public verdict/message from an unrelated dependency is
		// deliberately not the framer's private incomplete-evidence condition.
		var cause *api.Error
		if errors.As(err, &cause) {
			err = &api.Error{Code: cause.Code, Owner: cause.Owner, Message: cause.Message, Instead: cause.Instead}
		}
	}
	return records, err
}

func (s *framingCloseStore) PendingEffects(ctx context.Context, request api.CursorRequest) ([]api.Effect, error) {
	effects, err := s.Service.PendingEffects(ctx, request)
	// Cancel only after watchdog classification has returned to the service,
	// so the service must decide whether its earlier error was a host fault.
	s.stop()
	return effects, err
}

type framingQuotaProbe struct {
	api.Runner
	calls int
}

func (p *framingQuotaProbe) LimitFromCapture(context.Context, api.CaptureRecord, api.ProcessObservation) (*api.LimitSignal, error) {
	p.calls++
	return nil, serviceError(api.CodeIntegrity, "incomplete provider evidence reached quota classification")
}

func framingCloseFixture(t *testing.T) (*fx.Fixture, *Server) {
	t.Helper()
	f := fx.New(t)
	f.Start.Driver = api.DriverClaudock
	f.Ceiling.Profiles[0].Driver = api.DriverClaudock
	f.Ceiling.SHA256 = ""
	canonical, err := api.CanonicalJSON(fx.JSON(t, f.Ceiling))
	if err != nil {
		t.Fatal(err)
	}
	f.Ceiling.SHA256 = fx.Digest(canonical)
	f.Replace(t, "grants", f.Ceiling.ID, 1, f.Ceiling)
	f.PlanSetup = func(plan *api.LaunchPlan) {
		plan.Runner.Driver, plan.Runner.Session.Driver = api.DriverClaudock, api.DriverClaudock
		plan.Runner.Slot.Mode = "claudock-headless"
		plan.Data.Home.Home.VendorDirectory, plan.Runner.Home.VendorDirectory = ".claude", ".claude"
	}
	f.Admit(t, "lane.start", f.Start)
	f.Reserve(t)
	input := f.SourceTransaction(t)
	input.Writes.LaunchPlans[0].Inputs.Sources.Runtime.Driver = api.DriverClaudock
	if _, err := f.State.Transact(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	f.Record = input.Writes.LaunchPlans[0]
	f.BuildPlan(t, true)
	f.Spec(t)
	f.Bind(t)
	f.Opened(t)
	return f, launchServer(t, f)
}

func TestCaptureFramingHostClose(t *testing.T) {
	for _, mode := range []string{"eof_pending", "empty_frames", "invalid_frame", "joined_close_fault", "unmarked_prerequisite"} {
		t.Run(mode, func(t *testing.T) {
			f, host := framingCloseFixture(t)
			ctx := context.Background()
			// Explicit outside-job transport/identity is a component fixture.
			// Host capture ingestion, retained bytes, EOF acknowledgements,
			// real SQLite framing and the automatic watchdog all execute.
			streamIndex := 1 // An authentication refusal has stderr, no provider JSON.
			if mode == "invalid_frame" {
				streamIndex = 0
			}
			data := []byte("component credential was refused\n")
			ref, err := host.RetainCapture(ctx, f.Worker, f.Plan.Capture.ID, data)
			if err != nil {
				t.Fatal("host did not ingest actual outside capture bytes", err)
			}
			appendRequest := f.AppendRequest(t, &ref, false)
			appendRequest.Intent = api.InternalIntent{}
			appendRequest.StreamID = f.Plan.Capture.Streams[streamIndex].ID
			receipt, err := host.AppendCapture(ctx, f.Worker, appendRequest)
			if err != nil || receipt.NextOffset != int64(len(data)) {
				t.Fatal("host did not acknowledge its actual captured range", err)
			}
			generation := receipt.Generation
			for index, stream := range f.Plan.Capture.Streams {
				if mode == "eof_pending" && index == 0 {
					continue
				}
				request := f.AppendRequest(t, nil, true)
				request.Intent = api.InternalIntent{}
				request.StreamID, request.ExpectedGeneration = stream.ID, generation
				if index == streamIndex {
					request.Offset = int64(len(data))
				}
				receipt, err := host.AppendCapture(ctx, f.Worker, request)
				if err != nil || !receipt.EOF {
					t.Fatal("host did not retain its real stream EOF", err)
				}
				generation = receipt.Generation
			}
			f.Ended(t, 1)
			before, err := f.State.HealthSnapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			runCtx, stop := context.WithTimeout(ctx, 5*time.Second)
			defer stop()
			state := &framingCloseStore{Service: f.State, stop: stop, unmarked: mode == "unmarked_prerequisite"}
			if mode == "joined_close_fault" {
				state.file, err = os.CreateTemp(t.TempDir(), "framing-owned-")
				if err != nil {
					t.Fatal(err)
				}
				if err := state.file.Close(); err != nil {
					t.Fatal(err)
				}
			}
			quota := &framingQuotaProbe{}
			// These unused authority ports fail if unexpected calls reach them;
			// incomplete framing cannot authorize profile selection or a launch.
			driver, err := watchdog.New(watchdog.Dependencies{Config: f.Deps.Config, Store: state, Clock: f.Deps.Clock,
				Claudock: quota, Credentials: &struct{ api.CredentialBroker }{}, Lifecycle: &struct{ api.Continuation }{},
				Launcher: &struct{ api.Launcher }{}, Grants: &struct{ api.GrantResolver }{}})
			if err != nil {
				t.Fatal(err)
			}
			host.deps.Store, host.runtime.Watchdog = state, driver
			host.reconcileLoop(runCtx)
			if runCtx.Err() != context.Canceled || state.frames != 1 || quota.calls != 0 {
				t.Fatal("host did not classify the actual ended capture exactly once", runCtx.Err(), state.frames, quota.calls)
			}
			var cause *api.Error
			wantCode := api.CodePrerequisite
			if mode == "invalid_frame" {
				wantCode = api.CodeIntegrity
			}
			if !errors.As(state.frameErr, &cause) || cause.Code != wantCode {
				t.Fatal("framing did not reach its real missing-evidence or integrity result", state.frameErr)
			}
			after, err := f.State.HealthSnapshot(ctx)
			if err != nil || after.LastSeq != before.LastSeq {
				t.Fatal("incomplete framing fabricated a domain result", err)
			}
			lane, err := f.State.Lane(ctx, f.Execution, f.Reservation.Target)
			if err != nil || !reflect.DeepEqual(lane, f.Lane) {
				t.Fatal("quota classification changed the ended lane without provider evidence", err)
			}
			closed := host.Close()
			if mode == "eof_pending" || mode == "empty_frames" {
				if closed != nil {
					t.Fatalf("per-run framing prerequisite poisoned host close: %v", closed)
				}
			} else {
				if closed == nil {
					t.Fatal("host close discarded a genuine or unmarked dependency failure")
				}
				if mode == "joined_close_fault" && !errors.Is(closed, os.ErrClosed) {
					t.Fatal("host lost the independent joined native close failure", closed)
				}
				if mode != "joined_close_fault" {
					codeIs(t, closed, wantCode)
				}
			}
		})
	}
}
