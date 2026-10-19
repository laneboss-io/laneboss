package boxrun

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"laneboss.io/laneboss/internal/boxcore"
)

// End sends the done marker and records only provider-observed end states.
func (s *service) End(ctx context.Context, o boxcore.EndOptions) (boxcore.EndResult, error) {
	return s.end(ctx, o, nil, boxcore.Box{}, "", boxcore.TransportOptions{})
}

func (s *service) end(ctx context.Context, o boxcore.EndOptions, extra map[string]any,
	known boxcore.Box, knownRunID string, transportOpts boxcore.TransportOptions) (boxcore.EndResult, error) {
	result := boxcore.EndResult{ExitCode: boxcore.ExitUsage}
	if err := s.configured(); err != nil {
		return result, err
	}
	p, err := s.provider(o.Provider)
	if err != nil {
		return result, err
	}
	if o.ID == "" {
		return result, errors.New("boxrun: end needs an instance id")
	}
	if o.BoundSec <= 0 {
		o.BoundSec = 600
	}
	if o.PollSec <= 0 {
		o.PollSec = 15
	}
	events, ledgerErr := s.events()
	if ledgerErr != nil {
		s.note("read ledger for %s: %v", o.ID, ledgerErr)
	}
	b := known
	runID := knownRunID
	if event := launchEvent(events, o.Provider, o.ID); event != nil {
		b = boxFromEvent(event)
		runID = text(event, "run_id")
		if known.ID == b.ID {
			b.Labels = known.Labels
			b.Address = known.Address
		}
		if b.Labels == nil && runID != "" {
			// The run the ledger recorded: a provider that reads the machine's own run label refuses a machine of another run.
			b.Labels = map[string]string{"lb-run": boxcore.GCPLabelValue(runID)}
		}
	} else {
		s.note("no LAUNCHED ledger line for %s; ending from supplied facts", o.ID)
	}
	b.ID, b.Provider = o.ID, o.Provider
	if o.Address != "" {
		b.Address = o.Address
	}
	// A standalone end has no run directory yet: keep the box's host key out of the personal known_hosts file.
	if transportOpts.KnownHostsFile == "" && s.d.Config.Defaults.RunDir != "" && boxcore.PlainName(b.ID) {
		sub := runID
		if !boxcore.PlainName(sub) {
			sub = "standalone"
		}
		dir := filepath.Join(s.d.Config.Defaults.RunDir, sub)
		if err := os.MkdirAll(dir, 0700); err == nil {
			transportOpts.KnownHostsFile = filepath.Join(dir, "known_hosts."+b.ID)
		}
	}
	command, commandErr := doneCommand(s.d.Config.Guest.DoneFiles)
	done := "transport-failed"
	if commandErr == nil {
		markerStart := s.d.Now()
		code, execErr := markerExec(ctx, p, b, transportOpts, command)
		switch {
		case execErr != nil && b.Address == "" && boxcore.KindOf(execErr) == boxcore.KindTransport &&
			s.d.Now().Sub(markerStart) < time.Second && !errors.Is(execErr, context.DeadlineExceeded):
			done = "no-address"
		case execErr != nil:
			s.note("done marker for %s: %v", b.ID, execErr)
		case code != 0:
			done = fmt.Sprintf("exec-failed:rc=%d", code)
		default:
			done = "ok"
		}
	} else {
		ledgerErr = errors.Join(ledgerErr, commandErr)
		s.note("done marker for %s: %v", b.ID, commandErr)
	}
	if _, err := s.appendEvent("DONE_SENT", doneFields(b, runID, done, extra)); err != nil {
		ledgerErr = errors.Join(ledgerErr, err)
		s.note("record done marker for %s: %v", b.ID, err)
	}
	done = s.teardown(ctx, p, b, done)
	state, observed, pollErr := s.pollEnd(ctx, p, b, o.BoundSec, o.PollSec, &done)
	result.State = state.Name
	if observed && terminal(state.Name) {
		result.TerminatedUTC, result.Basis = s.terminationTime(state)
		if seconds, ok := boxcore.SecondsBetween(b.LaunchTimeUTC, result.TerminatedUTC); ok && seconds >= 0 {
			result.BilledSeconds = seconds
		}
		_, err := s.appendEvent("TERMINATED_CONFIRMED",
			endedFields(b, runID, done, state, result.TerminatedUTC, result.Basis))
		ledgerErr = errors.Join(ledgerErr, err)
		if ledgerErr == nil {
			result.ExitCode = boxcore.ExitOK
		}
		return result, ledgerErr
	}
	result.Pending, result.ExitCode = true, boxcore.ExitNoCandidate
	if observed {
		_, err := s.appendEvent("END_PENDING", map[string]any{
			"instance_id": b.ID, "run_id": runID, "state": state.Name,
			"bound_sec": o.BoundSec, "done_result": done,
		})
		ledgerErr = errors.Join(ledgerErr, err)
	} else {
		// Do not manufacture a provider state when every read failed.
		pollErr = errors.Join(pollErr, errors.New("boxrun: no provider state observed"))
	}
	if ledgerErr != nil {
		result.ExitCode = boxcore.ExitUsage
	}
	return result, errors.Join(ledgerErr, pollErr)
}

func (s *service) teardown(ctx context.Context, p boxcore.Provider, b boxcore.Box, done string) string {
	if err := teardownBound(ctx, p, b); err != nil {
		switch boxcore.KindOf(err) {
		case boxcore.KindUnsupported:
		case boxcore.KindDenied:
			done += ";teardown-denied"
			s.note("teardown denied for %s: %v", b.ID, err)
		default:
			s.note("teardown for %s: %v", b.ID, err)
		}
	}
	return done
}

func (s *service) pollEnd(ctx context.Context, p boxcore.Provider, b boxcore.Box,
	boundSec, pollSec int, done *string) (boxcore.State, bool, error) {
	deadline := s.d.Now().Add(time.Duration(boundSec) * time.Second)
	var state boxcore.State
	observed, stoppedRetry := false, false
	var lastErr error
	for {
		if err := ctx.Err(); err != nil {
			return state, observed, err
		}
		if s.d.Now().After(deadline) {
			return state, observed, lastErr
		}
		current, err := describeBound(ctx, p, b)
		if err != nil {
			lastErr = err
			s.note("describe %s: %v", b.ID, err)
		} else {
			state, observed, lastErr = current, true, nil
			if terminal(state.Name) {
				return state, true, nil
			}
			if state.Name == boxcore.StateStopped && !stoppedRetry {
				stoppedRetry = true
				*done = s.teardown(ctx, p, b, *done)
			}
		}
		remaining := deadline.Sub(s.d.Now())
		if remaining <= 0 {
			return state, observed, lastErr
		}
		if err := s.d.Sleep(ctx, min(remaining, time.Duration(pollSec)*time.Second)); err != nil {
			return state, observed, err
		}
	}
}

func (s *service) terminationTime(state boxcore.State) (string, string) {
	if state.TransitionUTC != "" {
		return state.TransitionUTC, "describe:transition-time"
	}
	basis := "describe:observed-at-poll"
	if state.Name == boxcore.StateGone {
		basis = "describe:not-found"
	}
	return boxcore.FormatUTC(s.d.Now()), basis
}

func markerExec(ctx context.Context, p boxcore.Provider, b boxcore.Box,
	opts boxcore.TransportOptions, command string) (code int, err error) {
	defer catchPanic("done marker", &err)
	return execBound(ctx, p.Transport(b, opts), command, nil, nil, nil, 30*time.Second)
}
