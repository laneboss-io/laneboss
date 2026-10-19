package watchdog

import (
	"context"
	"errors"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

// ReconcileAutomatic is called by the installed service inside its dispatch
// freeze barrier. Discovery is a read, never authority: ObserveLimit/Reconcile
// reread the actual life, grants, epoch and durable intent before any handoff.
func (s *Service) ReconcileAutomatic(ctx context.Context) error {
	if err := s.ready(ctx); err != nil {
		return err
	}
	request := api.ListRequest{Limit: 200}
	seenCursors, seenLives := map[string]bool{}, map[api.ID]bool{}
	for pageNumber := 0; pageNumber < maxEventPages; pageNumber++ {
		page, err := s.deps.Store.Lanes(ctx, s.readScope(), request)
		if err != nil {
			return err
		}
		for _, lane := range page.Lanes {
			if !validID.MatchString(string(lane.LifeID)) || lane.Run == 0 || seenLives[lane.LifeID] || len(seenLives) >= maxRunEvents {
				return problem(api.CodeIntegrity, "automatic watchdog inventory is invalid or repeats a life")
			}
			seenLives[lane.LifeID] = true
			if err := s.automaticLife(ctx, lane); err != nil {
				// This is the exact persisted timer's wait, not an execution
				// failure or permission to replace the timer after restart.
				var wait *api.Error
				if errors.As(err, &wait) && wait.Code == api.CodeUnavailable && wait.Retryable && wait.Owner == "lb-v2-watchdog" && wait.Message == "watchdog profile-room backoff has not elapsed" {
					continue
				}
				return err
			}
		}
		if page.Cursor == "" {
			return nil
		}
		if seenCursors[page.Cursor] || page.Cursor == request.Cursor {
			return problem(api.CodeIntegrity, "automatic watchdog inventory cursor did not advance")
		}
		seenCursors[page.Cursor], request.Cursor = true, page.Cursor
	}
	return problem(api.CodeUnavailable, "automatic watchdog inventory exceeds its bounded scan")
}

func (s *Service) automaticLife(ctx context.Context, lane api.Lane) error {
	if lane.Cleaned || lane.State != "running" && lane.State != "verifying" && lane.State != "profile_wait" {
		return nil
	}
	target := api.LifeRef{LifeID: lane.LifeID, Run: lane.Run}
	if lane.Run > 1 {
		prior := api.LifeRef{LifeID: lane.LifeID, Run: lane.Run - 1}
		intent, found, err := s.intent(ctx, prior)
		if err != nil {
			return err
		}
		if found && intent.Status == "claimed" {
			_, err := s.Reconcile(ctx, prior)
			return err // Recover the same slot/claim, never assess a second one.
		}
	}
	intent, found, err := s.intent(ctx, target)
	if err != nil {
		return err
	}
	if found {
		if intent.Status == "cancelled" || intent.Status == "completed" {
			return nil
		}
		_, err := s.Reconcile(ctx, target)
		return err
	}
	if lane.Session.Driver != api.DriverClaudock {
		return nil // No Codex/provider fallback is inferred from a quota label.
	}
	events, err := s.events(ctx, lane.LifeID)
	if err != nil {
		return err
	}
	var ended *api.RunEndEvent
	for _, event := range events {
		if event.Run != target.Run || event.Kind != "lane.ended" || !outsideEvent(event, "service", "worker") {
			continue
		}
		var end api.RunEndEvent
		if err := decodePayload(event.Payload, &end); err != nil {
			return err
		}
		if end.LaunchID != lane.LaunchID || end.Observation.Handle.Target != target || ended != nil && !reflect.DeepEqual(*ended, end) {
			return problem(api.CodeIntegrity, "automatic watchdog found a foreign or conflicting run end")
		}
		ended = &end
	}
	if ended == nil || ended.Reason != "exit" && ended.Reason != "limit" {
		return nil
	}
	exit := ended.Observation
	if exit.State != "exited" || exit.Survivors == nil || *exit.Survivors != 0 || exit.ExitCode == nil {
		return problem(api.CodeContainmentUnknown, "automatic quota classification requires an actual exited zero-survivor run")
	}
	if err := controlError(events, target, lane.LogicalTurnID); err != nil {
		return err
	}
	if framer, ok := s.deps.Store.(interface {
		FrameCapture(context.Context, api.Scope, api.ID) ([]api.CaptureRecord, error)
	}); ok {
		binding, err := s.deps.Store.LaunchBinding(ctx, lane.LaunchID)
		if err != nil {
			return err
		}
		if binding.Recovery == nil {
			return problem(api.CodeIntegrity, "quota framing lost its retained launch binding")
		}
		if _, err := framer.FrameCapture(ctx, s.readScope(), binding.Recovery.Capture.ID); err != nil {
			if api.IncompleteCaptureFraming(err) {
				// EOF may still be draining; an authentication failure may
				// never produce provider frames. Leave this run unclassified
				// and revisit it on a later scan, without blocking other lives.
				return nil
			}
			return err
		}
		events, err = s.events(ctx, lane.LifeID)
		if err != nil {
			return err
		}
	}
	hasFrames := false
	for _, event := range events {
		if event.Kind == "capture.framed" && event.Run == target.Run && outsideEvent(event, "service") {
			hasFrames = true
		}
	}
	for _, event := range events {
		if event.Run != target.Run || !outsideEvent(event, "service", "worker") {
			continue
		}
		if event.Kind == "capture.gap" {
			return problem(api.CodeIntegrity, "automatic quota classification has an unresolved capture gap")
		}
		if event.Kind != "capture.appended" && event.Kind != "capture.framed" {
			continue
		}
		var record api.CaptureRecord
		if err := decodePayload(event.Payload, &record); err != nil {
			return err
		}
		if record.Target != target {
			return problem(api.CodeIntegrity, "automatic quota capture belongs to another run")
		}
		if !record.Primary || record.ReplacementOf != "" {
			continue
		}
		// A raw pipe chunk cannot be relabelled as a complete vendor frame.
		// The installed capture owner must supply its actual framing contract.
		if record.Coverage != "complete" {
			if hasFrames && event.Kind == "capture.appended" {
				continue
			}
			return problem(api.CodePrerequisite, "automatic quota classification requires complete retained vendor frames")
		}
		signal, err := s.deps.Claudock.LimitFromCapture(ctx, record, exit)
		if err != nil {
			return err
		}
		if signal != nil {
			_, err := s.ObserveLimit(ctx, *signal)
			return err
		}
	}
	return nil
}
