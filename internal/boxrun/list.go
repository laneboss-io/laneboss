package boxrun

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"laneboss.io/laneboss/internal/boxcore"
)

// List joins managed boxes with ledger evidence and their observed states.
func (s *service) List(ctx context.Context, o boxcore.ListOptions) ([]boxcore.Listed, error) {
	if err := s.configured(); err != nil {
		return nil, err
	}
	events, err := s.events()
	if err != nil {
		return nil, err
	}
	var names []string
	if o.Provider != "" {
		if _, err := s.provider(o.Provider); err != nil {
			return nil, err
		}
		names = append(names, o.Provider)
	} else {
		for name := range s.d.Providers {
			names = append(names, name)
		}
		sort.Strings(names)
	}
	ended := make(map[string]bool)
	for _, event := range events {
		switch text(event, "event") {
		case "TERMINATED_CONFIRMED", "END_UNKNOWN":
			ended[text(event, "instance_id")] = true
		}
	}
	var listed []boxcore.Listed
	var failures []error
	for _, name := range names {
		p, err := s.provider(name)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		boxes, err := p.List(ctx, boxcore.ListFilter{Org: s.d.Config.Org, ManagedOnly: true})
		if err != nil {
			failures = append(failures, err)
			continue
		}
		for _, b := range boxes {
			if b.Provider == "" {
				b.Provider = name
			}
			row := boxcore.Listed{Box: b, LedgerEnded: ended[b.ID]}
			hardMin := s.d.Config.Defaults.HardMin
			if event := launchEvent(events, name, b.ID); event != nil {
				if hard := int(number(event, "hard_min")); hard > 0 {
					hardMin = hard
				}
				if b.LaunchTimeUTC == "" {
					row.Box.LaunchTimeUTC = text(event, "launch_time_utc")
				}
			}
			if seconds, ok := boxcore.SecondsBetween(row.Box.LaunchTimeUTC, boxcore.FormatUTC(s.d.Now())); ok && seconds > 0 {
				row.AgeMin = seconds / 60
			}
			row.State, err = describeBound(ctx, p, row.Box)
			if err != nil {
				failures = append(failures, fmt.Errorf("describe %s: %w", b.ID, err))
			} else {
				threshold := max(hardMin+15, o.OlderThanMin)
				row.Orphan = !row.LedgerEnded && !terminal(row.State.Name) && row.AgeMin > threshold
			}
			if !o.Orphans || row.Orphan {
				listed = append(listed, row)
			}
		}
	}
	return listed, errors.Join(failures...)
}

// Sweep reports orphans, or deletes and confirms them when Delete is set.
func (s *service) Sweep(ctx context.Context, o boxcore.SweepOptions) (boxcore.SweepResult, error) {
	result := boxcore.SweepResult{}
	rows, err := s.List(ctx, boxcore.ListOptions{Provider: o.Provider, OlderThanMin: o.OlderThanMin})
	result.Examined = len(rows)
	for _, row := range rows {
		if row.Orphan {
			result.Orphans = append(result.Orphans, row)
		}
	}
	if err != nil || !o.Delete {
		return result, err
	}
	if err := s.writable(); err != nil {
		return result, err
	}
	events, err := s.events()
	if err != nil {
		return result, err
	}
	var failures []error
	for _, row := range result.Orphans {
		b := row.Box
		p, err := s.provider(b.Provider)
		if err != nil {
			failures = append(failures, err)
			result.Refused = append(result.Refused, b.ID+": "+err.Error())
			continue
		}
		err = teardownBound(ctx, p, b)
		if err != nil {
			result.Refused = append(result.Refused, b.ID+": "+err.Error())
			if kind := boxcore.KindOf(err); kind != boxcore.KindDenied && kind != boxcore.KindUnsupported {
				failures = append(failures, err)
			}
			continue
		}
		done := "sweep"
		state, observed, pollErr := s.pollEnd(ctx, p, b, 120, 15, &done)
		if !observed || !terminal(state.Name) {
			pendingErr := errors.Join(pollErr, fmt.Errorf("sweep %s: termination not confirmed", b.ID))
			result.Refused = append(result.Refused, b.ID+": termination not confirmed")
			failures = append(failures, pendingErr)
			continue
		}
		utc, _ := s.terminationTime(state)
		runID := text(launchEvent(events, b.Provider, b.ID), "run_id")
		if _, err := s.appendEvent("TERMINATED_CONFIRMED", endedFields(b, runID, done, state, utc, "sweep")); err != nil {
			failures = append(failures, err)
			result.Refused = append(result.Refused, b.ID+": termination not recorded")
			continue
		}
		result.Deleted = append(result.Deleted, b.ID)
	}
	return result, errors.Join(failures...)
}
