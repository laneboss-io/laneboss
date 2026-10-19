package boxrun

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"

	"laneboss.io/laneboss/internal/boxcore"
)

// Launch tries candidates in order and records the single successful creation.
func (s *service) Launch(ctx context.Context, o boxcore.LaunchOptions) (boxcore.LaunchResult, error) {
	result, _, err := s.launch(ctx, o, false, nil)
	return result, err
}

func (s *service) launch(ctx context.Context, o boxcore.LaunchOptions, fromRun bool,
	created func(boxcore.Box, boxcore.Request)) (boxcore.LaunchResult, boxcore.Request, error) {
	result := boxcore.LaunchResult{ExitCode: boxcore.ExitUsage}
	req, err := s.request(o.Request)
	if err != nil {
		return result, req, err
	}
	p, err := s.provider(req.Provider)
	if err != nil {
		return result, req, err
	}
	if err := s.writable(); err != nil {
		return result, req, fmt.Errorf("boxrun: ledger is not writable: %w", err)
	}
	if err := p.Prepare(ctx, req); err != nil {
		if boxcore.KindOf(err) != boxcore.KindDenied {
			result.ExitCode = boxcore.ExitFailed
			if fromRun {
				result.ExitCode = boxcore.ExitNoCandidate
			}
		}
		return result, req, err
	}
	candidates, err := p.Candidates(ctx, req)
	if err != nil {
		result.ExitCode = boxcore.ExitFailed
		if fromRun {
			result.ExitCode = boxcore.ExitNoCandidate
		}
		return result, req, err
	}
	result.ExitCode = boxcore.ExitNoCandidate
	if len(candidates) == 0 {
		return result, req, errors.New("boxrun: no candidates")
	}
	quotaRegions := make(map[string]bool)
	fits, capSkips := 0, 0
	var failures []error
	for _, c := range candidates {
		if err := ctx.Err(); err != nil {
			return result, req, err
		}
		if quotaRegions[c.Region] {
			continue
		}
		hourly := boxcore.HourlyUSD(c.PriceUSDHour, req.RootGB, s.d.Config.Defaults.DiskUSDGBMonth)
		h, capErr := boxcore.FitHardMin(hourly, req.HardMin, req.CostCapUSD)
		// Disk pricing cannot supply a missing compute quote.
		if c.PriceUSDHour <= 0 || math.IsNaN(c.PriceUSDHour) || math.IsInf(c.PriceUSDHour, 0) {
			capErr = boxcore.ErrPriceUnknown
		}
		if capErr != nil {
			capSkips++
			failures = append(failures, capErr)
			s.note("cost cap skips %s %s: %v", c.Type, c.Zone, capErr)
			continue
		}
		fits++
		attempt := req
		attempt.HardMin = h
		guest := s.d.Guest.Render(s.guestSpec(attempt))
		if o.DryRun {
			dry, dryErr := p.DryRun(ctx, attempt, c, guest)
			result.Candidate, result.Dry = c, &dry
			switch {
			case dryErr != nil:
				result.ExitCode = boxcore.ExitDryUnexpected
			case !dry.Allowed:
				result.ExitCode = boxcore.ExitDryDenied
			default:
				result.ExitCode = boxcore.ExitOK
			}
			return result, attempt, dryErr
		}
		b, launchErr := p.Launch(ctx, attempt, c, guest)
		if launchErr != nil {
			failures = append(failures, launchErr)
			s.note("launch %s %s: %v", c.Type, c.Zone, launchErr)
			switch boxcore.KindOf(launchErr) {
			case boxcore.KindQuota:
				quotaRegions[c.Region] = true
			case boxcore.KindDenied:
				result.ExitCode = launchFailure(fromRun)
				return result, req, errors.Join(failures...)
			}
			continue
		}
		b.QuoteUSDHour = c.PriceUSDHour
		result.Box, result.Candidate = b, c
		if created != nil {
			created(b, attempt)
		}
		running, waitErr := p.WaitRunning(ctx, b)
		if waitErr == nil || running.ID != "" {
			b = running
		}
		b.QuoteUSDHour = c.PriceUSDHour
		result.Box = b
		if created != nil {
			created(b, attempt)
		}
		if _, err := s.appendEvent("LAUNCHED", s.launchedFields(attempt, c, b)); err != nil {
			s.note("box is UP but NOT recorded: %s", b.ID)
			result.ExitCode = boxcore.ExitNotRecorded
			return result, attempt, errors.Join(waitErr, err)
		}
		if s.d.Config.Ledger.Registry != "" {
			if err := s.register(attempt, b); err != nil {
				result.ExitCode = boxcore.ExitNotRegistered
				s.note("box is UP but NOT registered: %s", b.ID)
				return result, attempt, errors.Join(waitErr, err)
			}
		}
		if waitErr != nil {
			// Creation is recorded even if the wait failed; never launch another box.
			result.ExitCode = launchFailure(fromRun)
			return result, attempt, waitErr
		}
		result.ExitCode = boxcore.ExitOK
		return result, attempt, nil
	}
	result.ExitCode = launchFailure(fromRun)
	if fits == 0 && capSkips == len(candidates) {
		result.ExitCode = boxcore.ExitCostCap
	}
	return result, req, errors.Join(failures...)
}

func launchFailure(fromRun bool) int {
	if fromRun {
		return boxcore.ExitNoCandidate
	}
	return boxcore.ExitFailed
}

func (s *service) guestSpec(req boxcore.Request) boxcore.GuestSpec {
	cfg := s.d.Config.Guest
	spec := boxcore.GuestSpec{
		Provider: req.Provider, RunID: req.RunID, IdleMin: req.IdleMin,
		HardMin: req.HardMin, DoneFiles: append([]string(nil), cfg.DoneFiles...),
		BusyFiles: append([]string(nil), cfg.BusyFiles...), OutDir: cfg.OutDir, Tag: "lb-box",
	}
	if req.Provider == "gcp" && s.d.Config.GCP != nil {
		spec.Bucket = s.d.Config.GCP.ResultsBucket
		spec.ObjectPrefix = s.d.Config.GCP.ObjectPrefix + "/" + req.RunID
		spec.SyncSeconds = 60
	}
	return spec
}

func (s *service) register(req boxcore.Request, b boxcore.Box) error {
	f, err := os.OpenFile(s.d.Config.Ledger.Registry, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	_, writeErr := fmt.Fprintf(f, "%s %s %s %s\n", req.Purpose, b.ID, b.Address,
		s.d.Now().Local().Format("2006-01-02 15:04:05"))
	return errors.Join(writeErr, f.Close())
}
