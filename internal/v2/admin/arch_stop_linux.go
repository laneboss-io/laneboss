//go:build linux

package admin

import (
	"context"
	"errors"

	"laneboss.io/laneboss/internal/v2/api"
)

func (m *leaseManager) stopArchiveWorker(ctx context.Context, id api.ID) (bool, error) {
	records, err := m.records()
	if err != nil {
		return false, err
	}
	matched := false
	var failures []error
	for _, p := range records {
		if p.Archive == nil || p.Archive.Worker == nil {
			continue
		}
		w := p.Archive.Worker
		if w.Collected {
			continue
		}
		if id != p.Lease.ID && id != p.Lease.ContainmentID && id != p.Archive.LaunchID && id != w.Lease.ID && id != w.Lease.ContainmentID && id != w.Reg.Job.ID && id != w.Reg.Job.Lease.ID && id != w.Reg.LaunchID {
			continue
		}
		matched = true
		w.Revoked = true
		if err := m.save(p); err != nil {
			failures = append(failures, err)
			continue
		}
		child := archiveChild(p, *w)
		if err := m.killContainment(ctx, child); err != nil {
			failures = append(failures, err)
			continue
		}
		if w.Gate != nil {
			live := m.gates[w.Lease.ID]
			if live == nil {
				if w.Observation == nil {
					failures = append(failures, failure(api.CodeContainmentUnknown, "revoked archive lost its native wait owner"))
				}
			} else if err := stopAndWait(ctx, live, archiveHandle(*w), func() error { return m.waitContainmentEmpty(ctx, child) }); err != nil {
				failures = append(failures, err)
			}
		}
		if err := m.resources.Quiescent(ctx, child); err != nil {
			failures = append(failures, err)
		}
	}
	if !m.reviewView {
		for _, parent := range records {
			for _, review := range parent.Reviews {
				if review == nil || review.Worker == nil {
					continue
				}
				found, err := m.reviewManager(review.Intent.OperationID).stopArchiveWorker(ctx, id)
				matched = matched || found
				if err != nil {
					failures = append(failures, err)
				}
			}
		}
	}
	return matched, errors.Join(failures...)
}

// Only the authenticated cleanup job, with its committed verified archive,
// reaches this path. Retain the original wait; never synthesize another exit.
func (m *leaseManager) collectArchiveWorker(ctx context.Context, p *leaseRecord) error {
	if p.Archive == nil || p.Archive.Worker == nil {
		return failure(api.CodeContainmentUnknown, "cleanup lacks the original native archive worker")
	}
	w := p.Archive.Worker
	if w.Collected {
		return nil
	}
	if w.Observation == nil || w.Gate == nil {
		return failure(api.CodeContainmentUnknown, "archive collection lost its retained native exit")
	}
	if err := dataTerminal(*w.Observation, archiveHandle(*w)); err != nil {
		return err
	}
	child := archiveChild(*p, *w)
	if err := m.resources.Quiescent(ctx, child); err != nil {
		return err
	}
	if !w.Collecting {
		w.Collecting = true
		if err := m.save(*p); err != nil {
			return err
		}
	}
	if live := m.gates[w.Lease.ID]; live != nil {
		observation, err := measureArchiveNative(ctx, live, archiveHandle(*w), func() error { return m.resources.Quiescent(ctx, child) })
		if err != nil {
			return err
		}
		if observation.State != "exited" {
			return failure(api.CodeContainmentUnknown, "archive native worker is not terminal during collection")
		}
		if err := live.Close(); err != nil {
			return err
		}
		delete(m.gates, w.Lease.ID)
	}
	if err := m.resources.Remove(ctx, child); err != nil {
		return err
	}
	if err := m.resources.Quiescent(ctx, child); err != nil {
		return err
	}
	w.Collecting, w.Collected = false, true
	return m.save(*p)
}
