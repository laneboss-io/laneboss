//go:build linux

package admin

import (
	"context"
	"os"
	"path/filepath"

	"laneboss.io/laneboss/internal/v2/api"
)

func readReviewProtected(path string, max int64) ([]byte, error) { return readProtected(path, max) }

func (m *leaseManager) reviewLaunchSnapshot(ctx context.Context, id api.ID) (workerLaunchSnapshot, *nativeGate, bool, error) {
	records, err := m.records()
	if err != nil {
		return workerLaunchSnapshot{}, nil, false, err
	}
	for _, parent := range records {
		for _, journal := range parent.Reviews {
			if journal.Worker == nil || journal.Worker.Gate == nil || journal.Worker.Gate.Prepared.ID != id {
				continue
			}
			return m.reviewManager(journal.Intent.OperationID).archiveLaunchSnapshot(ctx, id)
		}
	}
	return workerLaunchSnapshot{}, nil, false, nil
}

func (s *Service) bindReviewContainment(ctx context.Context, r archiveReg) error {
	var lease api.HelperLease
	if err := s.call(ctx, "review_lease", r, &lease); err != nil {
		return err
	}
	var ticket containmentTicket
	if err := s.call(ctx, "containment", containmentQuery{LeaseID: lease.ID}, &ticket); err != nil {
		return err
	}
	file, err := os.Open(filepath.Join(s.binding.cgroupPath(), string(lease.ContainmentID)))
	if err != nil {
		return failure(api.CodeContainmentUnknown, "cannot open native review containment")
	}
	defer file.Close()
	return s.RegisterContainment(ctx, api.ContainmentBinding{Config: s.deps.Config, Lease: lease, Target: ticket.Target, Backend: "linux-bwrap-landlock", BootID: ticket.BootID, Generation: ticket.Generation, Directory: file})
}
