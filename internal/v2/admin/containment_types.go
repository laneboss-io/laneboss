package admin

import (
	"errors"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/pollgate"
)

type containmentQuery struct {
	LeaseID api.ID `json:"lease_id"`
	Opened  bool   `json:"opened,omitempty"`
}
type containmentTicket struct {
	Kind                api.EndpointClass `json:"kind"`
	WorkerLeaseID       api.ID            `json:"worker_lease_id,omitempty"`
	StageID             api.ID            `json:"stage_id,omitempty"`
	ParentLeaseID       api.ID            `json:"parent_lease_id,omitempty"`
	ParentContainmentID api.ID            `json:"parent_containment_id,omitempty"`
	ParentLaunchID      api.ID            `json:"parent_launch_id,omitempty"`
	Config              string            `json:"config"`
	Lease               api.HelperLease   `json:"lease"`
	Target              api.LifeRef       `json:"target"`
	LaunchID            api.ID            `json:"launch_id"`
	BootID              string            `json:"boot_id"`
	Generation          api.Generation    `json:"generation"`
	Device              string            `json:"device"`
	Inode               string            `json:"inode"`
}

func (t containmentTicket) matches(id api.ID) bool {
	return id != "" && (id == t.Lease.ID || id == t.Lease.ContainmentID || id == t.LaunchID || id == t.WorkerLeaseID || id == t.StageID ||
		id == t.ParentLeaseID || id == t.ParentContainmentID || id == t.ParentLaunchID)
}

func (t containmentTicket) endpointMatches(endpoint api.InstalledBinding) bool {
	return endpoint.Class == t.Kind && endpoint.WorkerLeaseID == t.WorkerLeaseID
}

type containmentEntry struct {
	Binding api.ContainmentBinding
	Ticket  containmentTicket
	memo    pollgate.Memo[containmentTicket]
}

func (s *Service) beginContainment(id api.ID) func() {
	s.registryMu.Lock()
	var finishes []func()
	for key, entry := range s.containments {
		if key == id || entry.Ticket.matches(id) {
			finishes = append(finishes, entry.memo.Begin())
		}
	}
	s.registryMu.Unlock()
	return func() {
		for _, finish := range finishes {
			finish()
		}
	}
}

func (s *Service) revokeEntries(id api.ID) error {
	return s.revokeKinds(id, false)
}

func (s *Service) revokeLanes(id api.ID) error {
	return s.revokeKinds(id, true)
}

func (s *Service) revokeKinds(id api.ID, lanesOnly bool) error {
	s.registryMu.Lock()
	defer s.registryMu.Unlock()
	var failures []error
	for key, entry := range s.containments {
		if lanesOnly && entry.Ticket.Kind != api.EndpointLane {
			continue
		}
		if key != id && !entry.Ticket.matches(id) || entry.Binding.Revoked {
			continue
		}
		entry.Binding.Revoked = true
		entry.memo.Invalidate()
		if entry.Binding.Directory != nil {
			if err := entry.Binding.Directory.Close(); err != nil {
				failures = append(failures, failure(api.CodeIntegrity, "cannot close revoked containment identity"))
			}
		}
	}
	return errors.Join(failures...)
}

func (s *Service) finishRevocation(id api.ID, matched bool, helperErr error) error {
	registryErr := s.revokeEntries(id)
	if err := errors.Join(helperErr, registryErr); err != nil {
		return err
	}
	if !matched {
		return failure(api.CodeNotFound, "revocation names no retained helper owner")
	}
	return nil
}
