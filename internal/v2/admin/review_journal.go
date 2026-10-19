package admin

import (
	"context"
	"encoding/json"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/reviewjob"
)

// A review is persisted in Reviews, never Archive. This private view reuses
// the existing measured storage/worker algorithms without changing the later
// archive's original-operation journal. The canonical helper lock serializes
// every view; no new process, store, allocation or identity is created here.
type reviewLeaseStorage struct {
	parent    *leaseManager
	operation api.ID
}

func (s reviewLeaseStorage) Records() ([]leaseRecord, error) {
	records, err := s.parent.records()
	if err != nil {
		return nil, err
	}
	for i := range records {
		r := &records[i]
		r.archivalOwner, r.Archive = r.Archive, nil
		for _, journal := range r.Reviews {
			if journal.Intent.OperationID == s.operation {
				r.Archive = journal
			}
		}
	}
	return records, nil
}

func (s reviewLeaseStorage) Save(r leaseRecord) error {
	journal := r.Archive
	if journal != nil && journal.Intent.OperationID != s.operation {
		return failure(api.CodeConflict, "review view changed its original operation")
	}
	// Read the canonical archival slot afresh; a view can never overwrite it.
	records, err := s.parent.store.Records()
	if err != nil {
		return err
	}
	found := false
	for _, original := range records {
		if original.Lease.ID != r.Lease.ID {
			continue
		}
		found = true
		r.Archive, r.Reviews, r.archivalOwner = original.Archive, original.Reviews, nil
		if journal != nil {
			replaced := false
			for i, prior := range r.Reviews {
				if prior.Intent.OperationID == s.operation {
					r.Reviews[i], replaced = journal, true
				}
			}
			if !replaced {
				r.Reviews = append(r.Reviews, journal)
			}
		}
		break
	}
	if !found {
		return failure(api.CodeNotFound, "review has no original native storage owner")
	}
	return s.parent.save(r)
}

func (m *leaseManager) reviewManager(operation api.ID) *leaseManager {
	if m.gates == nil {
		m.gates = make(map[api.ID]ownedGate)
	}
	if m.captures == nil {
		m.captures = make(map[api.ID]ownedCapture)
	}
	n := newLeaseManager(m.binding, m.bootID, reviewLeaseStorage{m, operation}, m.resources)
	n.reviewView, n.gates, n.captures, n.credentials = true, m.gates, m.captures, m.credentials
	n.workerLaunch, n.storeLock = m.workerLaunch, m.storeLock
	n.dataPins, n.exports, n.networks = m.dataPins, m.exports, m.networks
	return n
}

func (m *leaseManager) dispatchReview(ctx context.Context, method string, raw json.RawMessage) (any, error) {
	var operation api.ID
	switch method {
	case "review_freeze", "review_check", "review_bytes":
		var q archiveQuery
		if err := decodeStrict(raw, &q); err != nil {
			return nil, err
		}
		operation = q.Intent.OperationID
	case "review_register":
		var q archiveSeal
		if err := decodeStrict(raw, &q); err != nil {
			return nil, err
		}
		operation = q.Reg.Job.Intent.OperationID
	case "review_open":
		var q archiveOpen
		if err := decodeStrict(raw, &q); err != nil {
			return nil, err
		}
		operation = q.Reg.Job.Intent.OperationID
	case "review_retire":
		var q archiveRetireQuery
		if err := decodeStrict(raw, &q); err != nil {
			return nil, err
		}
		operation = q.Job.Intent.OperationID
	default:
		var q archiveReg
		if err := decodeStrict(raw, &q); err != nil {
			return nil, err
		}
		if q.Job.Lease.Kind != "export" && q.Job.Lease.Kind != "test" {
			return nil, failure(api.CodeForbidden, "review cannot select another worker kind")
		}
		operation = q.Job.Intent.OperationID
		if method == "review_lease" {
			if err := m.ensureReviewWorkerJournal(q); err != nil {
				return nil, err
			}
		}
	}
	if !validID(operation) {
		return nil, failure(api.CodeInvalid, "review lacks its original operation")
	}
	n := m.reviewManager(operation)
	selected := "archive_" + strings.TrimPrefix(method, "review_")
	switch method {
	case "review_freeze", "review_check", "review_bytes":
		return n.dispatchArchiveStorage(ctx, selected, raw)
	case "review_retire":
		var q archiveRetireQuery
		if err := decodeStrict(raw, &q); err != nil {
			return nil, err
		}
		return n.retireArchive(ctx, q)
	default:
		return n.dispatchArchiveWorker(ctx, selected, raw)
	}
}

// Each verifier has its own original operation, while all reviewers of this
// ended run consume the same measured freeze. Clone only that immutable source
// portion into the new review journal, never its worker or the archive slot.
func (m *leaseManager) ensureReviewWorkerJournal(r archiveReg) error {
	if err := validReviewReg(r, m.binding.Config); err != nil {
		return err
	}
	records, err := m.records()
	if err != nil {
		return err
	}
	for _, parent := range records {
		if parent.Request.LifeID != r.Job.Lease.Target.LifeID {
			continue
		}
		for _, prior := range parent.Reviews {
			if prior.Intent.OperationID == r.Job.Intent.OperationID {
				return nil
			}
		}
		for _, prior := range parent.Reviews {
			if prior.Phase != "frozen" || prior.Freeze.Target != r.Job.Lease.Target || prior.Intent.EndEventID != r.Job.Intent.EndEventID || prior.Intent.EndSeq != r.Job.Intent.EndSeq || prior.Intent.CancellationEpoch != r.Job.Intent.CancellationEpoch || !freezeObject(prior.Freeze, r.Job.Freeze) {
				continue
			}
			copy := *prior
			if copy.SourceOperationID == "" {
				copy.SourceOperationID = prior.Intent.OperationID
			}
			copy.Intent, copy.Worker, copy.Retirement = r.Job.Intent, nil, nil
			parent.Reviews = append(parent.Reviews, &copy)
			return m.save(parent)
		}
		return failure(api.CodePrerequisite, "review worker has no exact independently retained post-run freeze")
	}
	return failure(api.CodeNotFound, "review worker has no original native life")
}

func validateReviewSealInput(seal archiveSeal) error {
	if seal.Reg.Job.Lease.Kind == "test" {
		return validateCheckSealInput(seal)
	}
	var input reviewjob.Input
	j := seal.Reg.Job
	if api.DecodeObject(seal.Input, &input) != nil || input.Schema != "laneboss.review-input.v2" ||
		input.Subject.Target != j.Lease.Target || input.Subject.EndEventID != j.Intent.EndEventID || input.Subject.EndSeq != j.Intent.EndSeq ||
		input.Subject.Generation != j.Intent.Request.ExpectedGeneration || input.Request.Target != j.Lease.Target ||
		input.Required == nil || len(input.Required) == 0 || len(input.Required) > 200 || input.Checks == nil || len(input.Checks) == 0 {
		return failure(api.CodeIntegrity, "review seal changed its exact frozen input")
	}
	return nil
}

func validateReviewOwners(records []leaseRecord, binding installation) error {
	workers, uids := map[api.ID]bool{}, map[uint32]bool{}
	for _, parent := range records {
		all := append([]*archiveJournal{parent.Archive}, parent.Reviews...)
		operations := map[api.ID]bool{}
		for index, journal := range all {
			if journal == nil {
				if index != 0 {
					return failure(api.CodeIntegrity, "native review journal is missing")
				}
				continue
			}
			if operations[journal.Intent.OperationID] {
				return failure(api.CodeIntegrity, "native review reused an original operation")
			}
			operations[journal.Intent.OperationID] = true
			if index != 0 {
				view := append([]leaseRecord{}, records...)
				for i := range view {
					if view[i].Lease.ID == parent.Lease.ID {
						view[i].Archive = journal
					}
				}
				if err := validateArchiveOwners(view, binding); err != nil {
					return err
				}
				if err := validateChannelOwners(view, binding); err != nil {
					return err
				}
			}
			w := journal.Worker
			if w == nil {
				continue
			}
			if index != 0 && w.Reg.Job.Lease.Kind != "export" && w.Reg.Job.Lease.Kind != "test" {
				return failure(api.CodeIntegrity, "review journal contains another worker kind")
			}
			for _, id := range []api.ID{w.Lease.ID, w.Lease.ContainmentID, w.Reg.Job.ID, w.Reg.Job.Lease.ID, w.Reg.LaunchID} {
				if workers[id] {
					return failure(api.CodeIntegrity, "review worker aliases another retained native job")
				}
				workers[id] = true
			}
			if !w.Collected {
				if uids[w.Lease.UID] {
					return failure(api.CodeIntegrity, "review worker aliases another native UID")
				}
				uids[w.Lease.UID] = true
			}
		}
	}
	return nil
}
