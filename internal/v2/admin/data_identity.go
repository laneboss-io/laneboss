package admin

import (
	"errors"

	"laneboss.io/laneboss/internal/v2/api"
)

type identityIssue struct {
	owners []api.ID
	detail string
}

func (i identityIssue) affects(owner api.ID) bool {
	for _, id := range i.owners {
		if id == owner {
			return true
		}
	}
	return false
}

// The same complete inventory drives normal writes and scoped recovery.
// Recovery may act only on owners absent from every reported conflict.
func dataIdentityIssues(records []leaseRecord) []identityIssue {
	var issues []identityIssue
	problem := func(detail string, owners ...api.ID) { issues = append(issues, identityIssue{owners, detail}) }
	ids, workers, launches, effects, actors := map[api.ID]bool{}, map[api.ID]bool{}, map[api.ID]bool{}, map[api.ID]bool{}, map[api.ID]bool{}
	idOwners, workerOwners, launchOwners, effectOwners, actorOwners := map[api.ID]api.ID{}, map[api.ID]api.ID{}, map[api.ID]api.ID{}, map[api.ID]api.ID{}, map[api.ID]api.ID{}
	parents := map[api.ID]bool{}
	parentOwners := map[api.ID][]api.ID{}
	lives, uids := map[api.ID]api.ID{}, map[uint32]api.ID{}
	parentActor := func(actor, owner api.ID) {
		parents[actor] = true
		parentOwners[actor] = append(parentOwners[actor], owner)
	}
	laneLaunch := func(id, owner api.ID) {
		if id == "" {
			return
		}
		if launches[id] && launchOwners[id] != owner {
			problem("duplicate retained lane launch", launchOwners[id], owner)
		}
		launches[id], launchOwners[id] = true, owner
	}
	retainedID := func(id, owner api.ID) {
		if id == "" {
			return
		}
		if ids[id] {
			problem("retained capture or network identity overlaps owner", idOwners[id], owner)
		}
		ids[id], idOwners[id] = true, owner
	}
	uid := func(value uint32, owner api.ID) {
		if value == 0 {
			return
		} // structural lease validation rejects an unknown UID
		if prior, ok := uids[value]; ok {
			problem("native pool UID has multiple live owners", prior, owner)
		}
		uids[value] = owner
	}
	for _, record := range records {
		owner := record.Lease.ID
		for _, id := range []api.ID{record.Lease.ID, record.Lease.ContainmentID} {
			if ids[id] {
				problem("duplicate retained lease or containment identity", idOwners[id], owner)
			}
			ids[id], idOwners[id] = true, owner
		}
		if record.Spec != nil {
			laneLaunch(record.Spec.Handoff.Spec.LaunchID, owner)
		}
		for _, allocation := range record.LaunchAllocations {
			laneLaunch(allocation.Reservation.LaunchID, owner)
		}
		for _, capture := range record.Captures {
			retainedID(capture.Binding.ID, owner)
		}
		if record.Network != nil {
			retainedID(record.Network.Lease.ID, owner)
			retainedID(record.Network.Lease.NamespaceID, owner)
		}
		if record.Request.LifeID != "" {
			if prior, ok := lives[record.Request.LifeID]; ok {
				problem("duplicate retained life identity", prior, owner)
			}
			lives[record.Request.LifeID] = owner
		}
		if record.Phase != "released" && record.Phase != "aborted" {
			uid(record.Lease.UID, owner)
		}
		parentActor(record.Request.Cause.Actor.ID, owner)
		parentActor(record.Request.Cause.RequestedBy.ID, owner)
		for _, allocation := range record.Allocations {
			parentActor(allocation.Cause.Actor.ID, owner)
			parentActor(allocation.Cause.RequestedBy.ID, owner)
		}
		if record.Gate != nil && record.Gate.Open != nil {
			parentActor(record.Gate.Open.Binding.Record.Actor.ID, owner)
		}
	}
	for _, record := range records {
		owner := record.Lease.ID
		for _, job := range record.DataJobs {
			for _, id := range []api.ID{job.Lease.ID, job.Lease.ContainmentID, job.Reg.Request.StageID, job.Projection.OpenToken} {
				if id == "" {
					continue
				}
				if ids[id] {
					problem("duplicate retained data lease, containment, stage or token", idOwners[id], owner)
				}
				ids[id], idOwners[id] = true, owner
			}
			if workers[job.Reg.Worker.ID] || launches[job.Reg.LaunchID] || effects[job.Reg.Worker.EffectID] {
				if workers[job.Reg.Worker.ID] {
					problem("duplicate retained worker identity", workerOwners[job.Reg.Worker.ID], owner)
				}
				if launches[job.Reg.LaunchID] {
					problem("duplicate retained worker launch", launchOwners[job.Reg.LaunchID], owner)
				}
				if effects[job.Reg.Worker.EffectID] {
					problem("duplicate retained worker effect", effectOwners[job.Reg.Worker.EffectID], owner)
				}
			}
			workers[job.Reg.Worker.ID], launches[job.Reg.LaunchID], effects[job.Reg.Worker.EffectID] = true, true, true
			workerOwners[job.Reg.Worker.ID], launchOwners[job.Reg.LaunchID], effectOwners[job.Reg.Worker.EffectID] = owner, owner, owner
			if job.State != "collected" {
				uid(job.Lease.UID, owner)
			}
			if job.Gate != nil && job.Gate.Record != nil {
				id := job.Gate.Record.Actor.ID
				if !validID(id) || actors[id] || parents[id] {
					if !validID(id) {
						problem("invalid worker principal", owner)
					}
					if actors[id] {
						problem("duplicate worker principal", actorOwners[id], owner)
					}
					if parents[id] {
						problem("worker principal overlaps retained owner", append(append([]api.ID{}, parentOwners[id]...), owner)...)
					}
				}
				actors[id], actorOwners[id] = true, owner
			}
		}
		for _, capture := range record.Captures {
			if capture.Native == nil {
				continue
			}
			// Discharge returns the numeric UID to the allocator after its
			// acknowledged native collection. Keep the identities below even
			// then: historical lease and containment IDs cannot be reused.
			if captureReservesUID(capture) {
				uid(capture.Native.Lease.UID, owner)
			}
			for index, id := range []api.ID{capture.Native.Lease.ID, capture.Native.Lease.ContainmentID} {
				// Native capture intentionally uses its binding ID as its lease ID.
				// The binding was already registered above; only this reference is
				// shared, while another capture/owner or containment remains unique.
				if index == 0 && id == capture.Binding.ID {
					continue
				}
				if ids[id] {
					problem("outside capture identity overlaps retained owner", idOwners[id], owner)
				}
				ids[id], idOwners[id] = true, owner
			}
		}
	}
	return issues
}

func validateDataIdentities(records []leaseRecord) error {
	return validateIdentityScope(records, "")
}

func validateIdentityScope(records []leaseRecord, owner api.ID) error {
	var failures []error
	for _, issue := range dataIdentityIssues(records) {
		if owner == "" || issue.affects(owner) {
			failures = append(failures, failure(api.CodeIntegrity, issue.detail))
		}
	}
	return errors.Join(failures...)
}
func newDataIdentity(records []leaseRecord, reg dataReg) error {
	for _, record := range records {
		if record.Spec != nil && record.Spec.Handoff.Spec.LaunchID == reg.LaunchID {
			return failure(api.CodeConflict, "new worker launch overlaps a retained lane")
		}
		for _, allocation := range record.LaunchAllocations {
			if allocation.Reservation.LaunchID == reg.LaunchID {
				return failure(api.CodeConflict, "new worker launch overlaps a retained allocation")
			}
		}
		for _, job := range record.DataJobs {
			if job.Reg.Worker.ID == reg.Worker.ID || job.Reg.LaunchID == reg.LaunchID || job.Reg.Worker.EffectID == reg.Worker.EffectID || job.Reg.Request.StageID == reg.Request.StageID {
				return failure(api.CodeConflict, "new data attempt reuses a retained worker, launch, effect or stage")
			}
		}
	}
	return nil
}

func newWorkerPrincipal(records []leaseRecord, reg dataReg, actor api.Actor) error {
	for _, record := range records {
		if actor.ID == record.Request.Cause.Actor.ID || actor.ID == record.Request.Cause.RequestedBy.ID ||
			record.Gate != nil && record.Gate.Open != nil && actor.ID == record.Gate.Open.Binding.Record.Actor.ID {
			return failure(api.CodeForbidden, "worker principal overlaps a retained lane or requester")
		}
		for _, allocation := range record.Allocations {
			if actor.ID == allocation.Cause.Actor.ID || actor.ID == allocation.Cause.RequestedBy.ID {
				return failure(api.CodeForbidden, "worker principal overlaps a retained allocation requester")
			}
		}
		for _, job := range record.DataJobs {
			if job.Reg.LaunchID != reg.LaunchID && job.Gate != nil && job.Gate.Record != nil && actor.ID == job.Gate.Record.Actor.ID {
				return failure(api.CodeForbidden, "worker principal is already assigned to another launch")
			}
		}
	}
	return nil
}
