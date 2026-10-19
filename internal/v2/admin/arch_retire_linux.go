//go:build linux

package admin

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

func (m *leaseManager) retirementParent(q archiveRetireQuery) (leaseRecord, error) {
	if err := validArchiveRetirement(q.Job, q.Claim, m.binding.Config, time.Now()); err != nil {
		return leaseRecord{}, err
	}
	records, err := m.records()
	if err != nil {
		return leaseRecord{}, err
	}
	var parent *leaseRecord
	for index := range records {
		p := &records[index]
		if p.Archive == nil || p.Archive.Intent.OperationID != q.Job.Intent.OperationID {
			continue
		}
		if parent != nil || p.Archive.Intent != q.Job.Intent || !freezeObject(p.Archive.Freeze, q.Job.Freeze) {
			return leaseRecord{}, failure(api.CodeForbidden, "archive retirement selected a foreign native job")
		}
		parent = p
	}
	if parent == nil {
		return leaseRecord{}, failure(api.CodeNotFound, "archive retirement has no original native owner")
	}
	p := *parent
	if w := p.Archive.Worker; w != nil {
		if !reflect.DeepEqual(w.Reg.Job, q.Job) || !reflect.DeepEqual(w.Reg.Claim.Record.Effect, q.Claim.Record.Effect) || q.Claim.Record.Generation < w.Reg.Claim.Record.Generation {
			return p, failure(api.CodeForbidden, "archive retirement selected a foreign native job")
		}
		if q.Allocation.ID != "" && q.Allocation != w.Lease || q.Process.ID != "" && (w.Gate == nil || q.Process != archiveHandle(*w)) {
			return p, failure(api.CodeForbidden, "archive retirement selected a foreign native lease or process")
		}
		if q.Handoff && w.Spec == nil {
			return p, failure(api.CodeContainmentUnknown, "archive retirement lost its committed handoff")
		}
	} else if q.Allocation.ID != "" || q.Process.ID != "" || q.Handoff {
		return p, failure(api.CodeContainmentUnknown, "archive absence cannot replace a known allocation")
	}
	if r := p.Archive.Retirement; r != nil && (!reflect.DeepEqual(r.Job, q.Job) || !reflect.DeepEqual(r.Claim.Record.Effect, q.Claim.Record.Effect) || q.Claim.Record.Generation < r.Claim.Record.Generation) {
		return p, failure(api.CodeForbidden, "archive retirement changed its original fenced job")
	}
	return p, nil
}

func (m *leaseManager) retireArchive(ctx context.Context, q archiveRetireQuery) (archivejob.Retirement, error) {
	var zero archivejob.Retirement
	if err := contextError(ctx); err != nil {
		return zero, err
	}
	if native, ok := m.resources.(*linuxResources); !ok || native.binding.Config != m.binding.Config {
		return zero, failure(api.CodeContainmentUnknown, "archive retirement requires native Linux resource ownership")
	}
	p, err := m.retirementParent(q)
	if err != nil {
		return zero, err
	}
	j, w := p.Archive, p.Archive.Worker
	if j.Retirement != nil && j.Retirement.Proof != nil {
		if err := m.retirementAbsent(ctx, q.Job, w); err != nil {
			return zero, err
		}
		return *j.Retirement.Proof, nil
	}
	if j.Retirement == nil {
		opened := w != nil && w.Gate != nil && (w.Gate.Permit != nil || w.Gate.Record != nil || w.Observation != nil || w.State == "opening" || w.State == "opened")
		j.Retirement = &archiveRetirementJournal{Job: q.Job, Claim: q.Claim, AuthorizedAt: gateTimestamp(), Opened: opened}
		if w != nil {
			w.Revoked = true
		}
		if err := m.save(p); err != nil {
			return zero, err
		}
	}
	r := j.Retirement
	proof := archivejob.Retirement{JobID: q.Job.ID, OperationID: q.Job.Intent.OperationID, EffectID: q.Job.Lease.EffectID, Target: q.Job.Lease.Target}
	if w == nil {
		if _, err := m.archiveSocketCount(ctx, q.Job.Lease.ID); err != nil {
			return zero, err
		}
		proof.Absent, proof.ObservedAt = true, gateTimestamp()
	} else if p.BootID != m.bootID {
		boot, err := m.retirementPreviousBoot(ctx, p)
		if err != nil {
			return zero, err
		}
		r.Boot, proof.Boot = &boot, &boot
		proof.Allocation, proof.ObservedAt = w.Lease, gateTimestamp()
		w.Collecting, w.Collected = false, true
	} else {
		if w.Collected {
			if err := m.retirementAbsent(ctx, q.Job, w); err != nil {
				return zero, err
			}
		}
		observation, err := m.retirementWait(ctx, &p)
		if err != nil {
			return zero, err
		}
		child := archiveChild(p, *w)
		if !w.Collected {
			if err := m.resources.Quiescent(ctx, child); err != nil {
				return zero, err
			}
		}
		// The wait status is original. Zero survivors comes only from the
		// independent native cgroup and complete UID scan above.
		survivors := uint64(0)
		observation.Survivors, observation.ObservedAt = &survivors, gateTimestamp()
		r.Observation = &observation
		w.State = "exited"
		if err := m.save(p); err != nil {
			return zero, err
		}
		var control uint64
		if live := m.gates[w.Lease.ID]; live != nil {
			if err := live.Close(); err != nil {
				return zero, err
			}
			native, ok := live.(*nativeGate)
			if !ok {
				return zero, failure(api.CodeContainmentUnknown, "archive retirement lost its native connection owner")
			}
			control, err = native.connectionCount()
			if err != nil {
				return zero, err
			}
		}
		connections, err := m.archiveSocketCount(ctx, q.Job.Lease.ID)
		if err != nil {
			return zero, err
		}
		connections += control
		jobs, err := m.captureJobs(ctx, child)
		if err != nil {
			return zero, err
		}
		exports, _, err := m.storageReferences(ctx, child)
		if err != nil {
			return zero, err
		}
		if connections != 0 || jobs != 0 || exports != 0 {
			return zero, failure(api.CodeContainmentUnknown, "archive retirement has native connections, jobs or writable exports")
		}
		if !w.Collected {
			w.Collecting = true
			if err := m.save(p); err != nil {
				return zero, err
			}
			if err := m.resources.Remove(ctx, child); err != nil {
				return zero, err
			}
			if err := m.resources.Quiescent(ctx, child); err != nil {
				return zero, err
			}
		}
		proof.Allocation = w.Lease
		if r.Opened {
			id, err := randomID("archive-release-")
			if err != nil {
				return zero, err
			}
			proof.Release = &api.ReleaseReceipt{ID: id, LeaseID: w.Lease.ID, ContainmentID: w.Lease.ContainmentID, Backend: "linux-bwrap-landlock", OperationID: proof.OperationID, EffectID: proof.EffectID, Quiescence: observation, LiveConnections: &connections, QueuedJobs: &jobs, WritableExports: &exports, ObservedAt: observation.ObservedAt}
		} else {
			id, err := randomID("archive-abort-")
			if err != nil {
				return zero, err
			}
			unopened := observation
			unopened.State, unopened.ExitCode, unopened.Signal = "not_started", nil, nil
			proof.Abort = &api.AbortReceipt{ID: id, LeaseID: w.Lease.ID, AgentExecuted: false, Quiescence: unopened, ObservedAt: unopened.ObservedAt}
		}
		proof.ObservedAt = gateTimestamp()
		w.Collecting, w.Collected = false, true
		delete(m.gates, w.Lease.ID)
	}
	if err := validateRetirementProof(q.Job, proof, time.Now()); err != nil {
		return zero, err
	}
	r.Proof = &proof
	if err := m.save(p); err != nil {
		return zero, err
	}
	p, err = m.find(p.Lease.ID)
	if err != nil {
		return zero, err
	}
	if p.Archive == nil || p.Archive.Retirement == nil || p.Archive.Retirement.Proof == nil {
		return zero, failure(api.CodeIntegrity, "archive retirement journal disappeared")
	}
	if err := m.retirementAbsent(ctx, q.Job, p.Archive.Worker); err != nil {
		return zero, err
	}
	return *p.Archive.Retirement.Proof, nil
}

func (m *leaseManager) retirementWait(ctx context.Context, p *leaseRecord) (api.ProcessObservation, error) {
	w, r := p.Archive.Worker, p.Archive.Retirement
	live := m.gates[w.Lease.ID]
	if w.Gate == nil {
		if live != nil || r.Opened || w.State != "reserved" && w.State != "allocated" && w.State != "registered" && w.State != "exited" {
			return api.ProcessObservation{}, failure(api.CodeContainmentUnknown, "unopened archive allocation has an unknown native gate")
		}
		if err := m.resources.Quiescent(ctx, archiveChild(*p, *w)); err != nil {
			return api.ProcessObservation{}, err
		}
		return api.ProcessObservation{Handle: api.ProcessHandle{ID: w.Reg.LaunchID, Target: w.Reg.Job.Lease.Target, ContainmentID: w.Lease.ContainmentID}, State: "not_started", PromptStatus: "not_written", ObservedAt: gateTimestamp()}, nil
	}
	if live == nil {
		if r.Observation != nil {
			return retirementTerminal(*r.Observation)
		}
		if w.Observation != nil {
			return retirementTerminal(*w.Observation)
		}
		return api.ProcessObservation{}, failure(api.CodeContainmentUnknown, "archive retirement lost its original native wait owner")
	}
	native, ok := live.(*nativeGate)
	if !ok || !r.Opened && native.released {
		return api.ProcessObservation{}, failure(api.CodeContainmentUnknown, "archive retirement cannot prove an unopened native gate")
	}
	if w.Gate.State == "preparing" && !r.Opened && w.Gate.PID == 0 && w.Gate.Prepared.ProcessGeneration == "" {
		path := filepath.Join(m.binding.cgroupPath(), string(w.Lease.ContainmentID))
		if err := verifyGateMembership(live.PID(), strings.TrimPrefix(path, "/sys/fs/cgroup")); err != nil {
			return api.ProcessObservation{}, err
		}
		generation, err := processGeneration(live.PID(), m.bootID)
		if err != nil || generation != live.Generation() {
			return api.ProcessObservation{}, failure(api.CodeContainmentUnknown, "preparing archive lost its original native generation")
		}
		w.Gate.PID, w.Gate.Prepared.ProcessGeneration = live.PID(), generation
		w.Gate.State, w.State = "prepared", "prepared"
		if err := m.save(*p); err != nil {
			return api.ProcessObservation{}, err
		}
	}
	if live.PID() != w.Gate.PID || live.Generation() != w.Gate.Prepared.ProcessGeneration {
		return api.ProcessObservation{}, failure(api.CodeIntegrity, "archive retirement native process identity changed")
	}
	observation, err := live.Observe(ctx, archiveHandle(*w))
	if err != nil {
		return observation, err
	}
	if observation.State != "exited" {
		if err := m.killContainment(ctx, archiveChild(*p, *w)); err != nil {
			return observation, err
		}
		// Stop owns the real command.Wait; it never infers reaping from an
		// empty cgroup or from the existence of a journal entry.
		if _, err := live.Stop(ctx, archiveHandle(*w)); err != nil {
			return observation, err
		}
		observation, err = live.Observe(ctx, archiveHandle(*w))
		if err != nil {
			return observation, err
		}
	}
	if _, err := retirementTerminal(observation); err != nil {
		return observation, err
	}
	r.Observation, w.State = &observation, "exited"
	if err := m.save(*p); err != nil {
		return observation, err
	}
	return observation, nil
}

func retirementTerminal(observation api.ProcessObservation) (api.ProcessObservation, error) {
	if observation.State != "exited" || (observation.ExitCode == nil) == (observation.Signal == nil) {
		return observation, failure(api.CodeContainmentUnknown, "archive retirement did not observe a terminal native wait")
	}
	return observation, nil
}

func (m *leaseManager) retirementPreviousBoot(ctx context.Context, p leaseRecord) (archivejob.BootRetirement, error) {
	var zero archivejob.BootRetirement
	w := p.Archive.Worker
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || strings.TrimSpace(string(boot)) != m.bootID || p.BootID == m.bootID || m.gates[w.Lease.ID] != nil {
		return zero, failure(api.CodeContainmentUnknown, "archive previous-boot retirement lost its actual kernel identity")
	}
	path := filepath.Join(m.binding.cgroupPath(), string(w.Lease.ContainmentID))
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return zero, failure(api.CodeContainmentUnknown, "archive previous-boot retirement still has a native cgroup")
	}
	if err := uidQuiescent(ctx, w.Lease.UID); err != nil {
		return zero, err
	}
	connections, err := m.archiveSocketCount(ctx, w.Reg.Job.Lease.ID)
	if err != nil {
		return zero, err
	}
	child := archiveChild(p, *w)
	jobs, err := m.captureJobs(ctx, child)
	if err != nil {
		return zero, err
	}
	exports, _, err := m.storageReferences(ctx, child)
	if err != nil {
		return zero, err
	}
	if connections != 0 || jobs != 0 || exports != 0 {
		return zero, failure(api.CodeContainmentUnknown, "archive previous-boot retirement retains native resources")
	}
	if err := contextError(ctx); err != nil {
		return zero, err
	}
	survivors := uint64(0) // Complete UID scan above, not an inferred wait.
	return archivejob.BootRetirement{PreviousBootID: p.BootID, BootID: m.bootID, Process: retirementProcess(*w), CgroupAbsent: true, Survivors: &survivors, LiveConnections: &connections, QueuedJobs: &jobs, WritableExports: &exports, ObservedAt: gateTimestamp()}, nil
}

func (m *leaseManager) retirementAbsent(ctx context.Context, job archivejob.Job, worker *archiveWorker) error {
	if worker != nil {
		if !worker.Collected || m.gates[worker.Lease.ID] != nil {
			return failure(api.CodeContainmentUnknown, "archive retirement retains an original native gate")
		}
		_, err := os.Lstat(filepath.Join(m.binding.cgroupPath(), string(worker.Lease.ContainmentID)))
		if !errors.Is(err, os.ErrNotExist) {
			return failure(api.CodeContainmentUnknown, "archive retirement still has an original native cgroup")
		}
	}
	_, err := m.archiveSocketCount(ctx, job.Lease.ID)
	return err
}
