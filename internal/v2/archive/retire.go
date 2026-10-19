package archive

import (
	"context"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// Retirement is an authenticated administrator readback. The helper reconciles
// the original allocation, observes, stops/reaps an opened worker or aborts an
// unopened one, and releases its resources before returning this evidence.
type Retirement struct {
	JobID       api.ID              `json:"job_id"`
	OperationID api.ID              `json:"operation_id"`
	EffectID    api.ID              `json:"effect_id"`
	Target      api.LifeRef         `json:"target"`
	Allocation  api.HelperLease     `json:"allocation"`
	Absent      bool                `json:"absent"`
	Release     *api.ReleaseReceipt `json:"release,omitempty"`
	Abort       *api.AbortReceipt   `json:"abort,omitempty"`
	Boot        *BootRetirement     `json:"boot,omitempty"`
	ObservedAt  api.Timestamp       `json:"observed_at"`
}

// BootRetirement measures a previous-boot allocation without inventing its
// lost wait status or claiming that a previously opened agent never executed.
// Process retains the original identity; none of these fields is an exit.
type BootRetirement struct {
	PreviousBootID  string            `json:"previous_boot_id"`
	BootID          string            `json:"boot_id"`
	Process         api.ProcessHandle `json:"process"`
	CgroupAbsent    bool              `json:"cgroup_absent"`
	Survivors       *uint64           `json:"survivors"`
	LiveConnections *uint64           `json:"live_connections"`
	QueuedJobs      *uint64           `json:"queued_jobs"`
	WritableExports *uint64           `json:"writable_exports"`
	ObservedAt      api.Timestamp     `json:"observed_at"`
}

// ValidateBootRetirement checks the authenticated helper measurement's shape.
// The helper must also compare both boot IDs to its retained/kernel identities;
// the writer binds Process and Allocation to its original durable job.
func ValidateBootRetirement(allocation api.HelperLease, target api.LifeRef, proof BootRetirement, retiredAt api.Timestamp) error {
	at, err := time.Parse(time.RFC3339Nano, string(proof.ObservedAt))
	end, endErr := time.Parse(time.RFC3339Nano, string(retiredAt))
	if err != nil || endErr != nil || at.IsZero() || at.After(end) ||
		!wire.ValidID(proof.PreviousBootID) || !wire.ValidID(proof.BootID) || proof.PreviousBootID == proof.BootID ||
		!wire.ValidID(string(proof.Process.ID)) || proof.Process.Target != target || proof.Process.ContainmentID != allocation.ContainmentID || !proof.CgroupAbsent {
		return &api.Error{Code: api.CodeContainmentUnknown, Owner: "lb-v2-admin", Message: "archive boot retirement lacks its original identity and measured absence", Instead: "Retain the allocation until both boot identities, cgroup absence and native resource counts are measured."}
	}
	for _, count := range []*uint64{proof.Survivors, proof.LiveConnections, proof.QueuedJobs, proof.WritableExports} {
		if count == nil || *count != 0 {
			return &api.Error{Code: api.CodeContainmentUnknown, Owner: "lb-v2-admin", Message: "archive boot retirement has unknown or surviving native resources", Instead: "Measure the complete UID, endpoint, capture and writable exports inventory before collection."}
		}
	}
	return nil
}

// Additive to the original archive helper methods. Recovery is measurement and
// collection only, including after expiry; it must never allocate or open work.
type RetirementHelper interface {
	RetireArchiveWorker(context.Context, Job, api.EffectLease) (Retirement, error)
}

type Recovery struct {
	Job        Job               `json:"job"`
	Allocation api.HelperLease   `json:"allocation"`
	Process    api.ProcessHandle `json:"process"`
	Handoff    bool              `json:"handoff"`
	Allocating bool              `json:"allocating"`
	Retirement *Retirement       `json:"retirement,omitempty"`
}
