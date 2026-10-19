package api

import "time"

// UsageJob is private installed worker state. No public method accepts a job,
// launch identity, native allocation, scope or bootstrap frame from a caller.
type UsageJob struct {
	ID                ID                   `json:"id"`
	Input             UsageCredentialInput `json:"input"`
	Lease             WorkerLease          `json:"lease"`
	Runtime           LaunchRuntime        `json:"runtime"`
	Plan              WorkerPlan           `json:"plan"`
	Grants            GrantSet             `json:"grants"`
	LaunchID          ID                   `json:"launch_id"`
	Actor             Actor                `json:"actor"`
	ParentLeaseID     ID                   `json:"parent_lease_id"`
	CancellationEpoch Generation           `json:"cancellation_epoch"`
	Cause             InternalIntent       `json:"cause"`
}

type UsageStage struct {
	Job        UsageJob             `json:"job"`
	Claim      EffectLease          `json:"claim"`
	Allocation HelperLease          `json:"allocation"`
	Endpoint   *InstalledBinding    `json:"endpoint,omitempty"`
	Handoff    *PreparedSpecHandoff `json:"handoff,omitempty"`
	Prepared   *PreparedLaunch      `json:"prepared,omitempty"`
	Process    *ProcessHandle       `json:"process,omitempty"`
}

func ValidateUsageJob(job UsageJob, now time.Time) error {
	r, lease, plan := job.Input.Request, job.Lease, job.Plan
	expires, err := time.Parse(time.RFC3339Nano, string(lease.ExpiresAt))
	if job.Input.Schema != "laneboss.usage-input.v1" || job.Input.ProfileGeneration == 0 || job.Input.VendorProfile == "" ||
		!launchID(job.ID) || !launchID(job.LaunchID) || !launchID(job.ParentLeaseID) || job.Actor.Kind != "worker" || !launchID(job.Actor.ID) || job.Actor.Level != 0 || job.Actor.Role != "" ||
		lease.Kind != "usage" || lease.Target != r.Target || lease.OperationID != r.OperationID || lease.RuntimeManifest != r.RuntimeManifest || lease.GrantSetID != job.Grants.ID ||
		!launchBlob(lease.Input, "usage_input") || lease.Generation != 1 || lease.ConsumedBy != "" || err != nil || !expires.After(now) ||
		plan.Schema != "laneboss.worker-plan.v2" || plan.Kind != "usage" || plan.Input != lease.Input || plan.GrantSetID != lease.GrantSetID || plan.Executable != job.Runtime.Executable ||
		job.Runtime.Manifest != r.RuntimeManifest || !launchExecutable(plan.Executable) || plan.Budget.WallMS < 1 || plan.Budget.WallMS > 60000 ||
		len(job.Grants.Data)+len(job.Grants.Profiles)+len(job.Grants.Resources)+len(job.Grants.Channels) != 0 ||
		len(job.Grants.Secrets) != 1 || job.Grants.Secrets[0] != job.Input.Source {
		return launchInvalid("usage worker differs from its protected causing run and narrow input")
	}
	return nil
}
