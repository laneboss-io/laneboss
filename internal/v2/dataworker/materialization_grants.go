package dataworker

import (
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/lstate"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

func workerGrantCeilings(g api.GrantSet, d api.DataGrant, r api.LaunchReservation, source api.ProjectLaunchSource, lease api.WorkerLease, now time.Time) error {
	if g.ParentLifeID != r.Target.LifeID || g.Generation != 1 || !manifest.ValidID(d.ID) || d.ID == source.GrantID {
		return lstate.Error(api.CodeForbidden, "materialization worker grant identities differ from their narrow generation")
	}
	setExpiry, err := manifest.Expiry(g.ExpiresAt, now)
	if err != nil {
		return err
	}
	dataExpiry, err := manifest.Expiry(d.ExpiresAt, now)
	if err != nil {
		return err
	}
	leaseExpiry, err := manifest.Time(lease.ExpiresAt)
	if err != nil {
		return err
	}
	if dataExpiry.After(setExpiry) || setExpiry.After(leaseExpiry) {
		return lstate.Error(api.CodeForbidden, "materialization worker grants exceed their set or lease expiry ceiling")
	}
	return nil
}
