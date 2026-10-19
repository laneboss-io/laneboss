package laneturns

import (
	"strings"

	"laneboss.io/laneboss/internal/caller"
)

// carriedSender resolves mail that was already authenticated when enqueued.
// A config rewrite that omits the org can also omit its supervisor table.
// The lane's recorded starter still has the existing parent/child relationship;
// it needs no inferred level or recreated supervisor definition to deliver its
// queued mail. Every other sender retains current principal resolution.
func carriedSender(c *configuration, lane, id string) (caller.Principal, error) {
	principal, err := caller.Lookup(c.callerConfig(), id)
	if err == nil || !c.recordedTurnOrg || !strings.HasPrefix(id, "supervisor:") {
		return principal, err
	}
	name := strings.TrimPrefix(id, "supervisor:")
	if _, exists := obj(c.data["supervisors"])[name]; exists {
		return principal, err
	}
	target, recordErr := caller.Lane(c.callerConfig(), lane)
	if recordErr != nil {
		return caller.Principal{}, recordErr
	}
	if target.Starter != id {
		return principal, err
	}
	return caller.Principal{ID: id}, nil
}
