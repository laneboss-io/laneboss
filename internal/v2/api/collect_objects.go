package api

import "time"

// ValidateCleanupObjectResults checks the complete writer result before the
// administrator may remove a workspace. It performs no I/O and does not replace
// the protected journals and fresh namespace reads required by VerifyCleanup.
func ValidateCleanupObjectResults(job CleanupJob, inventory CleanupInventory, results []ObjectDisposition, now time.Time) error {
	if err := ValidateCleanupInventory(job, inventory, now); err != nil {
		return err
	}
	if len(results) != len(inventory.Objects) {
		return launchInvalid("cleanup object results omitted an inventory member")
	}
	seen := map[ID]bool{}
	for n, object := range inventory.Objects {
		result := results[n]
		action, reason := cleanupDisposition(object, job.Intent.Cause.Target)
		state := "present"
		if action == "remove" {
			state = "absent"
		}
		if result.ObjectID != object.Ref.ID || result.Action != action || result.Reason != reason ||
			!cleanupOrder(result.Before.ObservedAt, result.After.ObservedAt) || !cleanupOrder(job.Intent.Archive.VerifiedAt, result.Before.ObservedAt) ||
			!cleanupObjectReadback(object, result.Before, "present", now) || !cleanupObjectReadback(object, result.After, state, now) ||
			seen[result.Before.ID] || seen[result.After.ID] || result.Before.ID == result.After.ID {
			return launchInvalid("cleanup object results lack exact ordered removal or retention readbacks")
		}
		seen[result.Before.ID], seen[result.After.ID] = true, true
	}
	return nil
}
