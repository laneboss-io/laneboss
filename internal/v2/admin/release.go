package admin

import (
	"reflect"
	"strconv"

	"laneboss.io/laneboss/internal/v2/api"
)

// Only the resource owner supplies these observations. The service claim is
// never an input to ObserveRelease and never fills unknown counters.
type releaseFacts struct {
	Observation     api.ProcessObservation
	LiveConnections *uint64
	QueuedJobs      *uint64
	WritableExports *uint64
}

func compareRelease(record leaseRecord, claim api.ProcessObservation, measured releaseFacts) error {
	if err := validateObservation(record, measured.Observation); err != nil {
		return failure(api.CodeContainmentUnknown, "helper terminal observation is incomplete")
	}
	// The same rule, naming which count failed and its value (item 1 diagnosis, box 85).
	for _, c := range []struct {
		name  string
		count *uint64
	}{{"connections", measured.LiveConnections}, {"jobs", measured.QueuedJobs}, {"exports", measured.WritableExports}} {
		if c.count == nil {
			return failure(api.CodeContainmentUnknown, "helper connection, job or export count is unknown or nonzero ("+c.name+" unknown)")
		}
		if *c.count != 0 {
			return failure(api.CodeContainmentUnknown, "helper connection, job or export count is unknown or nonzero ("+c.name+" "+strconv.FormatUint(*c.count, 10)+")")
		}
	}
	actual := measured.Observation
	// Independently observed timestamps naturally differ. All process identity,
	// exit, prompt and survivor facts must still agree exactly.
	actual.ObservedAt, claim.ObservedAt = "", ""
	if !reflect.DeepEqual(actual, claim) {
		return failure(api.CodeContainmentUnknown, "helper measurement disagrees with the service claim")
	}
	return nil
}

func validateReceipt(record leaseRecord, request api.HelperReleaseRequest, receipt api.ReleaseReceipt) error {
	if !validID(receipt.ID) || receipt.LeaseID != request.LeaseID || receipt.ContainmentID != record.Lease.ContainmentID ||
		receipt.Backend != "linux-bwrap-landlock" || receipt.OperationID != request.Cause.CauseOperationID ||
		receipt.EffectID != request.Cause.EffectID || receipt.ObservedAt != receipt.Quiescence.ObservedAt {
		return failure(api.CodeIntegrity, "helper release measurement has mismatched identity or cause")
	}
	return compareRelease(record, request.Observation, releaseFacts{Observation: receipt.Quiescence,
		LiveConnections: receipt.LiveConnections, QueuedJobs: receipt.QueuedJobs, WritableExports: receipt.WritableExports})
}
