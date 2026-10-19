//go:build laneboss_faults

package identityd

import (
	"encoding/json"

	"laneboss.io/laneboss/internal/faults"
)

func mutation(point string) bool {
	if faults.Get(point).Point == "" {
		return false
	}
	if err := faults.Reach(point); err != nil {
		panic(err)
	}
	return true
}

// This deliberately vulnerable path is absent from release builds. It reads a
// real process, but chooses it using a client label rather than SO_PEERCRED.
func claimedPeer(peer Peer, request Request) (Peer, error) {
	var claim struct {
		PID int `json:"pid"`
	}
	if json.Unmarshal(request.Claim, &claim) == nil && claim.PID > 1 && mutation("identityd-trust-pid") {
		current, err := nativeProcess(claim.PID)
		return current.Peer, err
	}
	return peer, nil
}

func sameStart(a, b string) bool {
	if mutation("identityd-no-start") {
		return a != "" && b != ""
	}
	return a != "" && a == b
}

func appendActor(principal Principal, request Request) string {
	var claim struct {
		Actor string `json:"actor"`
	}
	if json.Unmarshal(request.Claim, &claim) == nil && claim.Actor != "" && mutation("identityd-append-actor") {
		return claim.Actor
	}
	return principal.ID
}

func allowUnknown() bool { return mutation("identityd-allow-unknown") }
func protocolVersion(version int) bool {
	return version == Version || mutation("identityd-ignore-version")
}

func storageModes() (uint32, uint32) {
	if mutation("identityd-public-store") {
		return 0750, 0660
	}
	return 0700, 0600
}

func unboundStarter() bool { return mutation("identityd-lane-owner") }

func replaceLiveRun() bool { return mutation("identityd-live-run") }

func retainRuns(previous []Record, next Record) []Record {
	if len(previous) > 0 && mutation("identityd-forget-runs") {
		previous = nil
	}
	return append(previous, next)
}

func overlapRoot() bool { return mutation("identityd-overlap-root") }

func foreignLaneScope() bool { return mutation("identityd-foreign-lane") }

func looseFieldCase() bool { return mutation("identityd-field-case") }

func unsafeDetach() bool { return mutation("identityd-no-detach") }

func wideDetach() bool { return mutation("identityd-wide-detach") }

func shortDetach() bool { return mutation("identityd-short-detach") }

func ignoreUIDSetting() bool { return mutation("identityd-uid-setting") }

func dropRefusal() bool { return mutation("identityd-drop-refusal") }

func verifyLocked() bool { return mutation("identityd-verify-lock") }

func unpinnedPeer() bool { return mutation("identityd-no-peer-pin") }

func unlimitedPeer() bool { return mutation("identityd-peer-slots") }

func unknownEvent() bool { return mutation("identityd-any-event") }

func oversizedPayload() bool { return mutation("identityd-large-payload") }
