//go:build !laneboss_faults

package identityd

func claimedPeer(peer Peer, _ Request) (Peer, error) { return peer, nil }

func sameStart(a, b string) bool { return a != "" && a == b }

func appendActor(principal Principal, _ Request) string {
	return principal.ID
}

func allowUnknown() bool { return false }

func protocolVersion(version int) bool { return version == Version }

func storageModes() (uint32, uint32) { return 0700, 0600 }

func unboundStarter() bool { return false }

func replaceLiveRun() bool { return false }

func retainRuns(previous []Record, next Record) []Record {
	return append(previous, next)
}

func overlapRoot() bool { return false }

func foreignLaneScope() bool { return false }

func looseFieldCase() bool { return false }

func unsafeDetach() bool { return false }

func wideDetach() bool { return false }

func shortDetach() bool { return false }

func ignoreUIDSetting() bool { return false }

func dropRefusal() bool { return false }

func verifyLocked() bool { return false }

func unpinnedPeer() bool { return false }

func unlimitedPeer() bool { return false }

func unknownEvent() bool { return false }

func oversizedPayload() bool { return false }
