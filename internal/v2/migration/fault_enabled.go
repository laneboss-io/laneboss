//go:build laneboss_faults

package migration

import "laneboss.io/laneboss/internal/faults"

func faultMutation(point string) bool {
	if faults.Get(point).Point == "" {
		return false
	}
	if err := faults.Reach(point); err != nil {
		panic(err)
	}
	return true
}

func allowCorruptEvidence() bool { return faultMutation("migration-allow-corrupt") }

func allowActiveWriter() bool { return faultMutation("migration-allow-active-writer") }

func allowRehashedHistory() bool { return faultMutation("migration-allow-rehashed") }

func allowInPlaceOwnership() bool { return faultMutation("migration-allow-inplace") }

func allowLabelParent() bool { return faultMutation("migration-allow-label-parent") }

func resendDeliveredMail() bool { return faultMutation("migration-resend-delivered") }

func importActiveAuthority() bool { return faultMutation("migration-import-active") }

func allowOldBinaryRelink() bool { return faultMutation("migration-relink-old-binary") }
