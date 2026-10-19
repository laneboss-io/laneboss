//go:build !laneboss_faults

package migration

func allowCorruptEvidence() bool { return false }

func allowActiveWriter() bool { return false }

func allowRehashedHistory() bool { return false }

func allowInPlaceOwnership() bool { return false }

func allowLabelParent() bool { return false }

func resendDeliveredMail() bool { return false }

func importActiveAuthority() bool { return false }

func allowOldBinaryRelink() bool { return false }
