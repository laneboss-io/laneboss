//go:build !laneboss_faults

package start

func (s *storeSnapshot) pauseSnapshotForTest() error { return nil }
