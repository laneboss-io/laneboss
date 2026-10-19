//go:build !laneboss_faults

package orgtree

func decisionStoreFaultMode() (string, error)    { return "", nil }
func decisionStoreCompanionFault() (bool, error) { return false, nil }
