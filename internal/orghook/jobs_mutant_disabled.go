//go:build !laneboss_faults

package orghook

func jobRelaxBaseline(*instance, action, map[string]any, string) (bool, string, string, map[string]any) {
	return false, "", "", nil
}
