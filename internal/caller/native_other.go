//go:build !linux && !darwin

package caller

import "fmt"

func nativeProcess(pid int) (process, error) {
	return process{}, fmt.Errorf("kernel session identities are unavailable on this platform")
}
