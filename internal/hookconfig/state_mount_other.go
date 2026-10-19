//go:build !linux && !darwin

package hookconfig

import "errors"

func stateMount(path string) error {
	return errors.New("state root mounts cannot be vetted on this OS")
}
