package config

import (
	"errors"
	"github.com/BurntSushi/toml"
)

// ScreenSettings applies the launcher's existing credential detector without
// repeating rejected input. Layered settings contain secret names only.
func ScreenSettings(data []byte) error {
	var document map[string]any
	_, parseErr := toml.Decode(string(data), &document)
	_, valueRule := detectValue(document)
	if detectText(string(data)) != nil || parseErr == nil && valueRule != "" {
		return errors.New("settings look like a credential; use environment variable names, never values")
	}
	return nil
}
