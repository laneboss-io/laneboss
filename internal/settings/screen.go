package settings

import "encoding/json"

// ScreenChoice applies the existing detector to a launch choice in its raw and
// JSON spelling. Labels and rejected values are never repeated by this helper.
func ScreenChoice(value string, screen func([]byte) error) error {
	if screen == nil {
		return nil
	}
	if err := screen([]byte(value)); err != nil {
		return err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return screen(encoded)
}
