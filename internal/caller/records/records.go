// Package records checks the optional report-line fields shared by event readers.
package records

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"laneboss.io/laneboss/internal/instancename"
)

var laneID = regexp.MustCompile(`^lane:[a-z0-9][a-z0-9._-]{0,63}$`)
var roleID = regexp.MustCompile(`^supervisor:[a-z0-9][a-z0-9-]{0,31}$`)
var oldSender = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// ValidID accepts the node identifiers used by the dashboard.
func ValidID(id string) bool {
	return id == "human" || laneID.MatchString(id) || roleID.MatchString(id) || strings.HasPrefix(id, "instance:") && instancename.Valid(strings.TrimPrefix(id, "instance:"))
}

// ValidSender keeps historical labels readable and accepts new canonical IDs.
// Message commands authenticate senders separately before writing an event.
func ValidSender(id string) bool { return ValidID(id) || oldSender.MatchString(id) }

// Integer accepts only integer-valued representations used by TOML and JSON.
func Integer(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), int64(int(n)) == n
	case json.Number:
		x, err := n.Int64()
		return int(x), err == nil && int64(int(x)) == x
	case float64:
		if n >= 0 && n <= 1<<31 && n == float64(int(n)) {
			return int(n), true
		}
	}
	return 0, false
}

// Validate leaves old events without these fields readable. Present fields must
// be valid, and a recorded level always has a recorded source (or both are null).
func Validate(p map[string]any) error {
	for _, key := range []string{"level", "level_source", "starter"} {
		if value, present := p[key]; present {
			if err := Field(key, value); err != nil {
				return err
			}
		}
	}
	level, hasLevel := p["level"]
	source, hasSource := p["level_source"]
	if hasLevel != hasSource || (level == nil) != (source == nil) {
		return fmt.Errorf("level and level_source must be recorded together")
	}
	return nil
}

// Field checks a single optional field; Validate also checks their relationship.
func Field(key string, value any) error {
	if value == nil {
		return nil
	}
	switch key {
	case "level":
		n, ok := Integer(value)
		if !ok || n < 3 || n > 6 {
			return fmt.Errorf("level must be null or an integer from 3 to 6")
		}
	case "level_source":
		if value != "supervisors" && value != "instance" && value != "protocol" && value != "org" {
			return fmt.Errorf("level_source must be supervisors, instance, protocol or org")
		}
	case "starter":
		id, ok := value.(string)
		if !ok || !ValidID(id) {
			return fmt.Errorf("starter must be null or a principal node id")
		}
	default:
		return fmt.Errorf("unknown report-line field")
	}
	return nil
}
