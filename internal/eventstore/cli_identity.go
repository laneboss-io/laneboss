package eventstore

import "laneboss.io/laneboss/internal/authorship"

// ValidateCLI is a write-boundary check. Stored-event validators must continue
// to read authentic dashboard events, including their reserved human actor.
func ValidateCLI(value any) (Object, error) {
	e, err := Validate(value)
	if err != nil {
		return nil, err
	}
	var reserved func(any) bool
	reserved = func(value any) bool {
		switch v := value.(type) {
		case Object:
			for key, item := range v {
				if (key == "actor" || key == "sender" || key == "from" || key == "sender_role" || key == "display_name") && authorship.Reserved(text(item)) {
					return true
				}
				if reserved(item) {
					return true
				}
			}
		case []any:
			for _, item := range v {
				if reserved(item) {
					return true
				}
			}
		}
		return false
	}
	if reserved(e) {
		return nil, Refuse("human actor and sender names are reserved for the dashboard; use your lane, instance, supervisor or cli identity\nInstead: leave the identity to the launcher, which records who you are, or report up with laneboss report.")
	}
	return e, nil
}
