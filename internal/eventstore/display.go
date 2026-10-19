package eventstore

import (
	"context"
	"os"
	"path/filepath"
)

// ScreenValue uses the event command's value/credential screen, including field
// names and sensitive assignments. It returns a copy suitable for display.
func ScreenValue(value any) any {
	switch v := value.(type) {
	case floatValue:
		return float64(v)
	case string:
		return shown(v)
	case Object:
		result := Object{}
		for key, item := range v {
			if credentialText(key) != "" {
				result["[withheld]"] = "[withheld]"
				continue
			}
			if s, ok := item.(string); ok && sensitiveName.MatchString(key) && literalQuoted(s) {
				result[key] = "[withheld]"
			} else {
				result[key] = ScreenValue(item)
			}
		}
		return result
	case []Object:
		result := make([]any, len(v))
		for i, item := range v {
			result[i] = ScreenValue(item)
		}
		return result
	case []any:
		result := make([]any, len(v))
		for i, item := range v {
			result[i] = ScreenValue(item)
		}
		return result
	case []string:
		result := make([]any, len(v))
		for i, item := range v {
			result[i] = shown(item)
		}
		return result
	default:
		return value
	}
}

// ReadDisplay returns lane projections, then events, from one SQLite snapshot
// without creating a state directory, ownership marker, lock file, database or
// projection. It deliberately returns integrity-checked event bytes to its
// caller, which MUST screen display output. Ordinary CLI readers keep their
// existing reject-on-credential behavior.
func ReadDisplay(c *Configuration) ([]Object, []Object, error) {
	return ReadDisplayContext(context.Background(), c)
}

func ReadDisplayContext(ctx context.Context, c *Configuration) ([]Object, []Object, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	d, err := c.OpenDirectory(false)
	if err != nil {
		return nil, nil, err
	}
	if d == nil {
		return []Object{}, []Object{}, nil
	}
	defer d.Close()
	marker, err := d.Marker()
	if err != nil {
		return nil, nil, err
	}
	info, err := d.StoreInfo()
	if err != nil {
		return nil, nil, err
	}
	recorded := object(marker["store"])
	if recorded == nil {
		if info == nil || info.Size() == 0 {
			return []Object{}, []Object{}, nil
		}
		return nil, nil, Integrity("an unrecorded event store is never adopted by a display reader")
	}
	if info == nil || info.Size() == 0 {
		return nil, nil, Integrity("the recorded event store is missing or empty")
	}
	s, err := database(filepath.Join(d.Path, storeFile), "ro")
	if err != nil {
		return nil, nil, err
	}
	defer s.Close()
	s.Dir = d
	if err = s.check(text(recorded["id"])); err != nil {
		return nil, nil, err
	}
	if err = s.exec("PRAGMA query_only = ON"); err != nil {
		return nil, nil, err
	}
	if err = s.exec("BEGIN"); err != nil {
		return nil, nil, err
	}
	defer s.rollback()
	rows, err := s.connection.QueryContext(ctx, "SELECT "+columns+" FROM events ORDER BY seq")
	if err != nil {
		return nil, nil, Integrity("the event store is not readable")
	}
	events := []Object{}
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			rows.Close()
			return nil, nil, err
		}
		event, e := eventContent(rows)
		if e != nil {
			rows.Close()
			return nil, nil, e
		}
		events = append(events, event)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, nil, Integrity("the event store is not readable")
	}
	// Reuse the stored projection's parser and form checks, but let the display
	// screen replace credentials instead of returning their values to a client.
	rows, err = s.connection.QueryContext(ctx, "SELECT projection FROM lanes ORDER BY lane")
	if err != nil {
		return nil, nil, Integrity("the lane projection is not readable")
	}
	lanes := []Object{}
	for rows.Next() {
		var encoded string
		if rows.Scan(&encoded) != nil {
			rows.Close()
			return nil, nil, Integrity("the lane projection is not readable")
		}
		value, e := Parse([]byte(encoded), "the lane projection")
		if e != nil || !currentForm(object(value)) {
			rows.Close()
			return nil, nil, Integrity("the lane projection is not in this version's form; run state rebuild")
		}
		lanes = append(lanes, object(value))
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, nil, Integrity("the lane projection is not readable")
	}
	if err = d.checkIdentity(); err != nil {
		return nil, nil, err
	}
	current, err := os.Lstat(filepath.Join(d.Path, storeFile))
	if err != nil || !os.SameFile(info, current) {
		return nil, nil, Integrity("the event store changed while it was read")
	}
	return lanes, events, nil
}
