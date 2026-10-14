package lane

import (
	"bytes"
	"database/sql"
	"sort"
)

// The private resource fold preserves the accepting-state gate of the shared store.
func checkResources(db *sql.DB, lane string, p object) error {
	records, err := foldResources(db)
	if err != nil {
		return err
	}
	ids := []string{}
	for id, r := range records {
		if str(r["lane"]) == lane && contains([]string{"intent", "acquired"}, str(r["state"])) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	held := []any{}
	for _, id := range ids {
		held = append(held, object{"resource": id, "state": records[id]["state"]})
	}
	given := p["held"]
	if given == nil {
		given = []any{}
	}
	if !bytes.Equal(canonical(given), canonical(held)) {
		return refuse("lane.state: payload.held must list exactly the resources lane %s holds now, each with its state, and be left out when it holds none", lane)
	}
	return nil
}
