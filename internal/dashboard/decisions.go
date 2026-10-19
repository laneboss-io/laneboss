package dashboard

import (
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/decisions"
	"laneboss.io/laneboss/internal/eventstore"
)

// The selected configuration's standard decision database is never supplied by
// an HTTP parameter. It can be built with decisions init --db STATE/decisions.sqlite.
func decisionView(binding *eventstore.Configuration, query string, lanes []object) (object, error) {
	d, err := binding.OpenDirectory(false)
	if err != nil {
		return nil, err
	}
	if d != nil {
		defer d.Close()
	}
	value, err := decisions.ReadDisplay(filepath.Join(binding.StatePath, "decisions.sqlite"), query)
	if err != nil {
		return nil, err
	}
	for _, entry := range value["items"].([]map[string]any) {
		entry["question"] = capText(str(screen(entry["question"])))
		entry["text"] = capText(str(screen(entry["text"])))
		entry["source"] = "/api/decisions?q=" + url.QueryEscape(str(entry["id"]))
	}
	changes := map[string]object{}
	usage := map[string]object{}
	known := map[string]bool{}
	for _, lane := range lanes {
		known[str(lane["lane"])] = true
	}
	for _, change := range value["changes"].([]map[string]any) {
		at, e := time.Parse(time.RFC3339Nano, str(change["time"]))
		if e != nil {
			continue
		}
		key := hour(at)
		if changes[key] == nil {
			changes[key] = object{"hour": key, "count": nil, "ids": []any{}, "source": "/api/decisions"}
		}
		bump(changes[key], "count")
		changes[key]["ids"] = append(changes[key]["ids"].([]any), change["id"])
	}
	for _, feedback := range value["feedback"].([]map[string]any) {
		if feedback["event"] != "cited" {
			continue
		}
		key := str(feedback["case_id"]) + "\n" + str(feedback["source"])
		if usage[key] == nil {
			var lane any
			name := strings.TrimPrefix(str(feedback["source"]), "lane:")
			if known[name] {
				lane = name
			}
			usage[key] = object{"id": feedback["case_id"], "source_record": feedback["source"], "lane": lane, "count": nil, "source": "/api/decisions?q=" + url.QueryEscape(str(feedback["case_id"]))}
		}
		bump(usage[key], "count")
	}
	value["changes_per_hour"], value["usage"] = metricRows(changes), metricRows(usage)
	return value, nil
}
