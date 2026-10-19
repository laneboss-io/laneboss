package dashboard

import (
	"io"
	"mime"
	"net/http"
	"strings"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/eventstore"
	"laneboss.io/laneboss/internal/refusal"
)

func (h *handler) reportRefusal(w http.ResponseWriter, r *http.Request) {
	if !h.humanOnly(w) {
		return
	}
	if r.URL.RawQuery != "" {
		reply(w, 400, object{"error": "query options are not accepted"})
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		reply(w, 415, object{"error": "a JSON request is required"})
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
	if err != nil {
		reply(w, 413, object{"error": "the report exceeds 8 KB"})
		return
	}
	parsed, err := eventstore.Parse(data, "the refusal report")
	body := obj(parsed)
	if err != nil || body == nil {
		reply(w, 400, object{"error": "invalid report JSON"})
		return
	}
	for key, value := range body {
		if key != "refusal" && key != "rule" && key != "effect" && key != "note" {
			reply(w, 400, object{"error": "unknown report field"})
			return
		}
		if _, ok := value.(string); !ok {
			reply(w, 400, object{"error": "report fields must be text"})
			return
		}
	}
	note := str(body["note"])
	if strings.TrimSpace(note) == "" || utf8.RuneCountInString(note) > 4000 || (str(body["refusal"]) == "") == (str(body["rule"]) == "") {
		reply(w, 400, object{"error": "select a refusal or rule and supply a note of at most 4000 characters"})
		return
	}
	if hasWithheld(eventstore.ScreenValue(body)) {
		reply(w, 422, object{"error": "the report contains a credential-shaped value; nothing was recorded"})
		return
	}
	receipt, err := refusal.Report(h.name, refusal.Request{Refusal: str(body["refusal"]), Rule: str(body["rule"]), Effect: str(body["effect"]), Note: note}, humanSender)
	if err != nil {
		reply(w, 422, object{"error": "the refusal report could not be recorded"})
		return
	}
	reply(w, 201, object{"proposal": receipt, "policy_changed": false})
}

func refusalGroups(cName string, events []object) (object, error) {
	c, err := configForGroups(cName)
	if err != nil {
		return nil, err
	}
	levels := map[string]int{}
	org, err := orgView(c, events)
	if err != nil {
		return nil, err
	}
	for _, group := range []string{"instances", "supervisors"} {
		for _, entry := range org[group].([]any) {
			row := obj(entry)
			levels[str(row["name"])] = int(number(row["level"]))
		}
	}
	return refusal.View(events, levels), nil
}
