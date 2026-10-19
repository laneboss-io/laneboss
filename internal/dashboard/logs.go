package dashboard

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/eventstore"
)

var logTarget = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func (h *handler) logs(w http.ResponseWriter, r *http.Request, c *config.Configuration, binding *eventstore.Configuration, lanes, events []object) {
	name := r.URL.Query().Get("lane")
	count := 200
	if raw := r.URL.Query().Get("tail"); raw != "" {
		var err error
		count, err = strconv.Atoi(raw)
		if err != nil || count < 1 || count > 2000 {
			reply(w, 400, object{"error": "tail must be from 1 to 2000"})
			return
		}
	}
	if !logTarget.MatchString(name) {
		reply(w, 400, object{"error": "invalid log target"})
		return
	}
	known := map[string]bool{}
	for _, lane := range lanes {
		known[str(lane["lane"])] = true
	}
	source := name
	if !known[source] {
		org, err := orgView(c, events)
		if err != nil {
			reply(w, 503, object{"error": "log targets could not be read"})
			return
		}
		found := false
		for _, group := range []string{"instances", "supervisors"} {
			for _, entry := range org[group].([]any) {
				row := obj(entry)
				if row["name"] != name {
					continue
				}
				found = true
				candidates := []string{strings.ToLower(name), strings.TrimPrefix(name, fmt.Sprintf("L%d-", int(number(row["level"]))))}
				for _, candidate := range candidates {
					if known[candidate] {
						source = candidate
						break
					}
				}
			}
		}
		if !found {
			reply(w, 404, object{"error": "log target not found"})
			return
		}
		if !known[source] {
			reply(w, 200, object{"target": name, "available": false, "timeline": []object{}})
			return
		}
	}
	lines, available, err := eventstore.ReadOutputTailContext(r.Context(), binding, source, count)
	if err != nil {
		if r.Context().Err() != nil {
			return
		}
		reply(w, 503, object{"error": "the recorded log could not be read"})
		return
	}
	timeline := []object{}
	for i, line := range lines {
		if r.Context().Err() != nil {
			return
		}
		for _, event := range parseLog(line) {
			event["line"] = i + 1
			timeline = append(timeline, event)
		}
	}
	if len(timeline) > 2000 {
		timeline = timeline[len(timeline)-2000:]
	}
	reply(w, 200, object{"target": name, "available": available, "timeline": timeline})
}

func logCap(text string, limit int) string {
	runes := []rune(text)
	if len(runes) > limit {
		return string(runes[:limit-1]) + "…"
	}
	return text
}
func logTail(text string, limit int) string {
	runes := []rune(text)
	if len(runes) > limit {
		return "…" + string(runes[len(runes)-limit+1:])
	}
	return text
}
func logEntry(kind, text string) object {
	return object{"kind": logCap(kind, 80), "text": logCap(str(screen(text)), 1000)}
}
func contentText(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	result := []string{}
	if items, ok := value.([]any); ok {
		for _, item := range items {
			if text := str(obj(item)["text"]); text != "" {
				result = append(result, text)
			}
		}
	}
	return strings.Join(result, "\n")
}

func parseLog(line string) []object {
	if len(line) > 256*1024 || hasWithheld(screen(line)) {
		return []object{logEntry("withheld", "[withheld]")}
	}
	value, err := eventstore.Parse([]byte(line), "the vendor stream event")
	if err != nil {
		return []object{logEntry("unknown", "[unparsed event]")}
	}
	if hasWithheld(screen(value)) {
		return []object{logEntry("withheld", "[withheld]")}
	}
	e := obj(value)
	typeName := str(e["type"])
	result := []object{}
	switch typeName {
	case "assistant", "user":
		for _, item := range listContent(obj(e["message"])["content"]) {
			block := obj(item)
			switch str(block["type"]) {
			case "thinking":
				text := str(block["thinking"])
				if text == "" {
					text = contentText(block["summary"])
				}
				result = append(result, logEntry("thinking", text))
			case "text":
				if typeName == "assistant" {
					result = append(result, logEntry("assistant", str(block["text"])))
				} else {
					result = append(result, logEntry("unknown", "[user input]"))
				}
			case "tool_use":
				entry := logEntry("tool_use", logCap(str(block["name"]), 80)+" · "+eventstore.Canonical(logInput(block["input"])))
				entry["tool_name"] = logCap(str(block["name"]), 80)
				entry["input"] = logCap(eventstore.Canonical(logInput(block["input"])), 1000)
				entry["tool_id"] = block["id"]
				result = append(result, entry)
			case "tool_result":
				status := "ok"
				if flag(block["is_error"]) {
					status = "error"
				}
				entry := logEntry("tool_result", status+" · "+logTail(contentText(block["content"]), 900))
				entry["status"], entry["tool_id"] = status, block["tool_use_id"]
				entry["output"] = logTail(contentText(block["content"]), 900)
				result = append(result, entry)
			default:
				result = append(result, logEntry("unknown", "["+str(block["type"])+"]"))
			}
		}
	case "stream_event":
		delta := obj(obj(e["event"])["delta"])
		if delta["type"] == "thinking_delta" {
			result = append(result, logEntry("thinking", str(delta["thinking"])))
		} else if delta["type"] == "text_delta" {
			result = append(result, logEntry("assistant", str(delta["text"])))
		}
	case "item.started", "item.updated", "item.completed":
		item := obj(e["item"])
		switch str(item["type"]) {
		case "reasoning":
			result = append(result, logEntry("reasoning", contentText(item["text"])))
		case "agent_message":
			result = append(result, logEntry("assistant", str(item["text"])))
		case "command_execution":
			text := logCap(str(item["command"]), 250) + "\nstatus: " + str(item["status"]) + "; exit: " + fmt.Sprint(item["exit_code"]) + "\n" + logTail(str(item["aggregated_output"]), 650)
			entry := logEntry("command_execution", text)
			entry["tool_name"], entry["input"] = "command", logCap(str(item["command"]), 250)
			entry["output"], entry["exit_code"], entry["status"] = logTail(str(item["aggregated_output"]), 650), item["exit_code"], item["status"]
			result = append(result, entry)
		case "error":
			result = append(result, logEntry("error", str(item["message"])))
		default:
			result = append(result, logEntry("unknown", "["+str(item["type"])+"]"))
		}
	case "error":
		result = append(result, logEntry("error", str(e["message"])))
	case "turn.failed":
		result = append(result, logEntry("error", str(obj(e["error"])["message"])))
	}
	if len(result) == 0 {
		if typeName == "" {
			typeName = "unknown"
		}
		result = append(result, logEntry("unknown", "["+typeName+"]"))
	}
	return result
}

func listContent(value any) []any { result, _ := value.([]any); return result }

// A tool-input summary does not expand nested prompt or environment documents.
func logInput(value any) any {
	switch v := value.(type) {
	case object:
		result := object{}
		for key, item := range v {
			switch strings.ToLower(key) {
			case "prompt", "messages", "system", "instructions", "env", "environment":
				result[key] = "[not displayed]"
			default:
				result[key] = logInput(item)
			}
		}
		return result
	case []any:
		result := make([]any, len(v))
		for i, item := range v {
			result[i] = logInput(item)
		}
		return result
	default:
		return value
	}
}
