package laneturns

import (
	"fmt"
	"math"
	"strings"
)

func cutText(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}
func answerSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 32 && r != '\n' && r != '\t' || r >= 127 && r <= 159 {
			return -1
		}
		return r
	}, screened(s))
}
func streamLabel(prefix, name string, input object) string {
	subject := ""
	for _, key := range []string{"command", "file_path", "pattern", "path", "url"} {
		if candidate, ok := input[key].(string); ok {
			subject = cutText(screened(candidate), 100)
			break
		}
	}
	return shown("[" + prefix + " " + screened(name) + "] " + subject)
}
func readStream(name, line string) []object {
	raw := func() []object { return []object{{"kind": "raw", "text": shown(cutText(screened(line), 200))}} }
	if name == "text" {
		return []object{{"kind": "answer", "text": answerSafe(line)}}
	}
	if name != "claude-stream-json" {
		return []object{{"kind": "notice", "text": "unknown stream reader"}}
	}
	if strings.TrimSpace(line) == "" {
		return []object{}
	}
	p, err := decodeJSON([]byte(line))
	if err != nil {
		return raw()
	}
	switch str(p["type"]) {
	case "system":
		switch str(p["subtype"]) {
		case "init":
			if mode, ok := p["permissionMode"].(string); ok {
				return []object{{"kind": "mode", "mode": shown(screened(mode))}}
			}
			return []object{}
		case "hook_started", "ui_invalidate", "status", "thinking_tokens", "task_started", "task_notification":
			return []object{}
		case "notification":
			if text, ok := p["text"].(string); ok && text != "" {
				return []object{{"kind": "notice", "text": shown(cutText(screened(text), 100))}}
			}
			return raw()
		case "hook_response":
			outcome := str(p["outcome"])
			code := p["exit_code"]
			if outcome == "success" && (code == nil || isWhole(code) && integer(code) == 0) {
				return []object{}
			}
			if outcome == "" && !isWhole(code) {
				return raw()
			}
			text := "hook"
			if name := str(p["hook_name"]); name != "" {
				text += " " + name
			}
			if outcome != "" {
				text += ": " + outcome
			}
			if isWhole(code) {
				text += fmt.Sprintf(" (exit %d)", integer(code))
			}
			return []object{{"kind": "notice", "text": shown(cutText(screened(text), 100))}}
		}
		return raw()
	case "rate_limit_event":
		if obj(p["rate_limit_info"])["status"] == "allowed" {
			return []object{}
		}
		return raw()
	case "user":
		found := false
		for _, item := range array(obj(p["message"])["content"]) {
			b := obj(item)
			if b["type"] != "tool_result" {
				continue
			}
			found = true
			if flag(b["is_error"]) {
				text := str(b["content"])
				if _, ok := b["content"].(string); !ok {
					for _, entry := range array(b["content"]) {
						v := obj(entry)
						if v["type"] == "text" {
							if t, ok := v["text"].(string); ok {
								text = t
								break
							}
						}
					}
				}
				return []object{{"kind": "tool", "label": shown("[tool error] " + cutText(screened(text), 100))}}
			}
		}
		if found {
			return []object{}
		}
		return raw()
	case "stream_event":
		event := obj(p["event"])
		delta := obj(event["delta"])
		if event["type"] == "content_block_delta" && delta["type"] == "text_delta" {
			if text, ok := delta["text"].(string); ok {
				return []object{{"kind": "answer", "text": answerSafe(text)}}
			}
		}
		return []object{}
	case "assistant":
		items := []object{}
		for _, item := range array(obj(p["message"])["content"]) {
			b := obj(item)
			switch b["type"] {
			case "text":
				if text, ok := b["text"].(string); ok {
					items = append(items, object{"kind": "answer", "text": answerSafe(text), "streamed": false})
				}
			case "tool_use":
				if name, ok := b["name"].(string); ok {
					items = append(items, object{"kind": "tool", "label": streamLabel("tool", name, obj(b["input"]))})
				}
			}
		}
		return items
	case "result":
		var cost any
		if value := p["total_cost_usd"]; isWhole(value) || isFloat(value) {
			n := number(p["total_cost_usd"])
			if !math.IsNaN(n) && !math.IsInf(n, 0) {
				cost = n
			}
		}
		denials := []any{}
		for _, item := range array(p["permission_denials"]) {
			d := obj(item)
			name, ok := d["tool_name"].(string)
			input := obj(d["tool_input"])
			if ok && input != nil {
				denials = append(denials, streamLabel("denied", name, input))
			}
		}
		return []object{{"kind": "result", "cost": cost, "error": flag(p["is_error"]), "denials": denials}}
	}
	return raw()
}
