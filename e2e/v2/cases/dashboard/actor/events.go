package main

import (
	"encoding/json"
	"io"
	"os"
)

type fixtureEncoder struct {
	opt    options
	writer io.Writer
}

func (e fixtureEncoder) Encode(value any) error {
	return json.NewEncoder(e.writer).Encode(map[string]any{"type": "system", "subtype": "dashboard-fixture",
		"session_id": e.opt.Vendor, "fixture": value})
}

func providerInit(writer io.Writer, opt options) error {
	return json.NewEncoder(writer).Encode(map[string]any{"type": "system", "subtype": "init",
		"session_id": opt.Vendor, "cwd": "/work/main", "vendor_stood_in": true})
}

func providerTool(writer io.Writer, opt options, input envelope, result *reply) error {
	block := map[string]any{"type": "tool_use", "id": input.RequestID, "name": "installed_cli",
		"input": map[string]any{"command": input.Command, "request": input.Request}}
	kind := "assistant"
	if result != nil {
		kind = "user"
		block = map[string]any{"type": "tool_result", "tool_use_id": input.RequestID,
			"is_error": result.Exit != 0, "content": result}
	}
	return json.NewEncoder(writer).Encode(map[string]any{"type": kind, "session_id": opt.Vendor,
		"message": map[string]any{"content": []any{block}}})
}

func providerResult(writer io.Writer, opt options) error {
	return json.NewEncoder(writer).Encode(map[string]any{"type": "result", "subtype": "success",
		"session_id": opt.Vendor, "is_error": false, "permission_denials": []any{}})
}

func emitFixture(opt options, value any) error { return (fixtureEncoder{opt, os.Stdout}).Encode(value) }
