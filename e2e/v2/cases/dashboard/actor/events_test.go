package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestDashboardEntryProvider(t *testing.T) {
	opt := options{Vendor: "actual-vendor", Life: "actual-life", Run: 2}
	var output bytes.Buffer
	input := envelope{Command: "lane status", RequestID: "actual-call", Request: json.RawMessage(`{"run":2}`)}
	result := reply{Exit: 2, Stdout: []byte("actual stdout"), Stderr: []byte("actual stderr")}
	for _, err := range []error{providerInit(&output, opt), providerTool(&output, opt, input, nil), providerTool(&output, opt, input, &result), (fixtureEncoder{opt, &output}).Encode(result), providerResult(&output, opt)} {
		if err != nil {
			t.Fatal(err)
		}
	}
	decoder := json.NewDecoder(&output)
	var frames []map[string]any
	for decoder.More() {
		var frame map[string]any
		if err := decoder.Decode(&frame); err != nil {
			t.Fatal(err)
		}
		frames = append(frames, frame)
	}
	if len(frames) != 5 || frames[0]["subtype"] != "init" || frames[0]["cwd"] != "/work/main" || frames[4]["type"] != "result" || frames[4]["is_error"] != false {
		t.Fatal("provider capture lost its actual session boundaries")
	}
	for _, frame := range frames {
		if frame["session_id"] != opt.Vendor {
			t.Fatal("provider capture replaced the reserved session")
		}
	}
	block := frames[2]["message"].(map[string]any)["content"].([]any)[0].(map[string]any)
	if block["tool_use_id"] != input.RequestID || block["is_error"] != true || frames[3]["type"] != "system" || frames[3]["fixture"].(map[string]any)["exit_code"] != float64(result.Exit) {
		t.Fatal("provider tool capture lost actual result or relay correlation")
	}
}
