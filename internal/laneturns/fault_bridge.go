//go:build laneboss_faults

package laneturns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// EditorProbe drives the native editor and its actual output-holding policy.
func EditorProbe(stdin io.Reader, stdout, stderr io.Writer) int {
	var request struct {
		Input     string   `json:"input"`
		Continued bool     `json:"continued"`
		History   []string `json:"history"`
		Discarded bool     `json:"discarded"`
		Typed     any      `json:"typed"`
		HintOnly  bool     `json:"hint_only"`
	}
	if err := json.NewDecoder(stdin).Decode(&request); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	var output bytes.Buffer
	v := &attachView{out: &output, errOut: io.Discard, terminal: true, history: request.History, prompt: "attach> "}
	if request.Continued {
		v.continued = []string{"earlier line"}
	}
	escape := ""
	for _, ch := range []byte(request.Input) {
		v.byte(ch, &escape)
	}
	typed := v.somethingTyped()
	v.emit("answer\n")
	hintTyped := any(typed)
	if request.HintOnly {
		hintTyped = request.Typed
	}
	result := object{"typed": typed, "typing": v.typing(), "hint": attachHintText(request.Discarded, hintTyped), "output": output.String(), "pending": v.pending}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	return 0
}

// ChoiceProbe passes test inputs to the same choice function a turn uses.
func ChoiceProbe(stdin io.Reader, stdout, stderr io.Writer) int {
	decoder := json.NewDecoder(io.LimitReader(stdin, 1<<20))
	decoder.UseNumber()
	var request object
	if err := decoder.Decode(&request); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	c, err := loadConfig(str(request["config"]))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	runner := obj(obj(c.data["runners"])[str(request["runner"])])
	if runner == nil {
		fmt.Fprintln(stderr, "runner not configured")
		return 2
	}
	if obj(c.data["lanes"]) == nil {
		c.data["lanes"] = object{}
	}
	for input, setting := range map[string]string{"timeout": "room_timeout_seconds", "grace": "stop_grace_seconds"} {
		if request[input] != nil {
			obj(c.data["lanes"])[setting] = request[input]
		}
	}
	started := map[string]int{}
	for key, value := range obj(request["started"]) {
		started[key] = integer(value)
	}
	result := accountChoice(c, runner, request["account"], request["previous"], object{"excluded_accounts": request["excluded"]}, started)
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	return 0
}
