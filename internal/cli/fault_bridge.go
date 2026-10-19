//go:build laneboss_faults

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"laneboss.io/laneboss/internal/adapters"
	"laneboss.io/laneboss/internal/identityd"
	"laneboss.io/laneboss/internal/judge"
	"laneboss.io/laneboss/internal/laneturns"
)

func init() { handlers["__test"] = testBridge }

func runLaneProbe(args []string, stdin io.Reader, stdout, stderr io.Writer) (int, bool) {
	if len(args) != 1 || args[0] != "__probe" {
		return 0, false
	}
	return laneturns.Probe(stdin, stdout, stderr), true
}

func testBridge(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "one bridge action is required")
		return 2
	}
	if args[0] == "room-choice" {
		return laneturns.ChoiceProbe(stdin, stdout, stderr)
	}
	if args[0] == "identityd-launch" {
		return identityd.LaunchProbe(stdin, stdout, stderr)
	}
	if args[0] == "attach-editor" {
		return laneturns.EditorProbe(stdin, stdout, stderr)
	}
	if args[0] == "judge-owner" {
		return judge.OwnerProbe(stdin, stdout, stderr)
	}
	decoder := json.NewDecoder(io.LimitReader(stdin, 8<<20))
	decoder.UseNumber()
	var cases []map[string]any
	if err := decoder.Decode(&cases); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	answers := []any{}
	for _, item := range cases {
		var answer any
		var err error
		if args[0] == "adapter-build" {
			kwargs, _ := item["kwargs"].(map[string]any)
			if item["call"] == "_operation" {
				var value string
				value, err = adapters.Operation(kwargs["value"])
				answer = map[string]any{"text": value}
			} else if item["call"] == "_dry_run" {
				var value bool
				value, err = adapters.DryRun(kwargs["value"])
				answer = map[string]any{"text": value}
			} else if item["call"] == "text_for" {
				request, _ := kwargs["request"].(map[string]any)
				var data []byte
				data, err = adapters.TextFor(request)
				answer = map[string]any{"text": string(data)}
			} else {
				var request map[string]any
				var keys []string
				form, _ := item["call"].(string)
				request, keys, err = adapters.Build(form, kwargs)
				answer = map[string]any{"keys": keys, "request": request}
			}
		} else if args[0] == "adapter-call" {
			form, _ := item["form"].(string)
			kwargs, _ := item["arguments"].(map[string]any)
			var request map[string]any
			request, _, err = adapters.Build(form, kwargs)
			if err == nil {
				answer, err = adapters.Call(item["command"], request, item["seconds"], item["credential_env"])
			}
		} else {
			fmt.Fprintln(stderr, "unknown bridge action")
			return 2
		}
		if err != nil {
			kind := "ValueError"
			var refused *adapters.Refused
			if errors.As(err, &refused) {
				kind = "Refused"
			}
			answer = map[string]any{"error": kind, "message": err.Error()}
		}
		answers = append(answers, answer)
	}
	var result any = answers
	if args[0] == "adapter-build" {
		result = map[string]any{"version": adapters.RequestVersion, "limit": adapters.MaxRequestBytes, "answers": answers}
	}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	return 0
}
