//go:build laneboss_faults

package laneturns

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// probe exposes the same stream, room and tmux operations the launcher uses to
// the black-box migration harness, without loading an interpreter implementation.
func Probe(stdin io.Reader, stdout, stderr io.Writer) int {
	decoder := json.NewDecoder(io.LimitReader(stdin, 8<<20))
	decoder.UseNumber()
	var request object
	if err := decoder.Decode(&request); err != nil {
		fmt.Fprintln(stderr, "invalid input: unreadable lane probe")
		return 2
	}
	var result any
	var err error
	switch str(request["action"]) {
	case "shell-analysis":
		writes, named := analyseShell(str(request["command"]), str(request["directory"]))
		result = object{"writes": writes, "named": named}
	case "stream":
		if !isStringValue(request["name"]) || str(request["name"]) != "text" && str(request["name"]) != "claude-stream-json" {
			err = refused("unknown stream reader")
			break
		}
		result = readStream(str(request["name"]), str(request["line"]))
	case "room":
		var c *configuration
		c, err = loadConfig(str(request["config"]))
		if err == nil {
			runner := obj(obj(c.data["runners"])[str(request["runner"])])
			if runner == nil {
				err = refused("the runner is not configured")
				break
			}
			if obj(c.data["lanes"]) == nil {
				c.data["lanes"] = object{}
			}
			if request["timeout"] != nil {
				obj(c.data["lanes"])["room_timeout_seconds"] = request["timeout"]
			}
			if request["grace"] != nil {
				obj(c.data["lanes"])["stop_grace_seconds"] = request["grace"]
			}
			if runner["room"] != nil {
				answer := probeRoom(c, runner, str(request["account"]))
				result = object{"room": answer.room, "slots": answer.slots, "reason": answer.reason}
			}
		}
	case "tmux-new":
		_, err = tmuxNew(str(request["socket"]), str(request["name"]), str(request["directory"]), texts(request["argv"]))
	case "loop-argv":
		var executable string
		executable, err = os.Executable()
		if err == nil {
			result = loopArguments(executable, str(request["fifo"]))
		}
	default:
		err = refused("unknown lane probe action")
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if err := json.NewEncoder(stdout).Encode(probeFloats(result)); err != nil {
		fmt.Fprintln(stderr, "cannot write lane probe result")
		return 2
	}
	return 0
}

// Preserve the float type through the JSON bridge, as the old Python encoder
// did even for integral costs. The product reader keeps its native float64.
func probeFloats(value any) any {
	switch v := value.(type) {
	case float64:
		text := strconv.FormatFloat(v, 'g', -1, 64)
		if !strings.ContainsAny(text, ".eE") {
			text += ".0"
		}
		return json.Number(text)
	case []object:
		items := make([]any, len(v))
		for i, item := range v {
			items[i] = probeFloats(item)
		}
		return items
	case object:
		result := object{}
		for key, item := range v {
			result[key] = probeFloats(item)
		}
		return result
	default:
		return value
	}
}
