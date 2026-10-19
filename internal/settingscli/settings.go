// Package settingscli exposes the shared resolver without starting a runner.
package settingscli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"laneboss.io/laneboss/internal/cliargs"
	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/eventstore"
	"laneboss.io/laneboss/internal/rolepolicy"
	"laneboss.io/laneboss/internal/settings"
)

const usage = "usage: laneboss settings {get KEY,list} --config NAME [--lane L | --instance I] [--explain]"

func explanation(entry settings.Entry) map[string]any {
	result := map[string]any{"value": entry.Value, "layers": entry.Layers, "winner": entry.Winner}
	if entry.Merge != "" {
		result["merge"], result["winner"] = entry.Merge, nil
	}
	return result
}

type options struct {
	action, config, lane, instance, key string
	explain, help                       bool
}

func parse(args []string) (options, error) {
	o := options{}
	for _, arg := range args {
		if arg == "--help" || arg == "-h" {
			o.help = true
			return o, nil
		}
	}
	if len(args) == 0 || args[0] != "get" && args[0] != "list" {
		return o, errors.New(cliargs.Required("ACTION"))
	}
	o.action = args[0]
	seen := map[string]bool{}
	for i := 1; i < len(args); i++ {
		arg, value, inline := strings.Cut(args[i], "=")
		if arg == "--explain" && !inline && !seen[arg] {
			o.explain = true
			seen[arg] = true
			continue
		}
		if !strings.HasPrefix(arg, "--") {
			if o.action != "get" || o.key != "" || !settings.Known(args[i]) {
				return o, errors.New(cliargs.Reject("KEY"))
			}
			o.key = args[i]
			continue
		}
		if seen[arg] || arg != "--config" && arg != "--lane" && arg != "--instance" {
			return o, errors.New(cliargs.Reject(""))
		}
		seen[arg] = true
		if !inline {
			i++
			if i == len(args) || strings.HasPrefix(args[i], "--") {
				return o, errors.New(cliargs.Expected(arg))
			}
			value = args[i]
		}
		if value == "" {
			return o, errors.New(cliargs.Reject(""))
		}
		if err := config.ScreenSettings([]byte(value)); err != nil {
			return o, err
		}
		switch arg {
		case "--config":
			o.config = value
		case "--lane":
			o.lane = value
		case "--instance":
			o.instance = value
		}
	}
	if o.config == "" {
		return o, errors.New(cliargs.Required("--config"))
	}
	if o.lane != "" && o.instance != "" {
		return o, errors.New(cliargs.Conflict("--lane", "--instance"))
	}
	if o.action == "get" && o.key == "" {
		return o, errors.New(cliargs.Required("KEY"))
	}
	return o, nil
}

func resolve(o options, external *bool) (*settings.Snapshot, error) {
	if o.lane != "" {
		if !regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`).MatchString(o.lane) {
			return nil, errors.New("--lane must be a documented lane name")
		}
		c, err := eventstore.Bind(o.config)
		if err != nil {
			return nil, err
		}
		_, events, err := eventstore.ReadDisplay(c)
		if err != nil {
			return nil, err
		}
		for i := len(events) - 1; i >= 0; i-- {
			event := events[i]
			if event["lane"] != o.lane || event["kind"] != "lane.started" {
				continue
			}
			p, _ := event["payload"].(map[string]any)
			if p["settings"] == nil {
				return nil, errors.New("this historic lane has no recorded settings snapshot; resume it to record one")
			}
			data, err := json.Marshal(p["settings"])
			if err != nil {
				return nil, errors.New("recorded settings cannot be displayed")
			}
			if err := config.ScreenSettings(data); err != nil {
				return nil, err
			}
			s, err := settings.Decode(p["settings"])
			if err != nil {
				return nil, err
			}
			seq, _ := settings.Number(event["seq"])
			run, _ := settings.Number(p["run"])
			*external = eventstore.ExternallyAppended(event)
			return settings.EventSource(s, int(seq), int(run)), nil
		}
		return nil, errors.New("lane has no recorded start")
	}
	c, err := config.Load(o.config)
	if err != nil {
		return nil, err
	}
	root, err := rolepolicy.ConfigRoot(c.Home, c.Data)
	if err != nil {
		return nil, err
	}
	level, role := 0, ""
	if o.instance != "" {
		level, role, err = settings.Instance(root, o.instance, config.ScreenSettings)
		if err != nil {
			return nil, err
		}
	}
	return settings.Resolve(root, level, role, o.instance, map[string]any{}, config.ScreenSettings)
}

func Run(args []string, _ io.Reader, stdout, stderr io.Writer) int {
	o, err := parse(args)
	if o.help {
		fmt.Fprintln(stdout, usage)
		return 0
	}
	var snapshot *settings.Snapshot
	external := false
	if err == nil {
		snapshot, err = resolve(o, &external)
	}
	if err != nil {
		var cfg *config.Error
		if errors.As(err, &cfg) {
			fmt.Fprintln(stderr, cfg.Prefix+": "+cfg.Message)
			return cfg.Code
		}
		var store *eventstore.Problem
		if errors.As(err, &store) {
			return eventstore.Failure(err, stderr)
		}
		fmt.Fprintln(stderr, "refused: "+err.Error())
		return 2
	}
	var output any
	if o.action == "get" {
		output = snapshot.Values[o.key]
		if o.explain {
			entry, exists := snapshot.Entries[o.key]
			if !exists {
				output = map[string]any{"key": o.key, "value": nil, "layers": []any{}, "winner": nil}
			} else {
				output = explanation(entry)
				output.(map[string]any)["key"] = o.key
			}
		}
	} else {
		values := map[string]any{}
		for _, key := range settings.Keys {
			values[key] = snapshot.Values[key]
			if o.explain {
				if entry, exists := snapshot.Entries[key]; exists {
					values[key] = explanation(entry)
				} else {
					values[key] = map[string]any{"value": nil, "layers": []any{}, "winner": nil}
				}
			}
		}
		output = values
	}
	if external {
		// A scalar get needs an envelope to carry the observation's origin.
		if o.action == "get" && !o.explain {
			output = map[string]any{"value": output}
		}
		output.(map[string]any)["externally_appended"] = true
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(output); err != nil {
		fmt.Fprintln(stderr, "cannot write settings output")
		return 1
	}
	return 0
}
