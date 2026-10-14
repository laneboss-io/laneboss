package eventstore

import (
	"strconv"
	"strings"

	"laneboss.io/laneboss/internal/cliargs"
)

type Options struct {
	Action, Config, File, Lane, Until string
	Since                             int64
	Follow, Help                      bool
}

// The parser reports only argument labels; typed values are never echoed.
func ParseOptions(group string, args []string) (Options, error) {
	o := Options{}
	if len(args) == 0 {
		return o, Refuse("%s", cliargs.Required("ACTION"))
	}
	if args[0] == "--help" || args[0] == "-h" {
		o.Help = true
		return o, nil
	}
	o.Action = args[0]
	actions := []string{"append", "tail"}
	if group == "state" {
		actions = []string{"events", "lanes", "rebuild", "verify"}
	}
	if !contains(actions, o.Action) {
		return o, Refuse("%s", cliargs.Reject("ACTION"))
	}
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if arg == "--help" || arg == "-h" {
			o.Help = true
			continue
		}
		name, value, inline := strings.Cut(arg, "=")
		if name == "--follow" && group == "event" && o.Action == "tail" {
			if inline {
				return o, Refuse("%s", cliargs.Reject("--follow"))
			}
			o.Follow = true
			continue
		}
		allowed := name == "--config" || group == "event" && (o.Action == "append" && name == "--file" || o.Action == "tail" && contains([]string{"--since", "--lane", "--until"}, name))
		if !allowed {
			return o, Refuse("%s", cliargs.Reject(""))
		}
		if !inline {
			i++
			if i >= len(args) {
				return o, Refuse("%s", cliargs.Expected(name))
			}
			value = args[i]
			if strings.HasPrefix(value, "--") {
				return o, Refuse("%s", cliargs.Expected(name))
			}
		}
		switch name {
		case "--config":
			if value == "" {
				return o, Refuse("the configuration name must match [a-z0-9][a-z0-9-]{0,31}")
			}
			o.Config = value
		case "--file":
			o.File = value
		case "--lane":
			if value == "" {
				return o, Refuse("--lane: must match [a-z0-9][a-z0-9._-]{0,63}")
			}
			o.Lane = value
		case "--until":
			if value == "" {
				return o, Refuse("--until: must be an event kind")
			}
			o.Until = value
		case "--since":
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil || n < 0 {
				return o, Refuse("%s", cliargs.Reject("--since"))
			}
			o.Since = n
		}
	}
	if o.Help {
		return o, nil
	}
	if group == "event" && o.Action == "append" && o.File == "" {
		return o, Refuse("%s", cliargs.Required("--file"))
	}
	if o.Lane != "" {
		if err := envelopeGrammar(o.Lane, laneGrammar, "--lane", false); err != nil {
			return o, err
		}
	}
	if o.Until != "" {
		if err := envelopeGrammar(o.Until, kindGrammar, "--until", false); err != nil {
			return o, err
		}
	}
	return o, nil
}
