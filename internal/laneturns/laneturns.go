// Package laneturns implements the turn-based lane commands without a Python runtime.
package laneturns

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"laneboss.io/laneboss/internal/cliargs"
)

type problem struct {
	code            int
	prefix, message string
}
type busyStoreError struct{ problem *problem }

func (e *busyStoreError) Error() string { return e.problem.Error() }
func (e *busyStoreError) Unwrap() error { return e.problem }
func isExpectedError(err error) bool {
	var p *problem
	return errors.As(err, &p) || errors.Is(err, os.ErrNotExist)
}

type unsupportedEventError struct{ problem *problem }

func (e *unsupportedEventError) Error() string { return e.problem.Error() }
func (e *unsupportedEventError) Unwrap() error { return e.problem }

func (p *problem) Error() string { return p.message }
func refused(format string, args ...any) error {
	return &problem{2, "refused", fmt.Sprintf(format, args...)}
}
func integrity(format string, args ...any) error {
	return &problem{3, "integrity problem", fmt.Sprintf(format, args...)}
}
func invalid(format string, args ...any) error {
	return &problem{2, "invalid configuration", fmt.Sprintf(format, args...)}
}

type arguments struct {
	action string
	values map[string]string
	flags  map[string]bool
	source *string
}

func (a arguments) get(name string) string { return a.values[name] }
func (a arguments) optional(name string) any {
	if value, ok := a.values[name]; ok {
		return value
	}
	return nil
}

var options = map[string]string{
	"adopt": "config lane project session runner model effort account worktree brief budget idle",
	"turn":  "config lane budget account", "send": "config lane file from", "attach": "config lane", "loop": "config",
}

func parseArgs(args []string) (arguments, error) {
	a := arguments{values: map[string]string{}, flags: map[string]bool{}}
	loopFlag := ""
	if len(args) == 0 {
		return a, refused("%s", cliargs.Required("ACTION"))
	}
	a.action = args[0]
	allowed, ok := options[a.action]
	if !ok {
		return a, refused("%s", cliargs.Reject("ACTION"))
	}
	for i := 1; i < len(args); i++ {
		value := args[i]
		if value == "--help" || value == "-h" {
			a.flags["help"] = true
			continue
		}
		if strings.HasPrefix(value, "--") {
			name, inline, hasInline := strings.Cut(value[2:], "=")
			boolean := a.action == "turn" && name == "idle" || a.action == "loop" && (name == "detach" || name == "status" || name == "stop")
			if boolean {
				if hasInline {
					return a, refused("%s", cliargs.Reject("--"+name))
				}
				if a.action == "loop" {
					if loopFlag != "" && loopFlag != name {
						return a, refused("%s", cliargs.Conflict("--"+name, "--"+loopFlag))
					}
					loopFlag = name
				}
				a.flags[name] = true
				continue
			}
			if !strings.Contains(" "+allowed+" ", " "+name+" ") {
				return a, refused("%s", cliargs.Reject(""))
			}
			if !hasInline {
				i++
				if i == len(args) || strings.HasPrefix(args[i], "--") {
					return a, refused("%s", cliargs.Expected("--"+name))
				}
				inline = args[i]
			}
			a.values[name] = inline
		} else {
			if a.action != "send" || a.source != nil {
				return a, refused("%s", cliargs.Reject(""))
			}
			copy := value
			a.source = &copy
		}
	}
	if a.flags["help"] {
		return a, nil
	}
	if a.action != "loop" {
		if _, supplied := a.values["lane"]; !supplied {
			return a, refused("%s", cliargs.Required("--lane"))
		}
	}
	if a.action == "loop" {
		n := 0
		for _, key := range []string{"status", "stop", "detach"} {
			if a.flags[key] {
				n++
			}
		}
		if n > 1 {
			return a, refused("--detach, --status and --stop are not allowed with one another")
		}
	} else if !lanePattern.MatchString(a.get("lane")) {
		return a, refused("--lane: must match [a-z0-9][a-z0-9._-]{0,63}")
	}
	if a.action == "adopt" {
		for _, key := range []string{"session", "runner", "model", "worktree", "brief"} {
			if _, ok := a.values[key]; !ok {
				return a, refused("%s", cliargs.Required("--"+key))
			}
		}
	}
	return a, nil
}

// Run executes lane adopt, turn, send, attach or loop and returns the launcher exit code.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	// Keep helper launches under public actions so a shared command dispatcher
	// need only route the actions this package owns.
	if len(args) == 2 && args[0] == "turn" && args[1] == "__turn_scan" {
		return scanWorker(stdin, stdout, stderr)
	}
	if len(args) == 3 && (args[0] == "turn" && args[1] == "__turn_supervise" || args[0] == "loop" && args[1] == "__turn_loop") {
		return worker(args[1], args[2], stdout, stderr)
	}
	if len(args) == 1 && args[0] == "__turn_scan" {
		return scanWorker(stdin, stdout, stderr)
	}
	if len(args) == 2 && (args[0] == "__turn_supervise" || args[0] == "__turn_loop") {
		return worker(args[0], args[1], stdout, stderr)
	}
	a, err := parseArgs(args)
	if err == nil && a.flags["help"] {
		fmt.Fprintf(stdout, "usage: laneboss lane %s [--config NAME]", a.action)
		for _, key := range strings.Fields(options[a.action]) {
			if key != "config" {
				fmt.Fprintf(stdout, " [--%s VALUE]", key)
			}
		}
		if a.action == "send" {
			fmt.Fprint(stdout, " [-]")
		}
		if a.action == "turn" {
			fmt.Fprint(stdout, " [--idle]")
		}
		if a.action == "loop" {
			fmt.Fprint(stdout, " [--detach | --status | --stop]")
		}
		fmt.Fprintln(stdout)
		return 0
	}
	var c *configuration
	if err == nil {
		c, err = loadConfig(a.get("config"))
	}
	if err == nil {
		var result any
		switch a.action {
		case "send":
			result, err = sendCommand(c, a, stdin)
		case "adopt":
			result, err = adopt(c, a)
		case "turn":
			result, err = turn(c, a, nil, nil)
		case "attach":
			return runAttach(c, a, stdin, stdout, stderr)
		case "loop":
			return runLoop(c, a, stdout, stderr)
		}
		if err == nil {
			if result != nil {
				err = printJSON(stdout, result)
			}
			if err == nil {
				return 0
			}
		}
	}
	return reportError(stderr, err)
}

func reportError(w io.Writer, err error) int {
	if err == nil {
		return 0
	}
	var p *problem
	if errors.As(err, &p) {
		fmt.Fprintf(w, "%s: %s\n", p.prefix, p.message)
		return p.code
	}
	if errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(w, "refused: a file or directory disappeared; nothing more was done")
		return 2
	}
	// Raw operating-system and decoder errors can embed input values.
	fmt.Fprintln(w, "internal error: the lane command could not complete; its inputs were not printed")
	return 70
}
