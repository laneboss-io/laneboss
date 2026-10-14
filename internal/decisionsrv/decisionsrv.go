// Package decisionsrv implements resident search, ingestion and org history in Go.
package decisionsrv

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"laneboss.io/laneboss/internal/cliargs"
	decisionargs "laneboss.io/laneboss/internal/decisions/argparse"
	"laneboss.io/laneboss/internal/decisions/jsonout"
)

type options map[string][]string

func (o options) get(key string) string {
	v := o[key]
	if len(v) == 0 {
		return ""
	}
	return v[len(v)-1]
}

func parseOptions(args []string, allowed, repeated string) (options, error) {
	return parseChoiceOptions(args, allowed, repeated, map[string][]string{"kind": {"ledger", "report", "board", "bulletin"}})
}

func parseChoiceOptions(args []string, allowed, repeated string, choices map[string][]string) (options, error) {
	o := options{}
	extra := []string{}
	allowedNames, appendNames := wordsSet(allowed), wordsSet(repeated)
	for i := 0; i < len(args); i++ {
		if args[i] == "--help" || args[i] == "-h" {
			o["_help"] = []string{"true"}
			return o, nil
		}
		if !strings.HasPrefix(args[i], "--") {
			extra = append(extra, args[i])
			continue
		}
		key, value, equals := strings.Cut(strings.TrimPrefix(args[i], "--"), "=")
		if !allowedNames[key] {
			extra = append(extra, args[i])
			continue
		}
		if !equals {
			i++
			if i >= len(args) || decisionargs.IsOption(args[i]) {
				return nil, invalid(decisionargs.Expected("--" + key))
			}
			value = args[i]
		}
		if values, constrained := choices[key]; constrained && !wordsSet(strings.Join(values, " "))[value] {
			return nil, invalid(decisionargs.Choice("--"+key, value, values))
		}
		if key == "idle-exit" {
			n, err := strconv.ParseFloat(value, 64)
			if err != nil || !finite(n) || n <= 0 {
				return nil, invalid("argument --idle-exit: must be a positive number of minutes")
			}
		}
		// argparse's store action uses the last value; append actions retain all.
		if !appendNames[key] {
			o[key] = nil
		}
		o[key] = append(o[key], value)
	}
	if len(extra) > 0 {
		return nil, invalid(decisionargs.Unrecognized(extra...))
	}
	return o, nil
}

func requireOptions(o options, keys ...string) error {
	missing := []string{}
	for _, key := range keys {
		if len(o[key]) == 0 {
			missing = append(missing, "--"+key)
		}
	}
	if len(missing) > 0 {
		return invalid(decisionargs.Required(missing...))
	}
	return nil
}

// Only the org actions delegated through this package belong to the launcher's
// ScreeningParser. Standalone decisions arguments retain argparse's wording.
func screenParserError(err error) error {
	if err == nil {
		return nil
	}
	if p, ok := err.(*commandError); ok && p.code == 2 {
		return invalid(cliargs.Screen(strings.TrimPrefix(p.message, "invalid input: ")))
	}
	return err
}

func parseLauncherOptions(args []string, allowed, repeated string) (options, error) {
	o, err := parseChoiceOptions(args, allowed, repeated, map[string][]string{
		"runner": {"claude", "codex"}, "event": {"SessionStart", "UserPromptSubmit"},
		"author-authority": {"decide", "inform"},
	})
	return o, screenParserError(err)
}

func printUsage(stdout io.Writer, action string) int {
	if action == "capture-decision" {
		fmt.Fprintln(stdout, "usage: laneboss org capture-decision --org-dir DIR --source SOURCE --text-file FILE --author-authority {decide,inform} [--config NAME] [--instance INSTANCE] [--judge JUDGE] [--at TIME]")
		return 0
	}
	if action == "hook-history" {
		fmt.Fprintln(stdout, "usage: laneboss org hook-history --runner {claude,codex} [--org-dir DIR] [--instance INSTANCE] [--event {SessionStart,UserPromptSubmit}]")
		return 0
	}
	fmt.Fprintf(stdout, "laneboss decisions %s --db FILE", action)
	if action == "serve" {
		fmt.Fprint(stdout, " --socket PATH [--config FILE] [--idle-exit MINUTES] (default 60)")
	}
	fmt.Fprintln(stdout)
	return 0
}

type commandError struct {
	code    int
	message string
}

func (e *commandError) Error() string { return e.message }
func invalid(s string) error          { return &commandError{2, "invalid input: " + s} }
func integrity(s string) error        { return &commandError{3, "integrity problem: " + s} }
func providerFailure(s string) error  { return &commandError{4, "provider failed: " + s} }
func errorCode(err error) int {
	if e, ok := err.(*commandError); ok {
		return e.code
	}
	return 3
}

func idleMinutes(o options) (float64, error) {
	minutes := 60.0
	if len(o["idle-exit"]) > 0 {
		value, err := strconv.ParseFloat(o.get("idle-exit"), 64)
		if err != nil || !finite(value) || value <= 0 {
			return 0, invalid("--idle-exit must be a positive number of minutes")
		}
		minutes = value
	}
	return minutes, nil
}

// Run also exposes history actions for delegation from the org command group.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "invalid input: "+decisionargs.Required("command"))
		return 2
	}
	action := args[0]
	if code, handled := TryProbe(args, stdin, stdout, stderr); handled {
		return code
	}
	if action == "hook-history" {
		return hookHistory(args[1:], stdin, stdout)
	}
	if action == "history-worker" {
		return historyWorker(stdin, stdout)
	}
	if len(args) == 2 && (args[1] == "--help" || args[1] == "-h") {
		return printUsage(stdout, action)
	}
	allowed := "db"
	switch action {
	case "serve":
		allowed += " socket config idle-exit"
	case "ingest-records":
		allowed += " org-dir instance file kind"
	case "ingest-lane":
		allowed += " org-dir instance config lane attach"
	case "capture-decision":
		allowed = "org-dir instance config judge text-file source at author-authority"
	default:
		fmt.Fprintln(stderr, "invalid input: unsupported resident action")
		return 2
	}
	var o options
	var err error
	if action == "capture-decision" {
		o, err = parseLauncherOptions(args[1:], allowed, "attach")
	} else {
		o, err = parseOptions(args[1:], allowed, "attach")
	}
	if err == nil && len(o["_help"]) > 0 {
		return printUsage(stdout, action)
	}
	if err == nil {
		required := map[string][]string{"serve": {"db", "socket"}, "ingest-records": {"db", "org-dir", "instance", "file"}, "ingest-lane": {"db", "config", "lane"}}
		if action != "capture-decision" {
			err = requireOptions(o, required[action]...)
		}
	}
	var result any
	if err == nil {
		switch action {
		case "serve":
			err = requireOptions(o, "socket")
			minutes := 0.0
			if err == nil {
				minutes, err = idleMinutes(o)
			}
			if err == nil {
				err = serve(o.get("db"), o.get("socket"), o.get("config"), minutes, stdout, stderr)
			}
		case "ingest-records":
			err = requireOptions(o, "org-dir", "instance", "file")
			if err == nil {
				result, err = ingestRecords(o)
			}
		case "ingest-lane":
			err = requireOptions(o, "config", "lane")
			if err == nil {
				result, err = ingestLane(o)
			}
		case "capture-decision":
			err = screenParserError(requireOptions(o, "org-dir", "source", "text-file", "author-authority"))
			if err == nil {
				result, err = captureDecision(o)
			}
		}
	}
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return errorCode(err)
	}
	if result != nil {
		body, err := jsonout.Line(result)
		if err != nil {
			err = invalid(err.Error())
			fmt.Fprintln(stderr, err.Error())
			return errorCode(err)
		}
		if _, err = stdout.Write(body); err != nil {
			fmt.Fprintln(stderr, "invalid input: cannot write result")
			return 2
		}
	}
	return 0
}
