// Package decisionsrv implements resident search, ingestion and org history in Go.
package decisionsrv

import (
	"fmt"
	"io"
	"strconv"
	"strings"

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
	o := options{}
	for i := 0; i < len(args); i++ {
		if !strings.HasPrefix(args[i], "--") {
			return nil, invalid("unrecognized argument")
		}
		key, value, equals := strings.Cut(strings.TrimPrefix(args[i], "--"), "=")
		if !strings.Contains(" "+allowed+" ", " "+key+" ") {
			return nil, invalid("unrecognized argument: --" + key)
		}
		if !equals {
			i++
			if i >= len(args) {
				return nil, invalid("argument --" + key + " requires a value")
			}
			value = args[i]
		}
		if len(o[key]) > 0 && !strings.Contains(" "+repeated+" ", " "+key+" ") {
			return nil, invalid("argument given twice: --" + key)
		}
		o[key] = append(o[key], value)
	}
	return o, nil
}

func requireOptions(o options, keys ...string) error {
	for _, key := range keys {
		if o.get(key) == "" {
			return invalid("argument --" + key + " is required")
		}
	}
	return nil
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
		fmt.Fprintln(stderr, "invalid input: an action is required")
		return 2
	}
	action := args[0]
	if action == "probe" {
		if len(args) > 1 {
			o, err := parseOptions(args[1:], "file", "")
			if err == nil {
				err = requireOptions(o, "file")
			}
			if err != nil {
				fmt.Fprintln(stderr, err.Error())
				return errorCode(err)
			}
			text, err := readRegular(o.get("file"), maxTextBytes)
			if err != nil {
				fmt.Fprintln(stderr, err.Error())
				return errorCode(err)
			}
			stdin = strings.NewReader(text)
		}
		return Probe(stdin, stdout, stderr)
	}
	if action == "hook-history" {
		return hookHistory(args[1:], stdin, stdout)
	}
	if action == "history-worker" {
		return historyWorker(stdin, stdout)
	}
	if len(args) == 2 && (args[1] == "--help" || args[1] == "-h") {
		fmt.Fprintf(stdout, "laneboss decisions %s --db FILE", action)
		if action == "serve" {
			fmt.Fprint(stdout, " --socket PATH [--config FILE] [--idle-exit MINUTES] (default 60)")
		}
		fmt.Fprintln(stdout)
		return 0
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
	o, err := parseOptions(args[1:], allowed, "attach")
	if err == nil && action != "capture-decision" {
		err = requireOptions(o, "db")
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
			err = requireOptions(o, "text-file", "source", "author-authority")
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
