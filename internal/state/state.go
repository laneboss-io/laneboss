// Package state implements `laneboss state`, ported from the Python launcher (tag python-final).
package state

import (
	"fmt"
	"io"

	"laneboss.io/laneboss/internal/eventstore"
)

// Run executes `laneboss state ARGS...` and returns the process exit code.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) (code int) {
	defer func() {
		if recover() != nil {
			fmt.Fprintln(stderr, "internal error: unexpected failure")
			code = 70
		}
	}()
	o, err := eventstore.ParseOptions("state", args)
	if err != nil {
		return eventstore.Failure(err, stderr)
	}
	if o.Help {
		fmt.Fprintln(stdout, "usage: laneboss state {events,lanes,rebuild,verify} [--config NAME]")
		return 0
	}
	c, err := eventstore.Bind(o.Config)
	if err != nil {
		return eventstore.Failure(err, stderr)
	}
	d, err := c.OpenDirectory(false)
	if err != nil {
		return eventstore.Failure(err, stderr)
	}
	if d != nil {
		defer d.Close()
	}
	s, err := eventstore.Open(d, false)
	if err != nil {
		return eventstore.Failure(err, stderr)
	}
	if s != nil {
		defer s.Close()
	}
	var result any
	if s == nil {
		result = []any{}
		if o.Action == "verify" {
			result, err = eventstore.VerifyEmpty(c, d)
		}
	} else {
		switch o.Action {
		case "events":
			result, err = s.Events(0)
		case "lanes":
			result, err = s.Lanes()
		case "rebuild":
			result, err = s.Rebuild()
		case "verify":
			result, err = s.Verify()
		}
	}
	if err != nil {
		return eventstore.Failure(err, stderr)
	}
	if err = eventstore.Output(result, stdout); err != nil {
		return eventstore.Failure(err, stderr)
	}
	return 0
}
