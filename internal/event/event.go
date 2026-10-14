// Package event implements `laneboss event`, ported from the Python launcher (tag python-final).
package event

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"laneboss.io/laneboss/internal/eventstore"
)

// Run executes `laneboss event ARGS...` and returns the process exit code.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) (code int) {
	defer func() {
		if recover() != nil {
			fmt.Fprintln(stderr, "internal error: unexpected failure")
			code = 70
		}
	}()
	o, err := eventstore.ParseOptions("event", args)
	if err != nil {
		return eventstore.Failure(err, stderr)
	}
	if o.Help {
		fmt.Fprintln(stdout, "usage: laneboss event append --config NAME --file FILE\n       laneboss event tail --config NAME [--since SEQ] [--lane LANE] [--follow] [--until KIND]")
		return 0
	}
	c, err := eventstore.Bind(o.Config)
	if err != nil {
		return eventstore.Failure(err, stderr)
	}
	if o.Action == "tail" {
		err = tail(c, o, stdout)
	} else {
		err = appendEvent(c, o, stdin, stdout)
	}
	if err != nil {
		return eventstore.Failure(err, stderr)
	}
	return 0
}

func appendEvent(c *eventstore.Configuration, o eventstore.Options, stdin io.Reader, stdout io.Writer) error {
	var data []byte
	var err error
	if o.File == "-" {
		data, err = io.ReadAll(io.LimitReader(stdin, 2*1024*1024+1))
		if err != nil {
			return eventstore.Refuse("the event cannot be read")
		}
		if len(data) > 2*1024*1024 {
			return eventstore.Refuse("the event is larger than 2 MiB")
		}
	} else {
		data, err = c.ReadExternal(o.File, 2*1024*1024)
		if err != nil {
			return err
		}
	}
	value, err := eventstore.Parse(data, "the event")
	if err != nil {
		return err
	}
	e, err := eventstore.Validate(value)
	if err != nil {
		return err
	}
	d, err := c.OpenDirectory(false)
	if err != nil {
		return err
	}
	if e["kind"] == "brief.rendered" {
		if err = eventstore.CheckRendered(e, d); err != nil {
			if d != nil {
				d.Close()
			}
			return err
		}
	}
	if d == nil {
		d, err = c.OpenDirectory(true)
		if err != nil {
			return err
		}
	}
	defer d.Close()
	s, err := eventstore.Open(d, true)
	if err != nil {
		return err
	}
	defer s.Close()
	result, err := s.Append(e)
	if err != nil {
		return err
	}
	return eventstore.Output(result, stdout)
}
func tail(c *eventstore.Configuration, o eventstore.Options, stdout io.Writer) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	last := o.Since
	for {
		d, err := c.OpenDirectory(false)
		if err != nil {
			return err
		}
		var s *eventstore.Store
		if d != nil {
			s, err = eventstore.Open(d, false)
			if err != nil {
				d.Close()
				return err
			}
		}
		items := []eventstore.Object{}
		if s != nil {
			items, err = s.Events(last)
			s.Close()
		}
		if d != nil {
			d.Close()
		}
		if err != nil {
			return err
		}
		for _, e := range items {
			last = e["seq"].(int64)
			if o.Lane != "" && e["lane"] != o.Lane {
				continue
			}
			if err = eventstore.Output(e, stdout); err != nil {
				return err
			}
			if o.Until != "" && e["kind"] == o.Until {
				return nil
			}
		}
		if !o.Follow {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(200 * time.Millisecond):
		}
	}
}
