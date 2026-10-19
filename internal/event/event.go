// Package event implements `laneboss event`, ported from the Python launcher (tag python-final).
package event

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/eventstore"
	"laneboss.io/laneboss/internal/report"
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
	// Caller resolution reads the same store, but reports identity failures.
	// Check this command's complete isolation scope and typed integrity errors
	// first, before an unreadable store can be mistaken for an unknown caller.
	if err = checkReadableState(c); err != nil {
		return eventstore.Failure(err, stderr)
	}
	principal, err := report.Resolve(c.Name)
	if err != nil {
		var problem *eventstore.Problem
		if errors.As(err, &problem) {
			return eventstore.Failure(err, stderr)
		}
		return eventstore.Failure(eventstore.Refuse("%s\nInstead: report up with laneboss report.", err.Error()), stderr)
	}
	if o.Action == "tail" {
		err = tail(c, o, principal, stdout)
	} else {
		err = appendEvent(c, o, principal, stdin, stdout)
	}
	if err != nil {
		return eventstore.Failure(err, stderr)
	}
	return 0
}

func checkReadableState(c *eventstore.Configuration) error {
	d, err := c.OpenDirectory(false)
	if err != nil || d == nil {
		return err
	}
	defer d.Close()
	s, err := eventstore.Open(d, false)
	if err != nil || s == nil {
		return err
	}
	defer s.Close()
	_, err = s.Events(0)
	return err
}

func authorizeEvent(value any, principal caller.Principal) error {
	if err := caller.RequireIdentity(principal); err != nil {
		return eventstore.Refuse("%s", err)
	}
	event, ok := value.(map[string]any)
	if !ok {
		return eventstore.Refuse("an event must be a JSON object")
	}
	kind, _ := event["kind"].(string)
	if kind == "lane.mailed" || strings.HasPrefix(kind, "report.") || strings.HasPrefix(kind, "owner.message.") {
		return eventstore.Refuse("event append may not append lane.mailed, report.* or owner.message.*\nInstead: use lane send for an allowed recipient, or report up with laneboss report.")
	}
	actor, _ := event["actor"].(string)
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(actor)), "human") {
		return eventstore.Refuse("human actors are reserved for authenticated human message paths\nInstead: let the launcher resolve your identity with lane send or laneboss report.")
	}
	if strings.HasPrefix(principal.ID, "lane:") && !eventstore.LifecycleKind(kind) {
		if event["lane"] != strings.TrimPrefix(principal.ID, "lane:") {
			return eventstore.Refuse("a lane may append events only for itself\nInstead: report up with laneboss report.")
		}
		event["actor"] = principal.ID
	}
	return nil
}

// Run resolves this principal against the selected configuration. A lane's
// level never grants the supervisor permission, even if it executes at L6.
func authorizeLifecycle(c *eventstore.Configuration, e eventstore.Object, principal caller.Principal) error {
	kind, _ := e["kind"].(string)
	if !eventstore.LifecycleKind(kind) {
		return nil
	}
	role := strings.HasPrefix(principal.ID, "supervisor:") || strings.HasPrefix(principal.ID, "instance:")
	if principal.ID != "human" && !(role && principal.Level >= 4 && principal.Level <= 6) {
		return eventstore.Refuse("lifecycle append requires the human or a configured L4-L6 supervisor\nInstead: report up with laneboss report.")
	}
	advance := kind == "lane.started" || kind == "lane.resumed" || kind == "lane.adopted"
	closing := kind == "lane.ended" || kind == "lane.lost" || kind == "lane.gone"
	if advance || closing {
		all, err := caller.Lanes(caller.Configuration(c.Name, c.Home, c.StateHome, c.Directory, c.StatePath, nil))
		if err != nil {
			return err
		}
		lane, _ := e["lane"].(string)
		if _, launched := all[lane]; launched {
			if closing {
				return eventstore.Refuse("event append may not end a launcher-recorded lane's run\nInstead: use lane stop, or lane check when its supervising process is gone.")
			}
			return eventstore.Refuse("event append may not advance a launcher-recorded lane's run\nInstead: use lane start, resume or turn.")
		}
	}
	return nil
}

func visibleEvent(event eventstore.Object, principal caller.Principal) bool {
	if !strings.HasPrefix(principal.ID, "lane:") {
		return true
	}
	if event["lane"] == strings.TrimPrefix(principal.ID, "lane:") {
		return true
	}
	payload, _ := event["payload"].(map[string]any)
	return payload["to"] == principal.ID
}

func appendEvent(c *eventstore.Configuration, o eventstore.Options, principal caller.Principal, stdin io.Reader, stdout io.Writer) error {
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
	if err = authorizeEvent(value, principal); err != nil {
		return err
	}
	e, err := eventstore.ValidateCLI(value)
	if err != nil {
		return err
	}
	// Payload and replay-scope diagnostics precede the lifecycle access gate.
	// This preflight writes no state, including for a refused lane caller.
	if err = c.CheckExternalBinding(e); err != nil {
		return err
	}
	if err = authorizeLifecycle(c, e, principal); err != nil {
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
	result, err := s.AppendExternal(e, principal.ID)
	if err != nil {
		return err
	}
	return eventstore.Output(result, stdout)
}
func tail(c *eventstore.Configuration, o eventstore.Options, principal caller.Principal, stdout io.Writer) error {
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
			if !visibleEvent(e, principal) {
				continue
			}
			if o.Lane != "" && e["lane"] != o.Lane {
				continue
			}
			display := eventstore.Object{}
			for key, value := range e {
				display[key] = value
			}
			display["externally_appended"] = eventstore.ExternallyAppended(e)
			if err = eventstore.Output(display, stdout); err != nil {
				return err
			}
			if o.Until != "" && e["kind"] == o.Until && !eventstore.ExternallyAppended(e) {
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
