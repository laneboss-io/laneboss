package boxrun

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"laneboss.io/laneboss/internal/boxcore"
)

type service struct {
	d boxcore.Deps
}

// New constructs a provider-neutral orchestrator. Nil clock and stream fields
// use the system clock and standard streams; other dependencies are required.
func New(d boxcore.Deps) boxcore.Service {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Sleep == nil {
		d.Sleep = sleep
	}
	if d.Out == nil {
		d.Out = os.Stdout
	}
	if d.Err == nil {
		d.Err = os.Stderr
	}
	return &service{d: d}
}

func sleep(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (s *service) provider(name string) (boxcore.Provider, error) {
	p := s.d.Providers[name]
	if p == nil {
		return nil, fmt.Errorf("boxrun: unknown provider %q", name)
	}
	return p, nil
}

func (s *service) configured() error {
	if s.d.Config == nil || s.d.Ledger == nil {
		return errors.New("boxrun: config and ledger are required")
	}
	return nil
}

func (s *service) request(req boxcore.Request) (boxcore.Request, error) {
	if err := s.configured(); err != nil {
		return req, err
	}
	if _, err := s.provider(req.Provider); err != nil {
		return req, err
	}
	if req.RunID == "" {
		if s.d.NewRunID != nil {
			req.RunID = s.d.NewRunID()
		} else {
			id, err := boxcore.NewRunID(s.d.Now(), rand.Reader)
			if err != nil {
				return req, err
			}
			req.RunID = id
		}
	}
	if req.Lane == "" {
		req.Lane = req.Purpose
	}
	if req.Owner == "" {
		req.Owner, req.OwnerBasis = "unknown", "unknown"
	}
	for _, name := range []string{req.Purpose, req.Lane, req.Owner, req.RunID} {
		if !boxcore.PlainName(name) {
			return req, fmt.Errorf("boxrun: invalid plain name %q", name)
		}
	}
	if req.HardMin < boxcore.MinHardMin || req.IdleMin <= 0 || req.RootGB < 0 {
		return req, errors.New("boxrun: invalid duration or root disk size")
	}
	if s.d.Guest == nil {
		return req, errors.New("boxrun: guest renderer is required")
	}
	return req, validateGuest(s.d.Config.Guest)
}

func (s *service) note(format string, args ...any) {
	// Diagnostics cannot replace the operation's original error.
	if _, err := fmt.Fprintf(s.d.Err, format+"\n", args...); err != nil {
		fmt.Fprintf(os.Stderr, "boxrun: diagnostic write failed: %v\n", err)
	}
}

func terminal(name string) bool {
	return name == boxcore.StateTerminated || name == boxcore.StateGone
}

func taken(name string) bool {
	return terminal(name) || name == boxcore.StateStopping || name == boxcore.StateStopped
}

func text(fields map[string]any, key string) string {
	value, _ := fields[key].(string)
	return value
}

func number(fields map[string]any, key string) float64 {
	switch value := fields[key].(type) {
	case float64:
		return value
	case int:
		return float64(value)
	case int64:
		return float64(value)
	default:
		return 0
	}
}

func launchEvent(events []map[string]any, provider, id string) map[string]any {
	var found map[string]any
	for _, event := range events {
		// A line with no provider field was written by the older AWS-only tool.
		recorded := text(event, "provider")
		if recorded == "" {
			recorded = "aws"
		}
		if text(event, "event") == "LAUNCHED" && text(event, "instance_id") == id &&
			(provider == "" || recorded == provider) {
			found = event
		}
	}
	return found
}

func execBound(ctx context.Context, tr boxcore.Transport, command string,
	input io.Reader, output, stderr io.Writer, bound time.Duration) (int, error) {
	if tr == nil {
		return -1, boxcore.NewError(boxcore.KindTransport, "exec", "", "no transport", nil)
	}
	callCtx, cancel := context.WithTimeout(ctx, bound)
	defer cancel()
	return tr.Exec(callCtx, command, input, output, stderr)
}

func catchPanic(op string, target *error) {
	if recovered := recover(); recovered != nil {
		*target = fmt.Errorf("boxrun: %s panic: %v", op, recovered)
	}
}

func (s *service) appendEvent(event string, fields map[string]any) (row map[string]any, err error) {
	defer catchPanic("ledger append", &err)
	return s.d.Ledger.Append(event, fields)
}

func (s *service) events() (events []map[string]any, err error) {
	defer catchPanic("ledger read", &err)
	return s.d.Ledger.Events()
}

func (s *service) writable() (err error) {
	defer catchPanic("ledger preflight", &err)
	return s.d.Ledger.Writable()
}

func describeBound(ctx context.Context, p boxcore.Provider, b boxcore.Box) (state boxcore.State, err error) {
	defer catchPanic("describe", &err)
	callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return p.Describe(callCtx, b)
}

func teardownBound(ctx context.Context, p boxcore.Provider, b boxcore.Box) (err error) {
	defer catchPanic("teardown", &err)
	callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return p.Teardown(callCtx, b)
}
