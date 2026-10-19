package boxexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
)

// Call is one recorded run.
type Call struct {
	Name  string
	Args  []string
	Env   []string
	Dir   string
	Stdin string // the whole stdin, read before the handler runs
}

// Handler answers the calls it matches.
type Handler struct {
	Name        string   // "" matches any program name
	ArgsContain []string // every string must be a substring of the arguments joined by single spaces
	// Respond builds the answer. n counts the earlier calls that matched THIS handler (0 for the first).
	// nil Respond answers Result{} (exit 0, no output).
	Respond func(c Cmd, n int) (Result, error)
}

// Fake is a Runner that replays Handlers. The first handler, in order, that matches answers. It is safe for concurrent use.
// Configure Handlers before running calls, and read Calls after the runs finish.
type Fake struct {
	Handlers []Handler
	Calls    []Call // appended under the fake's own lock; read after the run

	mu     sync.Mutex
	counts map[int]int
}

// Run records the input before choosing a handler and forwards answer streams.
func (f *Fake) Run(ctx context.Context, c Cmd) (Result, error) {
	var input []byte
	var readErr error
	if c.Stdin != nil {
		input, readErr = io.ReadAll(c.Stdin)
	}
	call := Call{
		Name: c.Name, Args: slices.Clone(c.Args), Env: slices.Clone(c.Env),
		Dir: c.Dir, Stdin: string(input),
	}
	f.mu.Lock()
	f.Calls = append(f.Calls, call)
	if readErr != nil || ctx.Err() != nil {
		f.mu.Unlock()
		return Result{Code: -1}, errors.Join(readErr, ctx.Err())
	}
	var chosen Handler
	found := false
	n := 0
	for i, handler := range f.Handlers {
		if !matches(call, handler.Name, handler.ArgsContain) {
			continue
		}
		if f.counts == nil {
			f.counts = make(map[int]int)
		}
		chosen, found, n = handler, true, f.counts[i]
		f.counts[i]++
		break
	}
	f.mu.Unlock()
	if !found {
		args := strings.Join(c.Args[:min(2, len(c.Args))], " ")
		return Result{Code: -1}, fmt.Errorf("boxexec fake: no handler for %q %q", c.Name, args)
	}
	// Let the handler read stdin even though recording already consumed it.
	if c.Stdin != nil {
		c.Stdin = bytes.NewReader(input)
	}
	var result Result
	var err error
	if chosen.Respond != nil {
		result, err = chosen.Respond(c, n)
	}
	var outErr, errErr error
	result.Stdout, outErr = forward(c.Stdout, result.Stdout)
	result.Stderr, errErr = forward(c.Stderr, result.Stderr)
	return result, errors.Join(err, outErr, errErr, ctx.Err())
}

// CallsMatching returns independent copies of calls matching all substrings.
func (f *Fake) CallsMatching(name string, contains ...string) []Call {
	f.mu.Lock()
	defer f.mu.Unlock()
	var calls []Call
	for _, call := range f.Calls {
		if matches(call, name, contains) {
			call.Args = slices.Clone(call.Args)
			call.Env = slices.Clone(call.Env)
			calls = append(calls, call)
		}
	}
	return calls
}

func matches(call Call, name string, contains []string) bool {
	if name != "" && call.Name != name {
		return false
	}
	args := strings.Join(call.Args, " ")
	for _, part := range contains {
		if !strings.Contains(args, part) {
			return false
		}
	}
	return true
}

func forward(writer io.Writer, data []byte) ([]byte, error) {
	if writer == nil {
		return data, nil
	}
	_, err := io.Copy(writer, bytes.NewReader(data))
	return nil, err
}
