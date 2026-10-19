package boxexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Cmd describes one child process.
type Cmd struct {
	Name   string // program; looked up on the PATH inside Env, never on the parent's
	Args   []string
	Env    []string // the whole environment, KEY=VALUE; nil means CleanEnv(nil)
	Dir    string
	Stdin  io.Reader
	Stdout io.Writer // nil: captured into Result.Stdout
	Stderr io.Writer // nil: captured into Result.Stderr
}

// Result is what a finished child left behind.
type Result struct {
	Code   int    // exit status; 128+signal when a signal ended it; -1 when it never started
	Stdout []byte // nil when Cmd.Stdout was set
	Stderr []byte // nil when Cmd.Stderr was set
}

// Runner starts child processes. Providers and the orchestrator take a Runner so tests need no cloud.
type Runner interface {
	// Run starts the child and waits. A non-zero exit is NOT an error: it is Result.Code with a nil error. The error
	// is non-nil only when the process could not start or the context ended first (then Code is -1 or the signal's).
	Run(ctx context.Context, c Cmd) (Result, error)
}

// ExecRunner runs real processes. Its zero value is ready for use.
type ExecRunner struct{}

const captureLimit = 16 << 20

// Run resolves the program on the child's PATH and waits for it to finish.
func (ExecRunner) Run(ctx context.Context, c Cmd) (Result, error) {
	result := Result{Code: -1}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	env := c.Env
	if env == nil {
		env = CleanEnv(nil)
	}
	path, err := resolve(c.Name, env, c.Dir)
	if err != nil {
		return result, err
	}
	cmd := exec.CommandContext(ctx, path, c.Args...)
	cmd.Env = env
	cmd.Dir = c.Dir
	cmd.Stdin = c.Stdin
	var stdout, stderr cappedBuffer
	if c.Stdout == nil {
		cmd.Stdout = &stdout
	} else {
		cmd.Stdout = c.Stdout
	}
	if c.Stderr == nil {
		cmd.Stderr = &stderr
	} else {
		cmd.Stderr = c.Stderr
	}
	setProcessGroup(cmd)
	cmd.WaitDelay = 5 * time.Second
	err = cmd.Run()
	result.Code = processCode(cmd.ProcessState)
	if c.Stdout == nil {
		result.Stdout = stdout.buf.Bytes()
	}
	if c.Stderr == nil {
		result.Stderr = stderr.buf.Bytes()
	}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return result, nil
	}
	return result, err
}

func resolve(name string, env []string, dir string) (string, error) {
	if strings.Contains(name, "/") {
		return name, nil
	}
	var path string
	for _, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		if ok && key == "PATH" {
			path = value
		}
	}
	for _, searchDir := range filepath.SplitList(path) {
		if searchDir == "" {
			continue
		}
		candidate := filepath.Join(searchDir, name)
		if !filepath.IsAbs(candidate) {
			var err error
			candidate, err = filepath.Abs(filepath.Join(dir, candidate))
			if err != nil {
				return "", err
			}
		}
		info, err := os.Stat(candidate)
		if err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("boxexec: resolve %q: %w", name, exec.ErrNotFound)
}

type cappedBuffer struct {
	buf bytes.Buffer
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if room := captureLimit - b.buf.Len(); room > 0 {
		_, err := b.buf.Write(p[:min(len(p), room)])
		if err != nil {
			return 0, err
		}
	}
	// Accept the whole write so excess output cannot fail the child run.
	return n, nil
}
