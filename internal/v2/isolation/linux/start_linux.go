//go:build linux

package linux

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
)

// boundedTail records diagnostic bytes only. They are never interpreted as
// evidence that a namespace or filter was installed successfully.
type boundedTail struct {
	mu   sync.Mutex
	data []byte
	max  int
}

func (tail *boundedTail) Write(data []byte) (int, error) {
	tail.mu.Lock()
	defer tail.mu.Unlock()
	length := len(data)
	if len(data) >= tail.max {
		tail.data = append(tail.data[:0], data[len(data)-tail.max:]...)
		return length, nil
	}
	if excess := len(tail.data) + len(data) - tail.max; excess > 0 {
		tail.data = append(tail.data[:0], tail.data[excess:]...)
	}
	tail.data = append(tail.data, data...)
	return length, nil
}

func (tail *boundedTail) bytes() []byte {
	tail.mu.Lock()
	defer tail.mu.Unlock()
	return append([]byte{}, tail.data...)
}

func checkStream(name string, stream any) error {
	file, ok := stream.(*os.File)
	if !ok {
		return nil // os/exec uses a pipe for an ordinary Reader/Writer
	}
	if file == nil {
		return fmt.Errorf("%s stream is a nil file descriptor", name)
	}
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("%s stream: %w", name, err)
	}
	mode := info.Mode()
	if mode&os.ModeNamedPipe == 0 && mode&os.ModeSocket == 0 && mode&os.ModeCharDevice == 0 {
		return fmt.Errorf("%s stream must be a pipe, socket or character device", name)
	}
	return nil
}

// startSandbox is the package's filesystem/namespace diagnostic start, NOT
// api.Launcher.Launch. It does not attest a UID lease or cgroup. The public
// launcher stays closed until the authenticated helper/control wiring exists.
func startSandbox(ctx context.Context, plan launchPlan, payload launchPayload, spec sandboxSpec) (_ *exec.Cmd, _ *boundedTail, resultErr error) {
	return startSandboxWithProbe(ctx, plan, payload, spec, requireBwrapOptions)
}

func startSandboxWithProbe(ctx context.Context, plan launchPlan, payload launchPayload, spec sandboxSpec,
	probe func(context.Context, launchPlan) error) (_ *exec.Cmd, _ *boundedTail, resultErr error) {
	for _, stream := range []struct {
		name string
		data any
	}{{"stdin", spec.Stdin}, {"stdout", spec.Stdout}, {"stderr", spec.Stderr}} {
		if err := checkStream(stream.name, stream.data); err != nil {
			return nil, nil, err
		}
	}
	if err := contextError(ctx); err != nil {
		return nil, nil, err
	}
	if _, err := probePrerequisites(ctx); err != nil {
		return nil, nil, err
	}
	if probe == nil {
		return nil, nil, &PrerequisiteError{Check: "bwrap_options", Err: errors.New("binary behavior probe is missing")}
	}
	if err := probe(ctx, plan); err != nil {
		return nil, nil, err
	}
	manifest, err := sealedPayload(payload)
	if err != nil {
		return nil, nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, manifest.Close()) }()
	filter, err := denyFilter()
	if err != nil {
		return nil, nil, &PrerequisiteError{Check: "seccomp_deny_filter", Err: err}
	}
	seccomp, err := sealedBytes(filterBytes(filter))
	if err != nil {
		return nil, nil, &PrerequisiteError{Check: "seccomp_deny_filter", Err: err}
	}
	defer func() { resultErr = errors.Join(resultErr, seccomp.Close()) }()
	args, files := buildArgs(plan)
	cmd := exec.CommandContext(ctx, bwrapPath, args...)
	cmd.Dir, cmd.Env = "/", []string{}
	cmd.ExtraFiles = append([]*os.File{manifest, seccomp}, files...)
	cmd.Stdin, cmd.Stdout = spec.Stdin, spec.Stdout
	tail := &boundedTail{max: 8192}
	cmd.Stderr = tail
	if spec.Stderr != nil {
		cmd.Stderr = io.MultiWriter(spec.Stderr, tail)
	}
	if err := cmd.Start(); err != nil {
		return nil, tail, &PrerequisiteError{Check: "sandbox_entry", Err: err}
	}
	return cmd, tail, nil
}
