package identityd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"

	"laneboss.io/laneboss/internal/config"
)

// LaunchSpec is the handoff for future CLI integration. Launcher names the
// installed laneboss executable. Command remains ordinary caller-owned work;
// neither its argv nor the internal worker transport grants service identity.
type LaunchSpec struct {
	Launcher    string   `json:"launcher"`
	Config      string   `json:"config"`
	RuntimeRoot string   `json:"runtime_root,omitempty"`
	Lane        string   `json:"lane"`
	Run         int      `json:"run"`
	Level       int      `json:"level,omitempty"`
	Command     []string `json:"command"`
	Directory   string   `json:"directory,omitempty"`
}

type LaunchIO struct{ Stdin, Stdout, Stderr *os.File }

type LaunchResult struct {
	Root    Peer   `json:"root"`
	Started Record `json:"started"`
}

// Launch records a gated child, exits its intermediate parent, verifies that
// the child no longer has any original recorded identity ancestor, and only then
// releases the command. setsid alone does not detach process ancestry.
func Launch(ctx context.Context, spec LaunchSpec, streams LaunchIO) (LaunchResult, error) {
	var result LaunchResult
	if spec.Launcher == "" || len(spec.Command) == 0 || !laneName.MatchString(spec.Lane) || spec.Run < 1 || streams.Stdin == nil || streams.Stdout == nil || streams.Stderr == nil {
		return result, refuse("the lane launch handoff is incomplete")
	}
	if err := config.GuardNamed(spec.Config); err != nil {
		return result, refuse("the lane launch conflicts with its bound configuration")
	}
	options := Options{Config: spec.Config, RuntimeRoot: spec.RuntimeRoot}
	who, err := Call(ctx, options, Request{Op: "whoami"})
	if err != nil {
		return result, err
	}
	if !who.Identified || who.Root == nil || who.DetachmentRoot == nil {
		return result, unidentified(true)
	}
	if err := requireNoSubreaper(); err != nil {
		return result, err
	}
	mine, err := nativeProcess(os.Getpid())
	if err != nil {
		return result, err
	}
	chain, err := ancestry(mine.Peer)
	if err != nil {
		return result, err
	}
	original, err := launchIdentityLine(chain, *who.Root, *who.DetachmentRoot)
	if err != nil {
		return result, err
	}
	data, err := json.Marshal(spec)
	if err != nil || len(data) > MaxRequestBytes {
		return result, refuse("the lane launch handoff exceeds its size limit")
	}
	gateRead, gateWrite, err := os.Pipe()
	if err != nil {
		return result, err
	}
	defer gateRead.Close()
	defer gateWrite.Close()
	exitRead, exitWrite, err := os.Pipe()
	if err != nil {
		return result, err
	}
	defer exitRead.Close()
	defer exitWrite.Close()
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		return result, err
	}
	defer readyRead.Close()
	defer readyWrite.Close()
	proxy := exec.Command(spec.Launcher, "service", "__launch_parent")
	proxy.Stdin, proxy.Stdout, proxy.Stderr = bytes.NewReader(data), readyWrite, streams.Stderr
	proxy.ExtraFiles = []*os.File{gateRead, streams.Stdout, streams.Stderr, streams.Stdin, exitRead}
	proxy.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := proxy.Start(); err != nil {
		return result, refuse("the lane launch parent could not start")
	}
	collected := false
	defer func() {
		if !collected {
			// Closing the gates prevents the unexecuted child from running.
			gateWrite.Close()
			exitWrite.Close()
			proxy.Process.Kill()
			proxy.Wait()
		}
	}()
	readyWrite.Close()
	deadline := time.Now().Add(connectionTimeout)
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	if err := readyRead.SetReadDeadline(deadline); err != nil {
		return result, err
	}
	line, err := bufio.NewReaderSize(readyRead, MaxRequestBytes+1).ReadSlice('\n')
	if err != nil || len(line) > MaxRequestBytes || json.Unmarshal(line, &result.Root) != nil {
		return result, refuse("the gated lane root did not report its kernel identity")
	}
	root, err := processFor(ProcessRef{PID: result.Root.PID, Start: result.Root.Start})
	if err != nil || !samePeer(root.Peer, result.Root) {
		return result, refuse("the gated lane root disagrees with the kernel")
	}
	started, err := Call(ctx, options, Request{Op: "lane-started", Lane: spec.Lane, Run: spec.Run, Level: spec.Level, Process: &ProcessRef{PID: root.PID, Start: root.Start}})
	if err != nil {
		return result, err
	}
	if started.Record == nil || started.Record.Process == nil || !samePeer(*started.Record.Process, root.Peer) {
		return result, corrupt("the service did not record the gated lane root")
	}
	result.Started = *started.Record
	if unsafeDetach() {
		// The mutant keeps the real parent alive and omits the ancestry check.
		if _, err := exitWrite.Write([]byte{'h'}); err != nil {
			return result, err
		}
		if err := proxy.Process.Release(); err != nil {
			return result, err
		}
		collected = true
	} else {
		if _, err := exitWrite.Write([]byte{'d'}); err != nil {
			return result, err
		}
		waited := make(chan error, 1)
		go func() { waited <- proxy.Wait() }()
		select {
		case err := <-waited:
			collected = true
			if err != nil {
				return result, refuse("the lane launch parent did not exit cleanly")
			}
		case <-ctx.Done():
			proxy.Process.Kill()
			<-waited
			collected = true
			return result, ctx.Err()
		}
		after, err := ancestry(root.Peer)
		if err != nil {
			return result, err
		}
		for _, old := range original {
			if inAncestry(old.Peer, after) {
				return result, refuse("a child subreaper retained the lane in the session tree\nInstead: remove the subreaper at or below the outermost recorded identity root and launch a new run.")
			}
		}
	}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if _, err := gateWrite.Write([]byte{'x'}); err != nil {
		return result, err
	}
	return result, nil
}

// Unrecorded ancestors above every identity root do not confer identity. A
// recorded outer session does, even when a nearer session selects the caller's
// principal, so the proof must extend through the outermost recorded root.
func launchIdentityLine(line []process, root, detachmentRoot ProcessRef) ([]process, error) {
	matched, boundary := -1, -1
	for index, current := range line {
		if current.PID == root.PID && sameStart(current.Start, root.Start) {
			matched = index
		}
		if current.PID == detachmentRoot.PID && sameStart(current.Start, detachmentRoot.Start) {
			boundary = index
		}
	}
	if matched < 0 || boundary < matched {
		return nil, refuse("the launcher's resolved identity roots are no longer in its kernel ancestry\nInstead: reconnect from the live recorded session.")
	}
	if wideDetach() {
		return line, nil
	}
	if boundary > matched && shortDetach() {
		boundary = matched
	}
	return line[:boundary+1], nil
}

func launchWorker(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		return 2
	}
	data, err := io.ReadAll(io.LimitReader(stdin, MaxRequestBytes+1))
	var spec LaunchSpec
	if err != nil || len(data) > MaxRequestBytes || json.Unmarshal(data, &spec) != nil || len(spec.Command) == 0 {
		return 2
	}
	if args[0] == "__launch_parent" {
		return launchParent(spec, data, stdout, stderr)
	}
	if args[0] != "__launch_root" {
		return 2
	}
	if err := requireNoSubreaper(); err != nil {
		return 2
	}
	current, err := nativeProcess(os.Getpid())
	if err != nil || json.NewEncoder(stdout).Encode(current.Peer) != nil {
		return 2
	}
	gate, err := inheritedGate(3, "lane-command-gate")
	if err != nil {
		return launchFailure(err, stderr)
	}
	defer gate.Close()
	var control [1]byte
	if _, err := io.ReadFull(gate, control[:]); err != nil || control[0] != 'x' {
		return 2
	}
	return execLane(spec)
}

func launchParent(spec LaunchSpec, data []byte, stdout, stderr io.Writer) int {
	if err := requireNoSubreaper(); err != nil {
		return 2
	}
	exitGate, err := inheritedGate(7, "lane-parent-gate")
	if err != nil {
		return launchFailure(err, stderr)
	}
	defer exitGate.Close()
	root := exec.Command(spec.Launcher, "service", "__launch_root")
	root.Stdin, root.Stdout, root.Stderr = bytes.NewReader(data), stdout, stderr
	root.ExtraFiles = []*os.File{os.NewFile(3, "lane-command-gate"), os.NewFile(4, "lane-stdout"), os.NewFile(5, "lane-stderr"), os.NewFile(6, "lane-stdin")}
	root.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := root.Start(); err != nil {
		return 2
	}
	var control [1]byte
	if _, err := io.ReadFull(exitGate, control[:]); err != nil {
		root.Process.Kill()
		root.Wait()
		return 2
	}
	if control[0] == 'h' {
		if err := root.Wait(); err != nil {
			return 2
		}
		return 0
	}
	if control[0] != 'd' || root.Process.Release() != nil {
		root.Process.Kill()
		root.Wait()
		return 2
	}
	return 0
}

func inheritedGate(fd int, name string) (*os.File, error) {
	// exec.Cmd obtains ExtraFiles through File.Fd(), which can make pipes
	// blocking. NewFile only registers an inherited descriptor with Go's poller
	// when it is nonblocking. Restore that mode before wrapping the descriptor,
	// so deadlines work in both the parent and root workers.
	if err := syscall.SetNonblock(fd, true); err != nil {
		return nil, refuse("the inherited lane gate cannot be made pollable")
	}
	syscall.CloseOnExec(fd)
	gate := os.NewFile(uintptr(fd), name)
	if gate == nil {
		return nil, refuse("the inherited lane gate is unavailable")
	}
	if err := gate.SetReadDeadline(time.Now().Add(connectionTimeout)); err != nil {
		gate.Close()
		return nil, refuse("the inherited lane gate cannot enforce its deadline")
	}
	return gate, nil
}

func execLane(spec LaunchSpec) int {
	path, err := exec.LookPath(spec.Command[0])
	if err != nil {
		return 2
	}
	if spec.Directory != "" && os.Chdir(spec.Directory) != nil {
		return 2
	}
	if err := replaceStdio(); err != nil {
		return 2
	}
	// Exec preserves the recorded root's PID/start time. It uses the caller's
	// normal environment; no environment entry selects a service principal.
	if err := syscall.Exec(path, spec.Command, os.Environ()); err != nil {
		return 2
	}
	return 0
}

func launchFailure(err error, stderr io.Writer) int {
	var problem *failure
	if errors.As(err, &problem) {
		io.WriteString(stderr, problem.text+"\n")
		return problem.code
	}
	io.WriteString(stderr, "refused: the lane launch handoff failed\n")
	return 2
}
