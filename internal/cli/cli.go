// Package cli owns the top-level launcher interface and in-process dispatch.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"laneboss.io/laneboss/internal/brief"
	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/decisions"
	"laneboss.io/laneboss/internal/decisionsrv"
	"laneboss.io/laneboss/internal/disk"
	"laneboss.io/laneboss/internal/doctor"
	"laneboss.io/laneboss/internal/event"
	"laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/judge"
	"laneboss.io/laneboss/internal/lane"
	"laneboss.io/laneboss/internal/laneturns"
	"laneboss.io/laneboss/internal/org"
	"laneboss.io/laneboss/internal/plugin"
	"laneboss.io/laneboss/internal/protocol"
	"laneboss.io/laneboss/internal/start"
	"laneboss.io/laneboss/internal/state"
)

const refused = "not accepted; a typed value is never repeated here, see the usage line above or run with --help"

type handler func([]string, io.Reader, io.Writer, io.Writer) int

var handlers = map[string]handler{
	"decisions": runDecisions, "plugin": plugin.Run, "org": org.Run,
	"config": config.Run, "event": event.Run, "state": state.Run,
	"brief": brief.Run, "lane": runLane, "judge": judge.Run,
	"disk": disk.Run, "doctor": doctor.Run, "start": start.Run,
}

func usageError(stderr io.Writer, message string) int {
	fmt.Fprint(stderr, syntaxUsage(&rootSyntax, identity.Program))
	fmt.Fprintln(stderr, "laneboss: error: "+message)
	return 2
}

func write(stdout, stderr io.Writer, text string) int {
	if _, err := io.WriteString(stdout, text); err != nil {
		if errors.Is(err, syscall.EPIPE) {
			return 0
		}
		fmt.Fprintln(stderr, "internal error: cannot write launcher output")
		return 70
	}
	return 0
}

// Run passes each group's argument slice unchanged to its existing entry point.
// Only options before the group belong to the root parser.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) (code int) {
	defer func() {
		if recovered := recover(); recovered != nil {
			if os.Getenv(identity.EnvPrefix+"DEBUG") != "" {
				panic(recovered)
			}
			fmt.Fprintln(stderr, "internal error: panic")
			code = 70
		}
	}()
	if len(args) > 0 {
		if run, ok := handlers[args[0]]; ok {
			return run(args[1:], stdin, stdout, stderr)
		}
	}
	version := false
	status, unknown := parseSyntax(&rootSyntax, identity.Program, args, stdout, stderr, &version)
	if status >= 0 {
		return status
	}
	if unknown {
		return usageError(stderr, "the command line was "+refused)
	}
	if version {
		return printVersion(stdout, stderr)
	}
	return usageError(stderr, "a command is required")
}

func printVersion(stdout, stderr io.Writer) int {
	_, version, err := protocol.Load()
	if err != nil {
		fmt.Fprintln(stderr, "integrity problem: "+err.Error())
		return 3
	}
	return write(stdout, stderr, fmt.Sprintf("{\"program\": %q, \"protocol_version\": %q, \"version\": %q}\n", identity.Program, version, identity.Version))
}

func runLane(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if code, handled := runLaneProbe(args, stdin, stdout, stderr); handled {
		return code
	}
	if len(args) > 0 {
		switch args[0] {
		case "adopt", "turn", "send", "attach", "loop":
			return laneturns.Run(args, stdin, stdout, stderr)
		}
	}
	return lane.Run(args, stdin, stdout, stderr)
}

func runDecisions(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if code, handled := decisionsrv.TryProbe(args, stdin, stdout, stderr); handled {
		return code
	}
	if len(args) > 0 {
		switch args[0] {
		case "serve", "ingest-lane", "ingest-records", "hook-history", "history-worker", "capture-decision":
			return decisionsrv.Run(args, stdin, stdout, stderr)
		}
	}
	return decisions.Run(args, stdin, stdout, stderr)
}
