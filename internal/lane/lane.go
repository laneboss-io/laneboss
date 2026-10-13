// Package lane implements the supervised lifecycle of a Laneboss lane.
package lane

import (
	"fmt"
	"io"
	"strings"
)

// Run executes `laneboss lane ARGS...` and returns the process exit code.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if contains(args, "--help") || contains(args, "-h") {
		fmt.Fprintln(stdout, "usage: laneboss lane {start,resume,stop,status,check,mark,clean,scan,refusals,review} --config NAME [options]\n\nstart: --lane --brief --runner|--difficulty --model --effort --account --budget --project --worktree|--base --reuse --turns --idle --touches\nresume: --lane --message --account --budget\nstop: --lane --run\nstatus, check, refusals: --lane (optional)\nmark: --lane --state|--landing|--gone --accept-uncovered\nclean, scan: --lane\nreview: --lane --refusal --path --verdict --note")
		return 0
	}
	if len(args) == 1 && args[0] == "__follow" {
		return followRecords(stdin, stdout, stderr)
	}
	if len(args) == 1 && args[0] == "__classify" {
		return classifyRecords(stdin, stdout)
	}
	if len(args) == 2 && args[0] == "__supervise" {
		return supervise(args[1], stderr)
	}
	a, err := parseArgs(args)
	var result any
	if err == nil {
		var c *configuration
		c, err = loadConfiguration(a.get("config"))
		if err == nil {
			var s *session
			s, err = openSession(c, a.action == "start")
			if err == nil {
				defer s.close()
				switch a.action {
				case "start":
					result, err = s.start(a, stderr)
				case "resume":
					result, err = s.resume(a)
				case "stop":
					result, err = s.stop(a)
				case "status":
					result, err = s.status(a)
				case "check":
					result, err = s.check(a)
				case "mark":
					result, err = s.mark(a)
				case "clean":
					result, err = s.clean(a)
				case "scan":
					result, err = s.scan(a)
				case "refusals":
					result, err = s.refusals(a)
				case "review":
					result, err = s.review(a)
				}
			}
		}
	}
	if err != nil {
		if refused, ok := err.(*storeRefusalError); ok {
			err = refused.cause
		}
		if unavailable, ok := err.(*storeUnavailableError); ok {
			err = unavailable.cause
		}
		if p, ok := err.(*problem); ok {
			for _, line := range strings.Split(p.message, "\n") {
				fmt.Fprintln(stderr, p.prefix+": "+line)
			}
			return p.code
		}
		fmt.Fprintln(stderr, "integrity problem: lane operation failed")
		return 3
	}
	if _, err = fmt.Fprintln(stdout, string(canonical(result))); err != nil {
		return 1
	}
	return 0
}
