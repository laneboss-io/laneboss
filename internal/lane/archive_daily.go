package lane

import (
	"fmt"
	"io"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/faults"
)

// RunArchive reports every finished lane. A local refusal does not starve later
// lanes; upload/integrity/lock failures halt mutations, with reports for the
// remaining lanes. The final exit reflects all reports, including zero work.
func RunArchive(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	const usage = "usage: laneboss archive daily --config NAME [--dry-run]"
	if contains(args, "--help") || contains(args, "-h") {
		fmt.Fprintln(stdout, usage)
		return 0
	}
	if len(args) == 0 || args[0] != "daily" {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	name, dry := "", false
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--config":
			i++
			if i == len(args) || name != "" {
				fmt.Fprintln(stderr, usage)
				return 2
			}
			name = args[i]
		case "--dry-run":
			if dry {
				fmt.Fprintln(stderr, usage)
				return 2
			}
			dry = true
		default:
			fmt.Fprintln(stderr, usage)
			return 2
		}
	}
	c, err := loadConfiguration(name)
	if err != nil {
		return archiveFailure(err, stderr)
	}
	principal, err := c.caller()
	if err != nil {
		return archiveFailure(err, stderr)
	}
	if err = caller.RequireIdentity(principal); err != nil {
		return archiveFailure(refuse("%s", err), stderr)
	}
	if len(principal.ID) >= 5 && principal.ID[:5] == "lane:" {
		return archiveFailure(refuse("daily archive requires a supervisor or human identity"), stderr)
	}
	s, err := openSession(c, false)
	if err != nil {
		return archiveFailure(err, stderr)
	}
	defer s.close()
	rows, err := s.rows()
	if err != nil {
		return archiveFailure(err, stderr)
	}
	processed, refused, failed, skipped, notAttempted, exitCode := 0, 0, 0, 0, 0, 0
	halted := false
	for _, row := range rows {
		if !contains([]string{"merged", "abandoned"}, str(row["state"])) {
			continue
		}
		lane := str(row["lane"])
		if halted {
			if _, err = fmt.Fprintln(stdout, string(canonical(object{"lane": lane, "run": row["run"], "status": "not-attempted", "dry_run": dry, "reason": "archive mutations halted after an upload, integrity, store or lifecycle-lock failure"}))); err != nil {
				return 1
			}
			notAttempted++
			continue
		}
		a := arguments{action: "archive", values: map[string]string{"lane": lane, "config": c.name}, booleans: map[string]bool{"dry-run": dry}}
		result, err := s.archive(a)
		if err != nil {
			code := archiveFailure(err, stderr)
			status, reason := "failed", "archive operation failed; inspect the retained evidence and store"
			stop := code != 2
			if p, ok := err.(*problem); ok {
				reason = safeMessage(p.message)
				stop = stop || p.haltBatch
			}
			if !stop {
				status = "refused"
				refused++
			} else {
				failed++
				halted = true
			}
			if code > exitCode {
				exitCode = code
			}
			if _, outputErr := fmt.Fprintln(stdout, string(canonical(object{"lane": lane, "run": row["run"], "status": status, "dry_run": dry, "reason": reason}))); outputErr != nil {
				return 1
			}
			if code == 2 && faults.Get("archive-daily-stop-on-refusal").Point != "" {
				if err = faults.Reach("archive-daily-stop-on-refusal"); err != nil {
					return archiveFailure(err, stderr)
				}
				return code
			}
			continue
		}
		if _, err = fmt.Fprintln(stdout, string(canonical(result))); err != nil {
			return 1
		}
		if obj(result)["status"] == "already-archived" {
			skipped++
		} else {
			processed++
		}
	}
	status := "complete"
	if halted {
		status = "failed"
	} else if refused != 0 {
		status = "complete-with-refusals"
	}
	_, err = fmt.Fprintln(stdout, string(canonical(object{"action": "archive.daily", "config": c.name, "dry_run": dry, "processed": processed, "refused": refused, "failed": failed, "skipped": skipped, "not_attempted": notAttempted, "status": status})))
	if err != nil {
		return 1
	}
	return exitCode
}

func archiveFailure(err error, stderr io.Writer) int {
	if p, ok := err.(*problem); ok {
		fmt.Fprintln(stderr, p.prefix+": "+p.message)
		return p.code
	}
	fmt.Fprintln(stderr, "integrity problem: archive operation failed")
	return 3
}
