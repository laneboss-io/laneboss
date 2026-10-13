// Package decisions implements the decision-store command group in Go.
package decisions

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"laneboss.io/laneboss/internal/decisions/jsonout"
)

type arguments struct {
	command     string
	values      map[string][]string
	positionals []string
	help        bool
}

func (a *arguments) get(k string) string {
	v := a.values[k]
	if len(v) == 0 {
		return ""
	}
	return v[len(v)-1]
}
func (a *arguments) flag(k string) bool { return a.get(k) == "true" }
func (a *arguments) has(k string) bool  { return len(a.values[k]) != 0 }
func parseArguments(args []string) (*arguments, error) {
	a := &arguments{values: map[string][]string{}, positionals: []string{}}
	if len(args) == 0 {
		return nil, invalid("a decisions command is required")
	}
	if args[0] == "--help" || args[0] == "-h" {
		a.help = true
		return a, nil
	}
	a.command = args[0]
	if !member(a.command, "init migrate add supersede annotate get search embed egress stats verify export import load feedback") {
		return nil, invalid("unsupported decisions command")
	}
	options := "db"
	switch a.command {
	case "add", "supersede", "annotate":
		options += " file"
	case "embed":
		options += " config"
	case "egress":
		options += " list"
	case "export":
		options += " out"
	case "import":
		options += " in"
	case "load":
		options += " in dry-run"
	case "feedback":
		options += " event source at"
	case "search":
		options += " config mode id project area topic kind status date-from date-to limit all level instance scope rank now half-life cautions"
	}
	aliases := map[string]string{"from": "date-from", "since": "date-from", "to": "date-to", "until": "date-to"}
	positional := false
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if arg == "--" && !positional {
			positional = true
			continue
		}
		if !positional && (arg == "--help" || arg == "-h") {
			a.help = true
			return a, nil
		}
		if !positional && strings.HasPrefix(arg, "--") {
			given := strings.TrimPrefix(arg, "--")
			parts := strings.SplitN(given, "=", 2)
			name := parts[0]
			if alias, ok := aliases[name]; ok {
				name = alias
			}
			if !member(name, options) {
				return nil, invalid("unsupported command option")
			}
			value := ""
			if member(name, "list all dry-run") {
				if len(parts) != 1 {
					return nil, invalid("flag does not accept a value")
				}
				value = "true"
			} else if len(parts) == 2 {
				value = parts[1]
			} else {
				if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
					return nil, invalid("option requires a value: --" + name)
				}
				i++
				value = args[i]
			}
			a.values[name] = append(a.values[name], value)
		} else if !positional && strings.HasPrefix(arg, "-") {
			return nil, invalid("unsupported command option")
		} else {
			a.positionals = append(a.positionals, arg)
		}
	}
	if a.get("db") == "" {
		return nil, invalid("--db is required")
	}
	requiredOptions := map[string][]string{"add": {"file"}, "supersede": {"file"}, "annotate": {"file"}, "export": {"out"}, "import": {"in"}, "load": {"in"}, "egress": {"list"}, "feedback": {"event", "source"}}
	for _, f := range requiredOptions[a.command] {
		if a.get(f) == "" {
			return nil, invalid("--" + f + " is required")
		}
	}
	want := 0
	if member(a.command, "get supersede annotate search feedback") {
		want = 1
	}
	if len(a.positionals) != want {
		return nil, invalid("command has missing or extra positional arguments")
	}
	if a.command == "search" {
		providedCautions := a.has("cautions")
		if a.has("level") {
			level, err := strconv.Atoi(trimmed(a.get("level")))
			if err != nil || level < 3 || level > 6 {
				return nil, invalid("argument --level: invalid choice")
			}
			a.values["level"] = []string{strconv.Itoa(level)}
		}
		for k, v := range map[string]string{"mode": "keyword", "limit": "20", "scope": "intersection", "rank": "relevance", "cautions": "0"} {
			if len(a.values[k]) == 0 {
				a.values[k] = []string{v}
			}
		}
		for _, c := range []struct{ field, choices string }{{"mode", "exact keyword vector hybrid"}, {"kind", kinds + " lane_record"}, {"scope", "intersection own-or-level"}, {"rank", "relevance time"}, {"level", "3 4 5 6"}} {
			if a.has(c.field) && !member(a.get(c.field), c.choices) {
				return nil, invalid("argument --" + c.field + ": invalid choice")
			}
		}
		for _, v := range a.values["status"] {
			if !member(v, statuses) {
				return nil, invalid("argument --status: invalid choice")
			}
		}
		for _, f := range []string{"limit", "cautions"} {
			n, e := strconv.Atoi(a.get(f))
			if e != nil || n < 0 || (f == "limit" && n == 0) || (f == "cautions" && providedCautions && n == 0) {
				return nil, invalid("--" + f + " must be a positive integer")
			}
		}
	}
	if a.command == "feedback" && !member(a.get("event"), "merged accepted abandoned refusal cited") {
		return nil, invalid("unsupported feedback event")
	}
	return a, nil
}
func dispatch(s *store, a *arguments) (any, error) {
	switch a.command {
	case "init":
		return object{"ok": true, "schema_version": schemaVersion}, nil
	case "migrate":
		return s.migrate()
	case "get":
		return s.get(a.positionals[0])
	case "add", "supersede", "annotate":
		v, e := readJSON(a.get("file"))
		if e != nil {
			return nil, e
		}
		switch a.command {
		case "add":
			return s.add(v)
		case "supersede":
			return s.supersede(a.positionals[0], v)
		default:
			return s.annotate(a.positionals[0], v)
		}
	case "stats":
		return s.stats()
	case "verify":
		return s.verify()
	case "search":
		return s.search(a)
	case "embed":
		p, e := providerFromConfig(a.get("config"))
		if e != nil {
			return nil, e
		}
		return s.embedStore(p)
	case "egress":
		return s.egress()
	case "export":
		return s.export(a.get("out"))
	case "import":
		return s.importFile(a.get("in"))
	case "load":
		return s.loadFile(a.get("in"), a.flag("dry-run"))
	case "feedback":
		return s.appendFeedback(a.positionals[0], a.get("event"), a.get("source"), a.get("at"))
	}
	return nil, invalid("unsupported decisions command")
}
func sqliteCode(e error) int {
	var coded interface{ Code() int }
	if errors.As(e, &coded) {
		return coded.Code() & 255
	}
	return 0
}
func plural(n int, noun string) string {
	suffix := ""
	if n != 1 {
		suffix = "s"
	}
	return fmt.Sprintf("%d %s%s", n, noun, suffix)
}
func (p *progress) outcome(command string) string {
	if p.created != "" {
		return ". This command had created the database file " + p.created + "; it is still there and holds no store"
	}
	if p.model == "" && p.receipts == 0 && p.sent == 0 && p.vectors == 0 {
		return "; nothing was changed"
	}
	stored := []string{}
	if p.model != "" {
		stored = append(stored, "the model row for "+p.model)
	}
	if p.receipts > 0 {
		stored = append(stored, plural(p.receipts, "egress receipt"))
	}
	if p.vectors > 0 {
		stored = append(stored, plural(p.vectors, "vector"))
	}
	text := "nothing"
	if len(stored) > 0 {
		text = strings.Join(stored, " and ")
	}
	text = ". Before that, this command had already stored " + text
	if p.sent > 0 {
		text += ", and had sent " + plural(p.sent, "text") + " to the embedding provider"
		if p.sent > p.vectors {
			text += "; the vectors for " + plural(p.sent-p.vectors, "text") + " were not stored"
		}
	}
	if command == "embed" {
		text += ". Run embed again: it sends only the texts that still have no current vector"
	}
	return text
}
func onlyReads(a *arguments) bool {
	return member(a.command, "get stats egress verify export") || (a.command == "search" && member(a.get("mode"), "exact keyword")) || (a.command == "load" && a.flag("dry-run"))
}
func failure(e error, a *arguments, p *progress) (string, int) {
	var problem *problem
	if errors.As(e, &problem) {
		prefix := map[int]string{2: "invalid input: ", 3: "integrity problem: ", 4: "provider failed: ", 6: "permission problem: "}[problem.code]
		message := prefix + problem.message
		if problem.code == 6 {
			message += p.outcome(a.command)
		}
		return message, problem.code
	}
	switch sqliteCode(e) {
	case 5, 6:
		message := "database busy: another process held the write lock for longer than the 10-second wait" + p.outcome(a.command)
		if p.created == "" && p.model == "" && p.receipts == 0 && p.sent == 0 && p.vectors == 0 {
			message += "; try again later"
		} else {
			message += "."
		}
		return message, 5
	case 8, 14:
		return "permission problem: SQLite cannot write the database. verify, export, migrate and every command that writes need write permission on the database file; commands that change the store also need write permission on its directory, where SQLite keeps its rollback journal" + p.outcome(a.command), 6
	case 10, 13:
		reason := "disk I/O error"
		if sqliteCode(e) == 13 {
			reason = "database or disk is full"
		}
		if onlyReads(a) {
			return "storage problem: SQLite failed (" + reason + ") while it read the database file, or restored it from the rollback journal of an earlier write that did not finish: the disk may be failing or full, or a file-size limit may have been reached. This command only reads, so nothing was changed", 7
		}
		return "storage problem: SQLite failed (" + reason + ") while it read or wrote the database file or its rollback journal: the disk may be full, a file-size limit may have been reached, or the system reported an I/O error. SQLite rolls a failed write back from the rollback journal (if this process could not finish that, the next one to open the file does), so it does not reach the store" + p.outcome(a.command), 7
	case 19:
		return "refused write: database constraint", 2
	}
	if os.IsPermission(e) {
		return "permission problem: unreadable or unwritable path" + p.outcome(a.command), 6
	}
	return "integrity problem: SQLite operation failed", 3
}

// Run executes the decision-store command and returns its stable process exit code.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) (exitCode int) {
	a, e := parseArguments(args)
	if e != nil {
		fmt.Fprintln(stderr, "invalid input: "+e.Error())
		return 2
	}
	if a.help {
		fmt.Fprintln(stdout, "usage: laneboss-decisions COMMAND --db FILE [OPTIONS]\nCommands: init migrate add supersede annotate get search embed egress stats verify export import load feedback")
		return 0
	}
	p := &progress{}
	defer func() {
		if caught := recover(); caught != nil {
			cause, ok := caught.(error)
			if !ok {
				cause = integrity("command failed")
			}
			message, code := failure(cause, a, p)
			fmt.Fprintln(stderr, message)
			exitCode = code
		}
	}()
	s, e := openStore(a.get("db"), a.command, p)
	if e != nil {
		message, code := failure(e, a, p)
		fmt.Fprintln(stderr, message)
		return code
	}
	defer s.close()
	result, e := dispatch(s, a)
	if e != nil {
		message, code := failure(e, a, p)
		fmt.Fprintln(stderr, message)
		return code
	}
	output, e := jsonout.Line(result)
	if e != nil {
		message, code := failure(invalid(e.Error()), a, p)
		fmt.Fprintln(stderr, message)
		return code
	}
	if _, e = stdout.Write(output); e != nil {
		fmt.Fprintln(stderr, "invalid input: cannot write command output")
		return 2
	}
	return 0
}
