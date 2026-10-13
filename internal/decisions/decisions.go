// Package decisions implements the decision-store command group in Go.
package decisions

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	decisionargs "laneboss.io/laneboss/internal/decisions/argparse"
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
		return nil, invalid(decisionargs.Required("command"))
	}
	if args[0] == "--help" || args[0] == "-h" {
		a.help = true
		return a, nil
	}
	a.command = args[0]
	if !member(a.command, "init migrate add supersede annotate get search embed egress stats verify export import load feedback") {
		return nil, invalid(decisionargs.Choice("command", a.command, strings.Fields(decisionargs.Commands)))
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
	want, positionalLabel := 0, "id"
	if member(a.command, "get supersede annotate search feedback") {
		want = 1
	}
	if a.command == "search" {
		positionalLabel = "query"
	}
	aliases := map[string]string{"from": "date-from", "since": "date-from", "to": "date-to", "until": "date-to"}
	positional := false
	extra := []string{}
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
			parts := strings.SplitN(strings.TrimPrefix(arg, "--"), "=", 2)
			name := parts[0]
			if alias, ok := aliases[name]; ok {
				name = alias
			}
			if !member(name, options) {
				extra = append(extra, arg)
				continue
			}
			label := "--" + name
			if name == "date-from" {
				label = "--date-from/--from/--since"
			} else if name == "date-to" {
				label = "--date-to/--to/--until"
			}
			value := ""
			if member(name, "list all dry-run") {
				if len(parts) != 1 {
					return nil, invalid(decisionargs.Ignored(label, parts[1]))
				}
				value = "true"
			} else if len(parts) == 2 {
				value = parts[1]
			} else {
				if i+1 >= len(args) || decisionargs.IsOption(args[i+1]) {
					return nil, invalid(decisionargs.Expected(label))
				}
				i++
				value = args[i]
			}
			checked, err := argumentValue(a.command, name, value)
			if err != nil {
				return nil, err
			}
			if !member(name, "status half-life") {
				a.values[name] = nil
			}
			a.values[name] = append(a.values[name], checked)
		} else if !positional && decisionargs.IsOption(arg) {
			extra = append(extra, arg)
		} else if len(a.positionals) < want {
			a.positionals = append(a.positionals, arg)
		} else {
			extra = append(extra, arg)
		}
	}
	missing := []string{}
	if !a.has("db") {
		missing = append(missing, "--db")
	}
	if len(a.positionals) < want {
		missing = append(missing, positionalLabel)
	}
	requiredOptions := map[string][]string{"add": {"file"}, "supersede": {"file"}, "annotate": {"file"}, "export": {"out"}, "import": {"in"}, "load": {"in"}, "egress": {"list"}, "feedback": {"event", "source"}}
	for _, key := range requiredOptions[a.command] {
		if !a.has(key) {
			missing = append(missing, "--"+key)
		}
	}
	if len(missing) > 0 {
		return nil, invalid(decisionargs.Required(missing...))
	}
	if len(extra) > 0 {
		return nil, invalid(decisionargs.Unrecognized(extra...))
	}
	if a.command == "search" {
		for key, value := range map[string]string{"mode": "keyword", "limit": "20", "scope": "intersection", "rank": "relevance", "cautions": "0"} {
			if !a.has(key) {
				a.values[key] = []string{value}
			}
		}
	}
	return a, nil
}

// The parser's registered types and choices are checked while values are read,
// before required-argument errors, as argparse does.
func argumentValue(command, name, value string) (string, error) {
	label := "--" + name
	choices := []string{}
	if command == "search" {
		switch name {
		case "mode":
			choices = strings.Fields("exact keyword vector hybrid")
		case "kind":
			choices = strings.Fields(kinds + " lane_record")
			sort.Strings(choices)
		case "status":
			choices = strings.Fields(statuses)
			sort.Strings(choices)
		case "scope":
			choices = strings.Fields("intersection own-or-level")
		case "rank":
			choices = strings.Fields("relevance time")
		case "level":
			n, err := strconv.Atoi(trimmed(value))
			if err != nil {
				return "", invalid(decisionargs.InvalidInt(label, value))
			}
			if n < 3 || n > 6 {
				return "", invalid(decisionargs.NumericChoice(label, strconv.Itoa(n), strings.Fields("3 4 5 6")))
			}
			return strconv.Itoa(n), nil
		case "limit", "cautions":
			n, err := strconv.Atoi(trimmed(value))
			if err != nil || n < 1 {
				return "", invalid("argument " + label + ": must be a positive integer")
			}
			return strconv.Itoa(n), nil
		}
	} else if command == "feedback" && name == "event" {
		choices = strings.Fields("abandoned accepted cited merged refusal")
	}
	if len(choices) > 0 && !member(value, strings.Join(choices, " ")) {
		return "", invalid(decisionargs.Choice(label, value, choices))
	}
	return value, nil
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
