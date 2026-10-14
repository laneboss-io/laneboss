// Package cliargs shares Python ScreeningParser's usage-error screening across
// the Go command groups. Argument labels must come from the parser's grammar,
// never from an unrecognized option or a supplied value.
package cliargs

import (
	"fmt"
	"io"
	"regexp"
	"strings"
)

const refused = "not accepted; a typed value is never repeated here, see the usage line above or run with --help"
const labels = `[A-Za-z0-9_/, \-]+`

var safeForms = []*regexp.Regexp{
	regexp.MustCompile(`^the following arguments are required: ` + labels + `$`),
	regexp.MustCompile(`^argument ` + labels + `: expected (?:one argument|at least one argument|at most one argument|[0-9]+ arguments?)$`),
	regexp.MustCompile(`^argument ` + labels + `: not allowed with argument ` + labels + `$`),
	regexp.MustCompile(`^one of the arguments ` + labels + ` is required$`),
}
var labelled = regexp.MustCompile(`^argument (` + labels + `): `)

// Screen preserves only the parser's complete safe forms. All other messages
// become a fixed refusal, retaining at most a label in the documented grammar.
func Screen(message string) string {
	for _, form := range safeForms {
		if form.MatchString(message) {
			return message
		}
	}
	if match := labelled.FindStringSubmatch(message); match != nil {
		return "argument " + match[1] + ": " + refused
	}
	return "the command line was " + refused
}

// Reject constructs a screened error for a parser-defined label. An empty label
// is used for unrecognized or extra tokens, which must never be echoed.
func Reject(label string) string {
	if label == "" {
		return Screen("")
	}
	return Screen("argument " + label + ": rejected")
}

func Required(arguments ...string) string {
	return Screen("the following arguments are required: " + strings.Join(arguments, ", "))
}

func Expected(argument string) string {
	return Screen("argument " + argument + ": expected one argument")
}

func Conflict(argument, other string) string {
	return Screen("argument " + argument + ": not allowed with argument " + other)
}

// Print reports a parser error with parser-defined program and usage strings.
func Print(stderr io.Writer, program, usage, message string) int {
	fmt.Fprintln(stderr, usage)
	fmt.Fprintln(stderr, program+": error: "+Screen(message))
	return 2
}
