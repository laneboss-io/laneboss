// Package argparse formats the standalone decisions parser's Python messages.
// It does not apply the launcher's ScreeningParser policy.
package argparse

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

const Commands = "init migrate add supersede annotate get search embed egress stats verify export import load serve ingest-lane ingest-records feedback"

var negativeNumber = regexp.MustCompile(`^-(?:[0-9]+|[0-9]*\.[0-9]+)$`)

func IsOption(word string) bool {
	return strings.HasPrefix(word, "-") && word != "-" && !negativeNumber.MatchString(word)
}

// Repr follows Python's string repr for parser diagnostics, including quote
// selection and escaping characters that Python does not print literally.
func Repr(value string) string {
	quote := '\''
	if strings.ContainsRune(value, '\'') && !strings.ContainsRune(value, '"') {
		quote = '"'
	}
	var out strings.Builder
	out.WriteRune(quote)
	for _, ch := range value {
		switch {
		case ch == quote || ch == '\\':
			out.WriteByte('\\')
			out.WriteRune(ch)
		case ch == '\n':
			out.WriteString(`\n`)
		case ch == '\r':
			out.WriteString(`\r`)
		case ch == '\t':
			out.WriteString(`\t`)
		case ch == ' ' || unicode.IsPrint(ch) && !unicode.IsSpace(ch):
			out.WriteRune(ch)
		case ch <= 0xff:
			fmt.Fprintf(&out, `\x%02x`, ch)
		case ch <= 0xffff:
			fmt.Fprintf(&out, `\u%04x`, ch)
		default:
			fmt.Fprintf(&out, `\U%08x`, ch)
		}
	}
	out.WriteRune(quote)
	return out.String()
}

func Required(labels ...string) string {
	return "the following arguments are required: " + strings.Join(labels, ", ")
}

func Expected(label string) string { return "argument " + label + ": expected one argument" }

func Unrecognized(words ...string) string {
	return "unrecognized arguments: " + strings.Join(words, " ")
}

func Ignored(label, value string) string {
	return "argument " + label + ": ignored explicit argument " + Repr(value)
}

func Choice(label, value string, choices []string) string {
	shown := make([]string, len(choices))
	for i, choice := range choices {
		shown[i] = Repr(choice)
	}
	return "argument " + label + ": invalid choice: " + Repr(value) + " (choose from " + strings.Join(shown, ", ") + ")"
}

func NumericChoice(label, value string, choices []string) string {
	return "argument " + label + ": invalid choice: " + value + " (choose from " + strings.Join(choices, ", ") + ")"
}

func InvalidInt(label, value string) string {
	return "argument " + label + ": invalid int value: " + Repr(value)
}
