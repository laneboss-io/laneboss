// Package start implements the read-only supervisor briefing.
package start

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"laneboss.io/laneboss/internal/cliargs"
)

const withheld = "[withheld]"
const unknown = "Open questions to the owner and due dates are not in the store yet."
const noStore = "no store exists yet"
const startUsage = "usage: laneboss start [-h] [--config NAME] [--role ROLE] [--format {text,json}]"

type problem struct {
	code            int
	prefix, message string
}

func (p *problem) Error() string     { return p.message }
func refused(message string) error   { return &problem{2, "refused", message} }
func integrity(message string) error { return &problem{3, "integrity problem", message} }
func usageError(message string) error {
	return &problem{2, "laneboss start: error", cliargs.Screen(message)}
}
func invalid(label, path, message string) error {
	if path == "" {
		path = "(top level)"
	}
	return &problem{2, "invalid configuration", label + ": " + scrub(path) + ": " + scrub(message)}
}

type options struct {
	config, role *string
	format       string
	help         bool
}

func parseArgs(args []string) (options, error) {
	o := options{format: "text"}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--help" || a == "-h" {
			o.help = true
			continue
		}
		label, val, attached := strings.Cut(a, "=")
		known := ""
		for _, candidate := range []string{"--config", "--role", "--format"} {
			if strings.HasPrefix(candidate, label) && strings.HasPrefix(label, "--") {
				if known != "" {
					return o, usageError(cliargs.Reject(""))
				}
				known = candidate
			}
		}
		if known == "" {
			return o, usageError(cliargs.Reject(""))
		}
		if !attached {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return o, usageError(cliargs.Expected(known))
			}
			i++
			val = args[i]
		}
		switch known {
		case "--config":
			value := val
			o.config = &value
		case "--role":
			value := val
			o.role = &value
		case "--format":
			if val != "text" && val != "json" {
				return o, usageError(cliargs.Reject("--format"))
			}
			o.format = val
		}
	}
	return o, nil
}

// Run executes laneboss start without invoking any other command group.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	o, err := parseArgs(args)
	if err == nil && o.help {
		_, err = fmt.Fprintln(stdout, startUsage+"\n\nPrint the briefing a supervisor session reads when it begins.")
		if err == nil {
			return 0
		}
	}
	var document map[string]any
	var lines []string
	if err == nil {
		if o.config == nil && os.Getenv("LANEBOSS_CONFIG") == "" {
			if o.role != nil {
				err = checkName(*o.role, "role")
			}
			if err == nil {
				document, err = listing(o.role)
				if err == nil {
					lines = listingText(document)
				}
			}
		} else {
			var c *configuration
			c, err = bind(o.config)
			if err == nil {
				document, err = briefing(c, o.role)
			}
			if err == nil && o.format == "text" {
				lines = briefingText(document)
			}
		}
	}
	if err == nil {
		if o.format == "json" {
			enc := json.NewEncoder(stdout)
			enc.SetEscapeHTML(false)
			err = enc.Encode(document)
		} else {
			_, err = io.WriteString(stdout, strings.Join(lines, "\n")+"\n")
		}
	}
	if err == nil {
		return 0
	}
	p, ok := err.(*problem)
	if !ok {
		p = &problem{70, "internal error", "the briefing could not be read or written"}
	}
	if p.prefix == "laneboss start: error" {
		fmt.Fprintln(stderr, startUsage)
	}
	for _, line := range splitLines(scrub(p.message)) {
		fmt.Fprintln(stderr, p.prefix+": "+line)
	}
	return p.code
}
