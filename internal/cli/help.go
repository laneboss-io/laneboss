package cli

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func helpWidth() int {
	columns := 80
	if n, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && n > 0 {
		columns = n
	} else if size, err := unix.IoctlGetWinsize(int(os.Stdout.Fd()), unix.TIOCGWINSZ); err == nil && size.Col > 0 {
		columns = int(size.Col)
	}
	return columns - 2
}

func wrap(text string, width int) []string {
	width = max(width, 1)
	var lines []string
	line := ""
	for _, word := range strings.Fields(text) {
		if line != "" && len(line)+1+len(word) > width {
			lines = append(lines, line)
			line = ""
		}
		for len(word) > width {
			lines = append(lines, word[:width])
			word = word[width:]
		}
		if line != "" {
			line += " "
		}
		line += word
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

func (a argumentSyntax) invocation() string {
	if a.positional() {
		return a.metavar()
	}
	label := a.Name
	if a.Short != "" {
		label = a.Short + ", " + label
	}
	if !a.Flag {
		label += " " + a.metavar()
	}
	return label
}

func usageActions(args []argumentSyntax, groups []exclusiveSyntax) string {
	grouped := map[string]bool{}
	starts, ends := map[int]string{}, map[int]string{}
	separators := map[int]bool{}
	for _, group := range groups {
		for i, a := range args {
			if len(group.Names) == 0 || a.Name != group.Names[0] || i+len(group.Names) > len(args) {
				continue
			}
			matches := true
			for j, name := range group.Names {
				matches = matches && args[i+j].Name == name
			}
			if !matches {
				continue
			}
			open, close := "[", "]"
			if group.Required {
				open, close = "(", ")"
			}
			starts[i], ends[i+len(group.Names)-1] = open, close
			for j, name := range group.Names {
				grouped[name] = true
				if j > 0 {
					separators[i+j] = true
				}
			}
		}
	}
	parts := make([]string, 0, len(args))
	for i, a := range args {
		part := a.metavar()
		if a.positional() {
			if a.Optional && !grouped[a.Name] {
				part = "[" + part + "]"
			}
		} else {
			part = a.Name
			if a.Short != "" {
				part = a.Short
			}
			if !a.Flag {
				part += " " + a.metavar()
			}
			if !a.Required && !grouped[a.Name] {
				part = "[" + part + "]"
			}
		}
		part = starts[i] + part + ends[i]
		if separators[i] {
			part = "| " + part
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, " ")
}

// usageParts keeps bracketed options and mutually exclusive groups together.
func usageParts(text string) []string {
	var result []string
	start, depth := 0, 0
	for i, r := range text {
		switch r {
		case '[', '(':
			depth++
		case ']', ')':
			depth--
		case ' ':
			if depth == 0 {
				if i > start {
					result = append(result, text[start:i])
				}
				start = i + 1
			}
		}
	}
	if start < len(text) {
		result = append(result, text[start:])
	}
	return result
}

func usageLines(parts []string, indent string, initial bool, width int) []string {
	var lines, line []string
	length := len(indent) - 1
	if initial {
		length = len("usage: ") - 1
	}
	for _, part := range parts {
		if length+1+len(part) > width && len(line) > 0 {
			lines = append(lines, indent+strings.Join(line, " "))
			line = nil
			length = len(indent) - 1
		}
		line = append(line, part)
		length += len(part) + 1
	}
	if len(line) > 0 {
		lines = append(lines, indent+strings.Join(line, " "))
	}
	if initial && len(lines) > 0 {
		lines[0] = strings.TrimPrefix(lines[0], indent)
	}
	return lines
}

func syntaxUsage(p *commandSyntax, path string) string {
	var options, positions []argumentSyntax
	for _, a := range p.Args {
		if a.positional() {
			positions = append(positions, a)
		} else {
			options = append(options, a)
		}
	}
	if p.Subcommand != "" {
		positions = append(positions, argumentSyntax{Name: p.Subcommand, Metavar: p.Subcommand + " ..."})
	}
	combined := append(append([]argumentSyntax{}, options...), positions...)
	line := strings.TrimSpace(path + " " + usageActions(combined, p.Exclusive))
	width := helpWidth()
	if len("usage: ")+len(line) <= width {
		return "usage: " + line + "\n"
	}
	opts := usageParts(usageActions(options, p.Exclusive))
	pos := usageParts(usageActions(positions, p.Exclusive))
	var lines []string
	if float64(len("usage: ")+len(path)) <= 0.75*float64(width) {
		indent := strings.Repeat(" ", len("usage: ")+len(path)+1)
		if len(opts) > 0 {
			lines = usageLines(append([]string{path}, opts...), indent, true, width)
			lines = append(lines, usageLines(pos, indent, false, width)...)
		} else {
			lines = usageLines(append([]string{path}, pos...), indent, true, width)
		}
	} else {
		indent := strings.Repeat(" ", len("usage: "))
		lines = usageLines(append(opts, pos...), indent, false, width)
		if len(lines) > 1 {
			lines = append(usageLines(opts, indent, false, width), usageLines(pos, indent, false, width)...)
		}
		lines = append([]string{path}, lines...)
	}
	return "usage: " + strings.Join(lines, "\n") + "\n"
}

func syntaxHelp(p *commandSyntax, path string) string {
	width, longest := helpWidth(), 0
	for _, a := range p.Args {
		longest = max(longest, len(a.invocation())+2)
	}
	if p.Subcommand != "" {
		longest = max(longest, len(p.Subcommand)+2)
	}
	for _, c := range p.Commands {
		longest = max(longest, len(c.Name)+4)
	}
	position := min(longest+2, min(24, max(4, width-20)))
	var b strings.Builder
	b.WriteString(syntaxUsage(p, path))
	b.WriteString("\n")
	if p.Description != "" {
		b.WriteString(strings.Join(wrap(p.Description, width), "\n") + "\n\n")
	}
	row := func(label, description string) {
		if description == "" {
			b.WriteString(label + "\n")
			return
		}
		if len(label) > position-2 {
			b.WriteString(label + "\n" + strings.Repeat(" ", position))
		} else {
			fmt.Fprintf(&b, "%-*s", position, label)
		}
		b.WriteString(strings.Join(wrap(description, max(width-position, 11)), "\n"+strings.Repeat(" ", position)) + "\n")
	}
	hasPosition := p.Subcommand != ""
	for _, a := range p.Args {
		hasPosition = hasPosition || a.positional()
	}
	if hasPosition {
		b.WriteString("positional arguments:\n")
		for _, a := range p.Args {
			if a.positional() {
				row("  "+a.invocation(), a.Help)
			}
		}
		if p.Subcommand != "" {
			row("  "+p.Subcommand, "")
			for _, c := range p.Commands {
				row("    "+c.Name, c.Help)
			}
		}
		b.WriteString("\n")
	}
	b.WriteString("options:\n")
	for _, a := range p.Args {
		if !a.positional() {
			row("  "+a.invocation(), a.Help)
		}
	}
	return b.String()
}
