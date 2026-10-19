package orghook

import (
	"path/filepath"
	"strings"
)

type shellResolution struct {
	name         string
	changesState bool
}

func laneIdentityAssignment(word string) bool {
	name, _, ok := strings.Cut(word, "=")
	return ok && strings.HasPrefix(name, "LANEBOSS_")
}

func stateBuiltin(name string) bool {
	return contains([]string{"cd", "chdir", "pushd", "popd", "dirs", "export", "set", "unset", "shopt", "setopt", "unsetopt",
		"alias", "unalias", "function", "eval", "source", ".", "typeset", "declare", "local", "readonly",
		"hash", "rehash", "umask", "ulimit", "trap", "enable", "disable", "autoload", "read", "getopts", "let", "shift", "fc", "zmodload"}, name)
}

// Lexing has already removed literal quotes and escapes. Resolve through the
// same wrapper inventory as normalise; never execute or expand the words.
func resolveShellCommand(argv []string) (shellResolution, error) {
	result := shellResolution{}
	for count := 0; count <= 8; count++ {
		for len(argv) > 0 && assignment.MatchString(argv[0]) {
			result.changesState = true
			argv = argv[1:]
		}
		if len(argv) == 0 || !standardExecutable(argv[0]) {
			return result, invalid("the effective shell command cannot be identified")
		}
		name := filepath.Base(argv[0])
		takes, wrapper := wrappers[name]
		if !wrapper {
			result.name = name
			result.changesState = result.changesState || stateBuiltin(name)
			if name == "printf" {
				result.changesState = result.changesState || printfState(argv[1:])
			}
			return result, nil
		}
		index := 1
		for index < len(argv) && strings.HasPrefix(argv[index], "-") {
			option := argv[index]
			index++
			if option == "--" {
				break
			}
			if contains(takes, option) {
				if index >= len(argv) {
					return result, invalid("a command wrapper option has no value")
				}
				index++
			} else if !contains([]string{"-p", "-v", "-V"}, option) || name != "command" {
				return result, invalid("a command wrapper option cannot be resolved")
			}
		}
		// env options affect the wrapped child, so they do not mark persistent
		// shell state. normalise checks execution-context and output changes.
		if name == "timeout" {
			if index >= len(argv) {
				return result, invalid("a timeout wrapper has no duration")
			}
			index++
		}
		argv = argv[index:]
	}
	return result, invalid("a command has too many wrappers")
}

// Bash printf also assigns a variable with %n, without a -v option.
func printfState(arguments []string) bool {
	for len(arguments) > 0 && strings.HasPrefix(arguments[0], "-") {
		if strings.HasPrefix(arguments[0], "-v") {
			return true
		}
		option := arguments[0]
		arguments = arguments[1:]
		if option == "--" {
			break
		}
	}
	if len(arguments) == 0 {
		return false
	}
	format := arguments[0]
	for index := 0; index < len(format); index++ {
		if format[index] != '%' {
			continue
		}
		index++
		if index < len(format) && format[index] == '%' {
			continue
		}
		for index < len(format) && strings.ContainsRune("-+ #0'0123456789.*hlLjzt", rune(format[index])) {
			index++
		}
		if index < len(format) && format[index] == 'n' {
			return true
		}
	}
	return false
}
