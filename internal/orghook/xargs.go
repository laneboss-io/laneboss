package orghook

import (
	"path/filepath"
	"strings"
)

type xargsInput struct {
	file string
	zero bool
	argv []string
}

func parseXargs(args []string) (xargsInput, bool) {
	spec := xargsInput{}
	for index := 0; index < len(args); index++ {
		arg := args[index]
		switch {
		case arg == "--":
			spec.argv = args[index+1:]
			return spec, len(spec.argv) > 0
		case arg == "-0" || arg == "--null":
			spec.zero = true
		case arg == "-r" || arg == "--no-run-if-empty" || arg == "-t" || arg == "--verbose":
		case arg == "-a" || arg == "--arg-file":
			index++
			if index >= len(args) {
				return spec, false
			}
			spec.file = args[index]
		case strings.HasPrefix(arg, "--arg-file="):
			spec.file = strings.TrimPrefix(arg, "--arg-file=")
		case strings.HasPrefix(arg, "-a") && len(arg) > 2:
			spec.file = arg[2:]
		case contains([]string{"-n", "-L", "-P", "-s", "--max-args", "--max-lines", "--max-procs", "--max-chars"}, arg):
			index++
			if index >= len(args) || !digits(args[index]) {
				return spec, false
			}
		case strings.HasPrefix(arg, "-"):
			return spec, false
		default:
			spec.argv = args[index:]
			return spec, len(spec.argv) > 0 && filepath.Base(spec.argv[0]) != "xargs"
		}
	}
	return spec, false
}

// xargs input is an argument list, not shell code: operators stay literal.
func xargsWords(text string, zero bool) ([]string, bool) {
	if zero {
		words := strings.Split(text, "\x00")
		if len(words) > 0 && words[len(words)-1] == "" {
			words = words[:len(words)-1]
		}
		return words, len(words) <= maxTokens
	}
	words := []string{}
	var word strings.Builder
	quote, active := byte(0), false
	flush := func() {
		if active {
			words = append(words, word.String())
			word.Reset()
			active = false
		}
	}
	for index := 0; index < len(text); index++ {
		c := text[index]
		if c == '\\' && quote == 0 {
			index++
			if index == len(text) {
				return nil, false
			}
			word.WriteByte(text[index])
			active = true
		} else if (c == '\'' || c == '"') && (quote == 0 || quote == c) {
			if quote == c {
				quote = 0
			} else {
				quote = c
			}
			active = true
		} else if quote == 0 && strings.ContainsRune(" \t\r\n", rune(c)) {
			flush()
		} else {
			word.WriteByte(c)
			active = true
		}
		if len(words) > maxTokens {
			return nil, false
		}
	}
	flush()
	return words, quote == 0 && len(words) <= maxTokens
}

func literalOutput(words []string) (string, bool) {
	if len(words) < 2 {
		return "", false
	}
	for _, word := range words[1:] {
		if strings.ContainsAny(word, "$`") {
			return "", false
		}
	}
	switch filepath.Base(words[0]) {
	case "echo":
		if strings.HasPrefix(words[1], "-") {
			return "", false
		}
		return strings.Join(words[1:], " ") + "\n", true
	case "printf":
		format := words[1]
		var output strings.Builder
		argument := 2
		for {
			before := argument
			for index := 0; index < len(format); index++ {
				switch format[index] {
				case '%':
					index++
					if index >= len(format) {
						return "", false
					}
					if format[index] == '%' {
						output.WriteByte('%')
					} else if format[index] == 's' && argument < len(words) {
						output.WriteString(words[argument])
						argument++
					} else {
						return "", false
					}
				case '\\':
					index++
					if index >= len(format) {
						return "", false
					}
					escapes := map[byte]byte{'n': '\n', 'r': '\r', 't': '\t', '0': 0, '\\': '\\'}
					value, ok := escapes[format[index]]
					if !ok {
						return "", false
					}
					output.WriteByte(value)
				default:
					output.WriteByte(format[index])
				}
			}
			if argument == len(words) {
				return output.String(), true
			}
			if argument == before {
				return "", false
			}
		}
	}
	return "", false
}

func projectRawWriteCommands(act action, cwd string) action {
	directory := act.rawDirectory
	if directory == "" {
		directory = cwd
	}
	segments := rawShellSegments(act.raw, directory)
	if patch, _, ok := literalShellPatchSequence(act.raw); ok {
		if paths, err := patchPaths(patch); err == nil {
			act.commands = append(act.commands, command{argv: []string{"apply_patch"}, directory: directory, writes: paths, opaque: true})
		}
	}
	candidates := []string{directory}
	for index, segment := range segments {
		words := codeCommandWords(rawEffectWords(segment))
		if len(words) > 1 && contains([]string{"cd", "chdir", "pushd"}, filepath.Base(words[0])) && literalReadValue(words[1]) {
			if candidate, err := pathAt(words[1], segment.directory); err == nil {
				candidates = uniqueDirectories(append(candidates, candidate)...)
			}
		}
		if cmd, ok := literalWriteCommand(words, segment.directory); ok {
			cmd.directories = uniqueDirectories(append(candidates, segment.directory)...)
			act.commands = append(act.commands, cmd)
		}
		redirects := []string{}
		for _, target := range rawRedirectTargets(segment) {
			if literalReadValue(target) && !standardOutputTarget(target) {
				redirects = append(redirects, target)
			}
		}
		if len(redirects) > 0 {
			act.commands = append(act.commands, command{argv: words, directory: segment.directory,
				directories: uniqueDirectories(append(candidates, segment.directory)...), writes: redirects, opaque: true})
		}
		if len(words) == 0 || filepath.Base(words[0]) != "xargs" || index == 0 || segments[index-1].following != "|" {
			continue
		}
		spec, ok := parseXargs(words[1:])
		if !ok || spec.file != "" {
			continue
		}
		output, ok := literalOutput(codeCommandWords(rawCommandWords(segments[index-1])))
		if !ok {
			continue
		}
		items, ok := xargsWords(output, spec.zero)
		if !ok {
			continue
		}
		argv := append(append([]string{}, spec.argv...), items...)
		if cmd, ok := literalWriteCommand(argv, segment.directory); ok {
			cmd.opaque = true
			act.commands = append(act.commands, cmd)
		}
	}
	return act
}

// Called only after the initial deterministic policy pass checked every list
// file as a read, including secret names and explicit path denials.
func projectArgumentFileWrites(act action) (action, bool) {
	changed := false
	seen := map[string]bool{}
	for _, cmd := range act.commands {
		words := codeCommandWords(cmd.argv)
		if len(words) == 0 || filepath.Base(words[0]) != "xargs" {
			continue
		}
		spec, ok := parseXargs(words[1:])
		if !ok || !literalReadValue(spec.file) {
			continue
		}
		if _, known := literalWriteCommand(spec.argv, cmd.directory); !known {
			continue
		}
		path, err := pathAt(spec.file, cmd.directory)
		if err != nil {
			continue // An unresolved input remains an opaque observation.
		}
		key := path + "\x00" + strings.Join(spec.argv, "\x00")
		if seen[key] {
			continue
		}
		seen[key] = true
		data, err := readBytes(path, "xargs argument file")
		if err != nil {
			continue // No contents were available to infer a literal destination.
		}
		items, ok := xargsWords(string(data), spec.zero)
		if !ok {
			continue
		}
		argv := append(append([]string{}, spec.argv...), items...)
		if effect, ok := literalWriteCommand(argv, cmd.directory); ok {
			effect.opaque = true
			act.commands = append(act.commands, effect)
			changed = true
		}
	}
	return act, changed
}
