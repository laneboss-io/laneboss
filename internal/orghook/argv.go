package orghook

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const maxCommand = 64 * 1024
const maxTokens = 10000

type command struct {
	argv          []string
	directory     string
	writes, reads []string
	opaque        bool
}
type shellToken struct {
	word     string
	operator bool
}

var assignment = regexp.MustCompile(`(?s)^[A-Za-z_][A-Za-z0-9_]*=.*$`)
var wrappers = map[string][]string{
	"sudo": {"-u", "-g", "-h", "-p", "-C", "-D", "-r", "-t", "-T", "-U"}, "doas": {"-u", "-C"},
	"env": {"-u", "-C", "-S", "--unset", "--chdir", "--split-string"}, "nohup": {}, "time": {"-f", "-o"},
	"command": {}, "builtin": {}, "exec": {"-a"}, "nice": {"-n", "--adjustment"},
	"timeout": {"-s", "-k", "--signal", "--kill-after"}, "stdbuf": {"-i", "-o", "-e"}, "noglob": {},
}
var copiers = map[string][]string{
	"cp": {"-t", "-S", "--target-directory", "--suffix"}, "mv": {"-t", "-S", "--target-directory", "--suffix"},
	"ln":      {"-t", "-S", "--target-directory", "--suffix"},
	"install": {"-m", "-o", "-g", "-t", "-S", "--mode", "--owner", "--group", "--target-directory"},
	"rsync":   {"-e", "--rsh", "--exclude", "--include", "--filter", "-f"},
}

type copierOptionSpec struct {
	flags                             string
	longFlags, values, optionalValues []string
}

// Only options with understood file effects are supported. Backup, suffix,
// parents, hardlink and external-program modes need dedicated adapters.
var copierOptions = map[string]copierOptionSpec{
	"cp": {
		flags: "adfHiLnPpRrTuvxZ",
		longFlags: []string{"--archive", "--attributes-only", "--copy-contents", "--dereference", "--force",
			"--interactive", "--no-clobber", "--no-dereference", "--no-target-directory",
			"--one-file-system", "--recursive", "--remove-destination", "--strip-trailing-slashes",
			"--verbose", "--help", "--version", "--debug"},
		values:         []string{"--target-directory", "--no-preserve", "--sparse"},
		optionalValues: []string{"--context", "--preserve", "--reflink", "--update"},
	},
	"mv": {
		flags: "finTuvZ",
		longFlags: []string{"--force", "--interactive", "--no-clobber", "--no-target-directory",
			"--strip-trailing-slashes", "--verbose", "--help", "--version", "--context",
			"--no-copy", "--debug"},
		values:         []string{"--target-directory"},
		optionalValues: []string{"--update"},
	},
	"install": {
		flags:          "cpvZ",
		longFlags:      []string{"--preserve-timestamps", "--verbose", "--help", "--version", "--no-target-directory"},
		values:         []string{"-m", "-o", "-g", "--target-directory", "--mode", "--owner", "--group"},
		optionalValues: []string{"--context"},
	},
}

type copierShortAritySpec struct {
	gnuFlags, gnuValues, bsdGetopt string
}

// GNU: coreutils declarations in copiers and the original copierOptions.
// BSD: macOS /usr/bin/{cp,mv,install} getopt strings supplied by the review.
// A short value option is inspectable only when both vendors require its value.
var copierShortArity = map[string]copierShortAritySpec{
	"cp":      {"adfHiLnPpRrTuvxZ", "St", "HLPRacfilNnprSsvXx"},
	"mv":      {"finTuvZ", "St", "fhinv"},
	"install": {"cDpvTZ", "gmotS", "B:bCcD:df:g:h:l:M:m:N:o:pSsT:Uv"},
}

func copierShortValueArity(name string, letter byte) (bool, bool) {
	source := copierShortArity[name]
	position := strings.IndexByte(source.bsdGetopt, letter)
	bsdValue := position >= 0 && position+1 < len(source.bsdGetopt) && source.bsdGetopt[position+1] == ':'
	return strings.IndexByte(source.gnuValues, letter) >= 0, bsdValue
}

var operandWriters = map[string][]string{
	"touch": {"-d", "-t", "-r", "--date", "--reference"}, "truncate": {"-s", "-r", "--size", "--reference"},
	"rm": {}, "unlink": {}, "shred": {"-n", "-s", "--iterations", "--size"}, "tee": {},
}
var readers = []string{"cat", "head", "tail", "wc", "sort", "uniq", "cut", "grep", "rg", "find", "ls", "stat", "file", "readlink", "realpath", "diff", "cmp", "od", "xxd", "base64", "sha256sum", "shasum"}
var searchOptions = []string{"-e", "--regexp", "-f", "--file", "-g", "--glob", "--iglob", "--type", "-t", "--type-not", "-T", "--encoding", "--threads", "--max-count", "-m", "--context", "-A", "-B", "-C", "--after-context", "--before-context", "--exclude", "--include", "--exclude-dir"}
var readerOptions = map[string][]string{
	"head": {"-n", "-c", "--lines", "--bytes"}, "tail": {"-n", "-c", "--lines", "--bytes", "--pid", "-s"},
	"sort": {"-o", "--output", "-k", "--key", "-t", "--field-separator", "-S", "--buffer-size", "--parallel", "-T", "--temporary-directory"},
	"uniq": {"-f", "-s", "-w", "--skip-fields", "--skip-chars", "--check-chars"},
	"cut":  {"-b", "-c", "-d", "-f", "--bytes", "--characters", "--delimiter", "--fields", "--output-delimiter"},
	"rg":   searchOptions, "grep": searchOptions, "stat": {"-c", "--format", "--printf"},
	"file": {"-f", "--files-from", "-m", "--magic-file", "-F", "-e"}, "od": {"-A", "-j", "-N", "-t", "-w"},
	"xxd": {"-c", "-g", "-l", "-s", "-o"}, "shasum": {"-a", "--algorithm"},
}
var gitReadOnly = []string{"status", "log", "rev-parse", "rev-list", "ls-files", "ls-tree", "show", "diff", "grep", "describe", "remote"}
var gitWriters = []string{"add", "commit", "checkout", "switch", "restore", "reset", "clean", "merge", "rebase", "cherry-pick", "revert", "fetch", "pull", "push", "stash", "tag", "branch", "init"}

// lexShell retains the distinction between quoted words and operators. It never expands text.
func lexShell(text string) ([]shellToken, error) {
	if len(text) > maxCommand || strings.ContainsRune(text, 0) {
		return nil, invalid("a shell command exceeds the inspection limit or contains NUL")
	}
	result := []shellToken{}
	var word strings.Builder
	active := false
	flush := func() {
		if active {
			result = append(result, shellToken{word: word.String()})
			word.Reset()
			active = false
		}
	}
	for i := 0; i < len(text); {
		if len(result) >= maxTokens {
			return nil, invalid("a shell command exceeds the token limit")
		}
		c := text[i]
		if c == '\\' {
			if i+1 >= len(text) {
				return nil, invalid("a shell command has broken quoting")
			}
			if text[i+1] != '\n' {
				word.WriteByte(text[i+1])
				active = true
			}
			i += 2
			continue
		}
		if c == '$' && i+1 < len(text) && text[i+1] == '\'' {
			return nil, invalid("ANSI-C shell quoting cannot be inspected")
		}
		if c == '\'' || c == '"' {
			quote := c
			active = true
			i++
			closed := false
			for i < len(text) {
				if text[i] == quote {
					closed = true
					i++
					break
				}
				if quote == '"' && text[i] == '\\' && i+1 < len(text) && strings.ContainsRune("\"\\$`\n", rune(text[i+1])) {
					if text[i+1] != '\n' {
						word.WriteByte(text[i+1])
					}
					i += 2
					continue
				}
				word.WriteByte(text[i])
				i++
			}
			if !closed {
				return nil, invalid("a shell command has broken quoting")
			}
			continue
		}
		if c == '#' && !active {
			for i < len(text) && text[i] != '\n' {
				i++
			}
			continue
		}
		if c == ' ' || c == '\t' || c == '\r' {
			flush()
			i++
			continue
		}
		if c == '\n' {
			flush()
			result = append(result, shellToken{word: "\n", operator: true})
			i++
			continue
		}
		if strings.ContainsRune("<>&|;()", rune(c)) {
			prefix := ""
			if (c == '<' || c == '>') && active && digits(word.String()) {
				prefix = word.String()
				word.Reset()
				active = false
			}
			flush()
			op := string(c)
			for _, candidate := range []string{"&>>", "<<<", "<<-", "&>", "&&", "||", ";;", "|&", "<<", "<>", "<&", ">>", ">|", ">&"} {
				if strings.HasPrefix(text[i:], candidate) {
					op = candidate
					break
				}
			}
			result = append(result, shellToken{word: prefix + op, operator: true})
			i += len(op)
			continue
		}
		word.WriteByte(c)
		active = true
		i++
	}
	flush()
	if len(result) >= maxTokens {
		return nil, invalid("a shell command exceeds the token limit")
	}
	return result, nil
}

func digits(word string) bool {
	if word == "" {
		return false
	}
	for _, c := range word {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
func splitWords(text string) ([]string, error) {
	tokens, err := lexShell(text)
	if err != nil {
		return nil, err
	}
	words := []string{}
	for _, token := range tokens {
		if token.operator {
			return nil, invalid("a runner or hook command needs literal argv")
		}
		words = append(words, token.word)
	}
	return words, nil
}

func operands(arguments, takes []string) []string {
	result := []string{}
	options := true
	for i := 0; i < len(arguments); i++ {
		argument := arguments[i]
		if options && argument == "--" {
			options = false
		} else if options && strings.HasPrefix(argument, "-") && argument != "-" {
			if contains(takes, argument) {
				i++
			}
		} else {
			result = append(result, argument)
		}
	}
	return result
}

func optionValues(arguments []string, short, long string) []string {
	result := []string{}
	for i := 0; i < len(arguments); i++ {
		argument := arguments[i]
		if argument == "--" {
			break
		}
		if argument == short || argument == long {
			if i+1 < len(arguments) {
				result = append(result, arguments[i+1])
				i++
			}
		} else if strings.HasPrefix(argument, long+"=") {
			result = append(result, strings.TrimPrefix(argument, long+"="))
		} else if len(short) == 2 && strings.HasPrefix(argument, short) && len(argument) > 2 {
			result = append(result, argument[2:])
		}
	}
	return result
}

// A value-taking short option may be separate or first with a joined value.
// Flag-only clusters are supported; clusters mixing flags and values are opaque.
// Long options require exact names, and consumed values are never rescanned.
// A terminator must precede the first operand; positional copies need two operands.
func copierOperands(name string, arguments []string) ([]string, []string, bool) {
	spec, exists := copierOptions[name]
	if !exists { // ln and rsync need dedicated file-effects adapters.
		return nil, nil, false
	}
	files, target := []string{}, []string{}
	for index := 0; index < len(arguments); {
		argument := arguments[index]
		index++
		if argument == "--" {
			if len(files) > 0 {
				return nil, nil, false
			}
			files = append(files, arguments[index:]...)
			break
		}
		// BSD getopt stops at the first operand; GNU may permute later options.
		if len(files) > 0 && strings.HasPrefix(argument, "-") {
			return nil, nil, false
		}
		option, value := "", ""
		if strings.HasPrefix(argument, "--") {
			var joined bool
			option, value, joined = strings.Cut(argument, "=")
			if contains(spec.longFlags, option) {
				if joined {
					return nil, nil, false
				}
				continue
			}
			if contains(spec.optionalValues, option) {
				if !joined {
					continue
				}
			} else if !contains(spec.values, option) {
				return nil, nil, false
			} else if !joined {
				if index >= len(arguments) {
					return nil, nil, false
				}
				value = arguments[index]
				index++
			}
		} else if strings.HasPrefix(argument, "-") && argument != "-" {
			option, value = argument[:2], argument[2:]
			gnuValue, bsdValue := copierShortValueArity(name, argument[1])
			if gnuValue != bsdValue {
				return nil, nil, false
			}
			if !contains(spec.values, option) {
				for _, flag := range argument[1:] {
					gnuFlagValue, bsdFlagValue := copierShortValueArity(name, byte(flag))
					if !strings.ContainsRune(spec.flags, flag) || gnuFlagValue || bsdFlagValue {
						return nil, nil, false
					}
				}
				continue
			}
			if len(argument) == 2 {
				if index >= len(arguments) {
					return nil, nil, false
				}
				value = arguments[index]
				index++
			}
		} else {
			files = append(files, argument)
			continue
		}
		if value == "" || strings.ContainsAny(value, "$`*?[]{}") || strings.HasPrefix(value, "~") || hasControl(value) {
			return nil, nil, false
		}
		if option == "-t" || option == "--target-directory" {
			if len(target) > 0 {
				return nil, nil, false
			}
			target = append(target, value)
		}
	}
	if len(target) == 0 && len(files) < 2 {
		return nil, nil, false
	}
	sources := files
	if len(target) == 0 {
		sources = files[:len(files)-1]
	}
	// BSD cp copies a slash-ended directory's contents, unlike GNU cp.
	if name == "cp" {
		for _, source := range sources {
			if strings.HasSuffix(source, "/") {
				return nil, nil, false
			}
		}
	}
	return files, target, true
}

func standardExecutable(word string) bool {
	if !strings.Contains(word, "/") {
		return true
	}
	// Cleaning '..' before checking an executable can hide a symlink traversal.
	return word == filepath.Clean(word) && (filepath.Dir(word) == "/bin" || filepath.Dir(word) == "/usr/bin")
}

func normalise(argv []string, directory string, depth int) ([]string, string, []command, error) {
	argv = append([]string(nil), argv...)
	if len(argv) > 0 && assignment.MatchString(argv[0]) {
		return nil, "", nil, invalid("command environment assignments cannot be inspected")
	}
	for count := 0; count < 8; count++ {
		if len(argv) == 0 {
			return nil, "", nil, invalid("a command has no executable")
		}
		name := filepath.Base(argv[0])
		takes, wrapper := wrappers[name]
		if !wrapper {
			break
		}
		if !standardExecutable(argv[0]) {
			return nil, "", nil, invalid("a command wrapper is not a standard system executable")
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
					return nil, "", nil, invalid("a command wrapper option has no value")
				}
				index++
			}
		}
		if name == "timeout" {
			index++
		}
		if index > len(argv) {
			return nil, "", nil, invalid("a command wrapper has no executable")
		}
		options := argv[1:index]
		if name == "env" && index < len(argv) && assignment.MatchString(argv[index]) {
			return nil, "", nil, invalid("command environment assignments cannot be inspected")
		}
		for _, option := range options {
			if contains([]string{"env", "sudo", "doas"}, name) && (contains([]string{"-C", "-D", "-S", "--chdir", "--split-string"}, option) || strings.HasPrefix(option, "--chdir=") || strings.HasPrefix(option, "--split-string=")) {
				return nil, "", nil, invalid("a command wrapper changes execution context")
			}
			if name == "time" && (option == "-o" || strings.HasPrefix(option, "--output")) {
				return nil, "", nil, invalid("a command wrapper's output files cannot be inspected")
			}
			if contains([]string{"sudo", "doas"}, name) && contains([]string{"-i", "--login", "-s", "--shell", "-E", "--preserve-env"}, option) {
				return nil, "", nil, invalid("a command wrapper changes execution context")
			}
		}
		if name == "nohup" {
			return nil, "", nil, invalid("a command wrapper's output files cannot be inspected")
		}
		argv = argv[index:]
	}
	if len(argv) == 0 {
		return nil, "", nil, invalid("a command has too many wrappers or no executable")
	}
	if _, exists := wrappers[filepath.Base(argv[0])]; exists {
		return nil, "", nil, invalid("a command has too many wrappers")
	}
	if !standardExecutable(argv[0]) {
		return argv, directory, nil, nil
	}
	argv[0] = filepath.Base(argv[0])
	for _, word := range argv {
		if strings.ContainsAny(word, "$`") {
			return nil, "", nil, invalid("command substitutions and variables cannot be inspected")
		}
	}
	if contains([]string{"sh", "bash", "zsh", "dash", "ksh"}, argv[0]) {
		if depth >= 4 {
			return nil, "", nil, invalid("a command has too many nested shells")
		}
		if len(argv) != 3 || !contains([]string{"-c", "-lc", "-cl"}, argv[1]) {
			return argv, directory, nil, nil
		}
		nested, err := inspectShell(argv[2], directory, depth+1)
		return argv, directory, nested, err
	}
	if argv[0] == "git" {
		index := 1
		for index < len(argv) && strings.HasPrefix(argv[index], "-") {
			option := argv[index]
			if contains([]string{"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env"}, option) {
				if index+1 >= len(argv) {
					return nil, "", nil, invalid("a Git global option has no value")
				}
				if option == "-c" || option == "--config-env" {
					return nil, "", nil, invalid("Git configuration overrides can execute uninspectable programs")
				}
				if option == "--git-dir" || option == "--work-tree" {
					return nil, "", nil, invalid("alternate Git repository paths cannot be inspected")
				}
				if option == "-C" {
					var err error
					directory, err = pathAt(argv[index+1], directory)
					if err != nil {
						return nil, "", nil, err
					}
				}
				index += 2
			} else if contains([]string{"--no-pager", "--paginate", "--bare", "--no-replace-objects", "--literal-pathspecs", "--glob-pathspecs", "--noglob-pathspecs", "--icase-pathspecs"}, option) {
				index++
			} else if strings.HasPrefix(option, "--config-env=") || strings.HasPrefix(option, "-c") {
				return nil, "", nil, invalid("Git configuration overrides can execute uninspectable programs")
			} else if strings.HasPrefix(option, "--git-dir=") || strings.HasPrefix(option, "--work-tree=") {
				return nil, "", nil, invalid("alternate Git repository paths cannot be inspected")
			} else if strings.HasPrefix(option, "--namespace=") {
				index++
			} else if strings.HasPrefix(option, "-C") && len(option) > 2 {
				var err error
				directory, err = pathAt(option[2:], directory)
				if err != nil {
					return nil, "", nil, err
				}
				index++
			} else {
				return nil, "", nil, invalid("an unsupported Git global option cannot be inspected")
			}
		}
		argv = append([]string{"git"}, argv[index:]...)
	}
	return argv, directory, nil, nil
}

func writtenBy(name string, arguments []string, directory string) []string {
	if takes, exists := operandWriters[name]; exists {
		return operands(arguments, takes)
	}
	if _, exists := copiers[name]; exists {
		files, target, supported := copierOperands(name, arguments)
		if !supported {
			return nil
		}
		result := []string{}
		if len(target) > 0 {
			for _, file := range files {
				result = append(result, joinPathWord(target[0], filepath.Base(strings.TrimRight(file, "/"))))
			}
			return result
		}
		if len(files) < 2 {
			return result
		}
		destination := files[len(files)-1]
		sources := files[:len(files)-1]
		resolved, err := pathAt(destination, directory)
		if len(sources) > 1 || strings.HasSuffix(destination, "/") || (err == nil && isDirectory(resolved)) {
			for _, source := range sources {
				result = append(result, joinPathWord(destination, filepath.Base(strings.TrimRight(source, "/"))))
			}
			return result
		}
		return []string{destination}
	}
	if name == "dd" {
		result := []string{}
		for _, argument := range arguments {
			if strings.HasPrefix(argument, "of=") {
				result = append(result, argument[3:])
			}
		}
		return result
	}
	return nil
}

// Do not clean a raw destination: a symlink followed by '..' must resolve before containment.
func joinPathWord(directory, name string) string {
	return strings.TrimRight(directory, "/") + "/" + name
}

func inspectArgv(argv []string, directory string, depth int) ([]command, error) {
	if len(argv) == 0 || len(argv) > maxTokens {
		return nil, invalid("command argv must be a nonempty array of words")
	}
	size := 0
	for _, word := range argv {
		if word == "" || strings.ContainsRune(word, 0) {
			return nil, invalid("command argv must be a nonempty array of words")
		}
		size += len(word)
	}
	if size > maxCommand {
		return nil, invalid("a command exceeds the inspection limit")
	}
	argv, directory, nested, err := normalise(argv, directory, depth)
	if err != nil {
		return nil, err
	}
	if nested != nil {
		return append([]command{{argv: argv, directory: directory}}, nested...), nil
	}
	name, arguments := argv[0], argv[1:]
	var copierFiles, copierTarget []string
	if _, copier := copiers[name]; copier {
		var supported bool
		copierFiles, copierTarget, supported = copierOperands(name, arguments)
		if !supported {
			return []command{{argv: argv, directory: directory, opaque: true}}, nil
		}
	}
	writes := writtenBy(name, arguments, directory)
	reads := []string{}
	_, writer := operandWriters[name]
	_, copier := copiers[name]
	known := standardExecutable(name) && (contains([]string{"echo", "printf", "pwd", "true", "false", ":"}, name) || contains(readers, name) || writer || copier || contains([]string{"dd", "mkdir", "rmdir", "chmod", "chown", "chgrp", "cd", "pushd"}, name))
	if name == "mv" {
		files := copierFiles
		// A target option makes every operand a source, including the last one.
		if len(copierTarget) > 0 {
			writes = append(writes, files...)
		} else if len(files) > 0 {
			writes = append(writes, files[:len(files)-1]...)
		}
	}
	if name == "sort" {
		writes = append(writes, optionValues(arguments, "-o", "--output")...)
		writes = append(writes, optionValues(arguments, "-T", "--temporary-directory")...)
		for _, word := range arguments {
			if word == "--compress-program" || strings.HasPrefix(word, "--compress-program=") {
				known = false
			}
		}
	}
	if name == "uniq" {
		files := operands(arguments, readerOptions[name])
		if len(files) > 1 {
			writes = append(writes, files[1])
		}
	}
	if name == "xxd" && (contains(arguments, "-r") || len(operands(arguments, readerOptions[name])) > 1) {
		known = false
	}
	if name == "find" {
		for _, word := range arguments {
			if contains([]string{"-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprintf", "-fls", "-fprint0"}, word) {
				known = false
			}
		}
	}
	if name == "rg" {
		for _, word := range arguments {
			if word == "--pre" || strings.HasPrefix(word, "--pre=") {
				known = false
			}
		}
	}
	if name == "file" && (contains(arguments, "-C") || contains(arguments, "--compile")) {
		known = false
	}
	if contains([]string{"mkdir", "rmdir", "chmod", "chown", "chgrp"}, name) {
		writes = operands(arguments, nil)
		if name == "chmod" || name == "chown" || name == "chgrp" {
			if len(writes) > 0 {
				writes = writes[1:]
			}
			for _, word := range arguments {
				if strings.HasPrefix(word, "--reference") {
					known = false
				}
			}
		}
	}
	if name == "git" {
		subcommand := ""
		if len(arguments) > 0 {
			subcommand = arguments[0]
		}
		known = contains(gitReadOnly, subcommand) || contains(gitWriters, subcommand)
		if contains(gitWriters, subcommand) {
			repository := directory
			for parent := directory; ; parent = filepath.Dir(parent) {
				if _, err := os.Stat(filepath.Join(parent, ".git")); err == nil {
					repository = parent
					break
				}
				if filepath.Dir(parent) == parent {
					break
				}
			}
			writes = append(writes, repository)
			if regular(filepath.Join(repository, ".git")) {
				known = false
			}
		}
		if contains([]string{"diff", "show", "grep"}, subcommand) {
			for _, word := range operands(arguments[1:], nil) {
				if strings.ContainsAny(word, "/.") {
					if index := strings.IndexByte(word, ':'); index >= 0 {
						word = word[index+1:]
					}
					reads = append(reads, word)
				}
			}
			known = known && len(reads) > 0
		}
		if subcommand == "remote" && len(arguments) > 1 {
			known = contains([]string{"get-url", "show"}, arguments[1])
		}
		for _, word := range arguments {
			if contains([]string{"--exec", "--textconv", "--ext-diff", "--output", "--upload-pack", "--receive-pack"}, word) || strings.HasPrefix(word, "--exec=") || strings.HasPrefix(word, "--output=") || strings.HasPrefix(word, "--upload-pack=") || strings.HasPrefix(word, "--receive-pack=") {
				known = false
			}
		}
	}
	if contains(readers, name) {
		files := operands(arguments, readerOptions[name])
		if name == "rg" || name == "grep" {
			pattern := len(optionValues(arguments, "-e", "--regexp")) > 0 || len(optionValues(arguments, "-f", "--file")) > 0
			if !pattern && len(files) > 0 {
				files = files[1:]
			}
			reads = append(reads, optionValues(arguments, "-f", "--file")...)
			if len(files) == 0 {
				files = []string{directory}
			}
		}
		if name == "file" {
			reads = append(reads, optionValues(arguments, "-f", "--files-from")...)
			reads = append(reads, optionValues(arguments, "-m", "--magic-file")...)
		}
		if name == "find" {
			for _, word := range arguments {
				if strings.HasPrefix(word, "-") && !contains([]string{"-H", "-L", "-P"}, word) {
					known = false
				}
			}
			if len(files) == 0 {
				files = []string{directory}
			}
		}
		for _, word := range files {
			if word != "-" && !strings.Contains(word, "://") {
				reads = append(reads, word)
			}
		}
	} else if copier {
		files := copierFiles
		if len(copierTarget) == 0 && len(files) > 0 {
			files = files[:len(files)-1]
		}
		reads = append(reads, files...)
	} else if name == "dd" {
		for _, word := range arguments {
			if strings.HasPrefix(word, "if=") {
				reads = append(reads, word[3:])
			}
		}
	}
	return []command{{argv: argv, directory: directory, writes: writes, reads: reads, opaque: !known}}, nil
}

func inspectShell(text, directory string, depth int) ([]command, error) {
	if strings.TrimSpace(text) == "" || len(text) > maxCommand || strings.ContainsRune(text, 0) {
		return nil, invalid("a shell command is empty, invalid or exceeds the inspection limit")
	}
	tokens, err := lexShell(strings.TrimRight(text, " \t\r\n"))
	if err != nil {
		return nil, err
	}
	commands := []command{}
	current := []shellToken{}
	stack := []string{}
	connectors := []string{}
	needsCommand, changedDirectory := false, false
	finish := func() error {
		if len(current) == 0 {
			return nil
		}
		argv, writes, reads := []string{}, []string{}, []string{}
		for index := 0; index < len(current); {
			token := current[index]
			if !token.operator {
				argv = append(argv, token.word)
				index++
				continue
			}
			op := strings.TrimLeft(token.word, "0123456789")
			if !contains([]string{"<", ">", ">>", ">|", "<>", "&>", "&>>", "<&", ">&"}, op) || index+1 >= len(current) || current[index+1].operator {
				return invalid("a shell redirection cannot be inspected")
			}
			target := current[index+1].word
			if contains([]string{">", ">>", ">|", "<>", "&>", "&>>"}, op) || (op == ">&" && !digits(target) && target != "-") {
				writes = append(writes, target)
			}
			if op == "<" || op == "<>" {
				reads = append(reads, target)
			}
			if op == "<&" && !digits(target) && target != "-" {
				return invalid("an input descriptor redirection cannot be inspected")
			}
			index += 2
		}
		if len(argv) > 0 {
			inspected, err := inspectArgv(argv, directory, depth)
			if err != nil {
				return err
			}
			commands = append(commands, command{argv: inspected[0].argv, directory: directory, writes: writes, reads: reads})
			commands = append(commands, inspected...)
			if contains([]string{"cd", "pushd"}, inspected[0].argv[0]) {
				files := operands(inspected[0].argv[1:], nil)
				if len(files) != 1 {
					return invalid("a directory change needs one literal directory")
				}
				directory, err = pathAt(files[0], directory)
				if err != nil {
					return err
				}
				if !isDirectory(directory) {
					return invalid("a directory change needs an existing directory")
				}
				changedDirectory = true
			}
		} else {
			commands = append(commands, command{directory: directory, writes: writes, reads: reads})
		}
		current = nil
		return nil
	}
	for _, token := range tokens {
		value := token.word
		if token.operator && contains([]string{"\n", ";", "&", "&&", "||", "|", "|&", "(", ")"}, value) {
			if value == "\n" && len(current) > 0 {
				connectors = append(connectors, value)
			}
			if contains([]string{"&&", "||", "|", "|&", "&", ";"}, value) {
				if len(current) == 0 {
					return nil, invalid("a shell operator has no preceding command")
				}
				connectors = append(connectors, value)
			}
			if value == "(" && len(current) > 0 {
				return nil, invalid("a subshell must start at a command boundary")
			}
			if value == ")" && needsCommand {
				return nil, invalid("a subshell has an incomplete command")
			}
			if err := finish(); err != nil {
				return nil, err
			}
			if value != "\n" {
				needsCommand = contains([]string{"&&", "||", "|", "|&", "("}, value)
			}
			if value == "(" {
				stack = append(stack, directory)
			} else if value == ")" {
				if len(stack) == 0 {
					return nil, invalid("a shell command has unmatched parentheses")
				}
				directory = stack[len(stack)-1]
				stack = stack[:len(stack)-1]
			}
		} else {
			current = append(current, token)
			needsCommand = false
		}
	}
	if err := finish(); err != nil {
		return nil, err
	}
	if len(stack) > 0 || len(commands) == 0 || needsCommand {
		return nil, invalid("a shell command is incomplete")
	}
	if changedDirectory {
		for _, op := range connectors {
			if op != "&&" {
				return nil, invalid("directory changes are supported only in an && chain")
			}
		}
	}
	return commands, nil
}
