package laneturns

import (
	"math"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"laneboss.io/laneboss/internal/lane"
)

type shellToken struct{ kind, value string }

var shellOperators = []string{"&>>", "&>", "&&", "||", ";;", "|&", "<<<", "<<-", "<<", "<>", "<&", ">>", ">|", ">&", "<", ">", "&", "|", ";", "(", ")"}
var shellAssignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\+?=`)
var shellPathLike = regexp.MustCompile(`^[^\s=:]+\.[A-Za-z0-9]{1,8}$`)

func shellTokens(text string) []shellToken {
	text = cutText(text, 65536)
	found := []shellToken{}
	var word strings.Builder
	inWord := false
	type heredoc struct {
		end   string
		strip bool
	}
	docs := []heredoc{}
	flush := func() {
		if inWord {
			found = append(found, shellToken{"word", word.String()})
			word.Reset()
			inWord = false
		}
	}
	for i := 0; i < len(text) && len(found) < 10000; {
		ch := text[i]
		switch {
		case ch == '\\':
			if i+1 < len(text) && text[i+1] != '\n' {
				word.WriteByte(text[i+1])
				inWord = true
			}
			i += 2
		case ch == '\'' || ch == '$' && i+1 < len(text) && text[i+1] == '\'':
			start := i + 1
			if ch == '$' {
				start++
			}
			end := strings.IndexByte(text[start:], '\'')
			if end < 0 {
				end = len(text) - start
			}
			word.WriteString(text[start : start+end])
			inWord = true
			i = start + end + 1
		case ch == '"':
			j := i + 1
			for j < len(text) && text[j] != '"' {
				if text[j] == '\\' && j+1 < len(text) && strings.ContainsRune("\"\\$`\n", rune(text[j+1])) {
					if text[j+1] != '\n' {
						word.WriteByte(text[j+1])
					}
					j += 2
					continue
				}
				word.WriteByte(text[j])
				j++
			}
			inWord = true
			i = j + 1
		case ch == '$' && i+1 < len(text) && (text[i+1] == '(' || text[i+1] == '{'):
			opening := text[i+1]
			closing := byte(')')
			if opening == '{' {
				closing = '}'
			}
			depth := 0
			j := i + 1
			for j < len(text) {
				if text[j] == opening {
					depth++
				}
				if text[j] == closing {
					depth--
					if depth == 0 {
						j++
						break
					}
				}
				j++
			}
			word.WriteString(text[i:j])
			inWord = true
			i = j
		case ch == '`':
			end := strings.IndexByte(text[i+1:], '`')
			j := len(text)
			if end >= 0 {
				j = i + end + 2
			}
			word.WriteString(text[i:j])
			inWord = true
			i = j
		case ch == '#' && !inWord:
			end := strings.IndexByte(text[i:], '\n')
			if end < 0 {
				i = len(text)
			} else {
				i += end
			}
		case ch == ' ' || ch == '\t' || ch == '\r':
			flush()
			i++
		case ch == '\n':
			flush()
			found = append(found, shellToken{"op", "\n"})
			i++
			for _, doc := range docs {
				for i < len(text) {
					end := strings.IndexByte(text[i:], '\n')
					line := text[i:]
					if end >= 0 {
						line = text[i : i+end]
						i += end + 1
					} else {
						i = len(text)
					}
					if doc.strip {
						line = strings.TrimLeft(line, "\t")
					}
					if line == doc.end {
						break
					}
				}
			}
			docs = nil
		case strings.ContainsRune("<>&|;()", rune(ch)):
			prefix := ""
			if (ch == '<' || ch == '>') && inWord && allDigits(word.String()) {
				prefix = word.String()
				word.Reset()
				inWord = false
			}
			flush()
			operator := ""
			for _, candidate := range shellOperators {
				if strings.HasPrefix(text[i:], candidate) {
					operator = candidate
					break
				}
			}
			found = append(found, shellToken{"op", prefix + operator})
			i += len(operator)
			if operator == "<<" || operator == "<<-" {
				j := i
				for j < len(text) && (text[j] == ' ' || text[j] == '\t') {
					j++
				}
				end := j
				for end < len(text) && !unicode.IsSpace(rune(text[end])) && !strings.ContainsRune("<>&|;()", rune(text[end])) {
					end++
				}
				if end > j {
					delimiter := strings.NewReplacer("'", "", "\"", "", "\\", "").Replace(text[j:end])
					docs = append(docs, heredoc{delimiter, operator == "<<-"})
					found = append(found, shellToken{"word", delimiter})
					i = end
				}
			}
		default:
			word.WriteByte(ch)
			inWord = true
			i++
		}
	}
	flush()
	return found
}
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
func resolveShellPath(word, directory string) string {
	if word == "" || strings.Contains(word, "://") || strings.ContainsRune(word, 0) || shown(word) != word {
		return ""
	}
	for _, name := range []string{"$HOME", "${HOME}"} {
		if word == name || strings.HasPrefix(word, name+"/") {
			word = "~" + strings.TrimPrefix(word, name)
		}
	}
	if strings.ContainsAny(word, "$`") {
		return ""
	}
	if strings.HasPrefix(word, "~") {
		slash := strings.IndexByte(word, '/')
		head := word
		rest := ""
		if slash >= 0 {
			head = word[:slash]
			rest = word[slash+1:]
		}
		home := ""
		if head == "~" {
			home, _ = os.UserHomeDir()
		} else if account, err := user.Lookup(head[1:]); err == nil {
			home = account.HomeDir
		}
		if home == "" {
			return ""
		}
		word = filepath.Join(home, rest)
	}
	if !filepath.IsAbs(word) {
		if directory == "" {
			return ""
		}
		word = filepath.Join(directory, word)
	}
	path := filepath.Clean(word)
	if contains([]string{"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/stdin", "/dev/tty", "/dev/zero", "/dev/random", "/dev/urandom", "/dev/full"}, path) || strings.HasPrefix(path, "/dev/fd/") || strings.HasPrefix(path, "/proc/self/fd/") {
		return ""
	}
	return path
}
func shellOperands(args []string, takes []string) []string {
	found := []string{}
	options := true
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if options && arg == "--" {
			options = false
		} else if options && strings.HasPrefix(arg, "-") && arg != "-" {
			if contains(takes, arg) {
				i++
			}
		} else {
			found = append(found, arg)
		}
	}
	return found
}
func shellOptionValues(args []string, short, long string) []string {
	found := []string{}
	for i, arg := range args {
		if (arg == short || arg == long) && i+1 < len(args) {
			found = append(found, args[i+1])
		} else if strings.HasPrefix(arg, long+"=") {
			found = append(found, strings.TrimPrefix(arg, long+"="))
		}
	}
	return found
}

var shellWrappers = map[string][]string{"sudo": {"-u", "-g", "-h", "-p", "-C", "-D", "-r", "-t", "-T", "-U"}, "doas": {"-u", "-C"}, "env": {"-u", "-C", "-S", "--unset", "--chdir", "--split-string"}, "nohup": {}, "time": {"-f", "-o"}, "command": {}, "builtin": {}, "exec": {"-a"}, "nice": {"-n", "--adjustment"}, "timeout": {"-s", "-k", "--signal", "--kill-after"}, "stdbuf": {"-i", "-o", "-e"}, "noglob": {}}
var shellWriters = map[string][]string{"touch": {"-d", "-t", "-r", "--date", "--reference"}, "truncate": {"-s", "-r", "--size", "--reference"}, "rm": {}, "unlink": {}, "shred": {"-n", "-s", "--iterations", "--size"}, "tee": {}}

func unwrapShell(argv []string) []string {
	for n := 0; n < 8 && len(argv) > 0; n++ {
		name := filepath.Base(argv[0])
		takes, ok := shellWrappers[name]
		if !ok {
			break
		}
		argv = argv[1:]
		for len(argv) > 0 && (strings.HasPrefix(argv[0], "-") || name == "env" && shellAssignment.MatchString(argv[0])) {
			option := argv[0]
			argv = argv[1:]
			if option == "--" {
				break
			}
			if contains(takes, option) && len(argv) > 0 {
				argv = argv[1:]
			}
		}
		if name == "timeout" && len(argv) > 0 {
			argv = argv[1:]
		}
	}
	return argv
}
func shellWrites(name string, args []string, directory string) []string {
	if takes, ok := shellWriters[name]; ok {
		return shellOperands(args, takes)
	}
	if writes, copier := lane.CopierWriteCandidates(name, args, directory); copier {
		return writes
	}
	if name == "dd" {
		r := []string{}
		for _, arg := range args {
			if strings.HasPrefix(arg, "of=") {
				r = append(r, arg[3:])
			}
		}
		return r
	}
	if name == "curl" {
		return shellOptionValues(args, "-o", "--output")
	}
	if name == "wget" {
		return shellOptionValues(args, "-O", "--output-document")
	}
	if name == "sed" || name == "gsed" || name == "perl" {
		inplace := false
		for _, arg := range args {
			if arg == "--in-place" || strings.HasPrefix(arg, "--in-place=") {
				inplace = true
			}
			if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.Contains(strings.SplitN(arg[1:], ".", 2)[0], "i") && (name == "perl" || !strings.HasPrefix(arg, "-e")) {
				inplace = true
			}
		}
		if !inplace {
			return []string{}
		}
		scripts := []string{"-e", "-f", "--expression", "--file", "-E", "-l"}
		if name == "perl" {
			scripts = []string{"-e", "-E", "-M", "-I"}
		}
		files := shellOperands(args, scripts)
		given := false
		for _, arg := range args {
			if contains(scripts, arg) && arg != "-l" || strings.HasPrefix(arg, "--expression=") || strings.HasPrefix(arg, "--file=") {
				given = true
			}
		}
		if !given && len(files) > 0 {
			files = files[1:]
		}
		return files
	}
	return []string{}
}
func analyseShell(command, directory string) ([]string, []string) {
	writes, named := map[string]bool{}, map[string]bool{}
	add := func(where map[string]bool, word, dir string) {
		if path := resolveShellPath(word, dir); path != "" {
			where[path] = true
			named[path] = true
		}
	}
	simple := func(tokens []shellToken, here string) string {
		argv := []string{}
		for i := 0; i < len(tokens); i++ {
			token := tokens[i]
			if token.kind == "op" {
				if i+1 < len(tokens) && tokens[i+1].kind == "word" {
					op := strings.TrimLeft(token.value, "0123456789")
					target := tokens[i+1].value
					i++
					if contains([]string{">", ">>", ">|", "&>", "&>>", "<>"}, op) || op == ">&" && !allDigits(target) && target != "-" {
						add(writes, target, here)
					} else if op == "<" {
						add(named, target, here)
					}
				}
				continue
			}
			argv = append(argv, token.value)
		}
		for len(argv) > 0 && shellAssignment.MatchString(argv[0]) {
			argv = argv[1:]
		}
		argv = unwrapShell(argv)
		if len(argv) == 0 {
			return here
		}
		name := filepath.Base(argv[0])
		if name == "cd" || name == "pushd" {
			target := "~"
			for _, arg := range argv[1:] {
				if !strings.HasPrefix(arg, "-") {
					target = arg
					break
				}
			}
			if resolved := resolveShellPath(target, here); resolved != "" {
				return resolved
			}
			return here
		}
		for _, word := range shellWrites(name, argv[1:], here) {
			add(writes, word, here)
		}
		for _, word := range shellOperands(argv[1:], nil) {
			if !strings.HasPrefix(word, "-") && !strings.Contains(word, "://") && (strings.Contains(word, "/") || strings.HasPrefix(word, "~") || shellPathLike.MatchString(word)) {
				add(named, word, here)
			}
		}
		return here
	}
	outer := []string{}
	current := []shellToken{}
	for _, token := range append(shellTokens(command), shellToken{"op", "\n"}) {
		if token.kind == "op" && contains([]string{"\n", ";", ";;", "&", "&&", "||", "|", "|&", "(", ")"}, token.value) {
			if len(current) > 0 {
				directory = simple(current, directory)
				current = nil
			}
			if token.value == "(" {
				outer = append(outer, directory)
			} else if token.value == ")" && len(outer) > 0 {
				directory = outer[len(outer)-1]
				outer = outer[:len(outer)-1]
			}
		} else {
			current = append(current, token)
		}
	}
	return sortedSet(writes), sortedSet(named)
}
func sortedSet(set map[string]bool) []string {
	result := []string{}
	for s := range set {
		result = append(result, s)
	}
	sort.Strings(result)
	return result
}
func shellShingles(text string) map[string]bool {
	squashed := strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return unicode.ToLower(r)
		}
		return -1
	}, cutText(text, 65536))
	r := []rune(cutText(squashed, 16384))
	set := map[string]bool{}
	if len(r) < 5 {
		if len(r) > 0 {
			set[string(r)] = true
		}
		return set
	}
	for i := 0; i+5 <= len(r); i++ {
		set[string(r[i:i+5])] = true
	}
	return set
}
func shellSimilarity(later, refused map[string]bool) object {
	if len(later) == 0 || len(refused) == 0 {
		return nil
	}
	shared := 0
	for s := range later {
		if refused[s] {
			shared++
		}
	}
	containment := float64(shared) / float64(len(later))
	coverage := float64(shared) / float64(len(refused))
	if containment >= 0.8 && (coverage >= 0.8 || coverage >= 0.2 && shared >= 20 || shared >= 200) {
		return object{"containment": math.Round(containment*1000) / 1000, "coverage": math.Round(coverage*1000) / 1000}
	}
	return nil
}
