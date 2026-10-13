package lane

import (
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

type shellToken struct {
	op   bool
	text string
}

func cutText(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}
func shellTokens(text string) []shellToken {
	text = cutText(text, 65536)
	found := []shellToken{}
	word := ""
	inWord := false
	type heredoc struct {
		delimiter string
		strip     bool
	}
	docs := []heredoc{}
	flush := func() {
		if inWord {
			found = append(found, shellToken{false, word})
			word = ""
			inWord = false
		}
	}
	for i := 0; i < len(text) && len(found) < 10000; {
		c := text[i]
		if c == '\\' {
			if i+1 < len(text) && text[i+1] != '\n' {
				word += text[i+1 : i+2]
				inWord = true
			}
			i += 2
			continue
		}
		if c == '\'' || (c == '$' && i+1 < len(text) && text[i+1] == '\'') {
			start := i + 1
			if c == '$' {
				start++
			}
			end := strings.IndexByte(text[start:], '\'')
			if end < 0 {
				end = len(text)
			} else {
				end += start
			}
			word += text[start:end]
			inWord = true
			i = end + 1
			continue
		}
		if c == '"' {
			j := i + 1
			for j < len(text) && text[j] != '"' {
				if text[j] == '\\' && j+1 < len(text) && strings.ContainsRune("\"\\$`\n", rune(text[j+1])) {
					if text[j+1] != '\n' {
						word += text[j+1 : j+2]
					}
					j += 2
				} else {
					word += text[j : j+1]
					j++
				}
			}
			inWord = true
			i = j + 1
			continue
		}
		if c == '$' && i+1 < len(text) && (text[i+1] == '(' || text[i+1] == '{') {
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
			word += text[i:j]
			inWord = true
			i = j
			continue
		}
		if c == '`' {
			end := strings.IndexByte(text[i+1:], '`')
			if end < 0 {
				end = len(text) - 1
			} else {
				end += i + 1
			}
			word += text[i : end+1]
			inWord = true
			i = end + 1
			continue
		}
		if c == '#' && !inWord {
			end := strings.IndexByte(text[i:], '\n')
			if end < 0 {
				break
			}
			i += end
			continue
		}
		if strings.ContainsRune(" \t\r", rune(c)) {
			flush()
			i++
			continue
		}
		if c == '\n' {
			flush()
			found = append(found, shellToken{true, "\n"})
			i++
			for _, doc := range docs {
				for i < len(text) {
					end := strings.IndexByte(text[i:], '\n')
					if end < 0 {
						end = len(text)
					} else {
						end += i
					}
					line := text[i:end]
					i = end + 1
					if doc.strip {
						line = strings.TrimLeft(line, "\t")
					}
					if line == doc.delimiter {
						break
					}
				}
			}
			docs = nil
			continue
		}
		if strings.ContainsRune("<>&|;()", rune(c)) {
			prefix := ""
			if (c == '<' || c == '>') && inWord && match(`[0-9]+`, word) {
				prefix = word
				word = ""
				inWord = false
			}
			flush()
			operator := text[i : i+1]
			for _, op := range []string{"&>>", "&>", "&&", "||", ";;", "|&", "<<<", "<<-", "<<", "<>", "<&", ">>", ">|", ">&"} {
				if strings.HasPrefix(text[i:], op) {
					operator = op
					break
				}
			}
			found = append(found, shellToken{true, prefix + operator})
			i += len(operator)
			if operator == "<<" || operator == "<<-" {
				for i < len(text) && (text[i] == ' ' || text[i] == '\t') {
					i++
				}
				start := i
				for i < len(text) && !strings.ContainsRune(" \t\r\n<>&|;()", rune(text[i])) {
					i++
				}
				if i > start {
					delimiter := strings.NewReplacer("'", "", "\"", "", "\\", "").Replace(text[start:i])
					docs = append(docs, heredoc{delimiter, operator == "<<-"})
					found = append(found, shellToken{false, delimiter})
				}
			}
			continue
		}
		word += text[i : i+1]
		inWord = true
		i++
	}
	flush()
	return found
}
func expandHome(s string) string {
	if s == "~" || strings.HasPrefix(s, "~/") {
		home, _ := os.UserHomeDir()
		return home + strings.TrimPrefix(s, "~")
	}
	if strings.HasPrefix(s, "~") {
		name, tail, _ := strings.Cut(s[1:], "/")
		u, err := user.Lookup(name)
		if err == nil {
			return filepath.Join(u.HomeDir, tail)
		}
	}
	return s
}
func shellResolve(word, directory string) string {
	if word == "" || strings.Contains(word, "\x00") || strings.Contains(word, "://") || strings.IndexFunc(word, func(r rune) bool { return r < 32 }) >= 0 {
		return ""
	}
	for _, prefix := range []string{"$HOME", "${HOME}"} {
		if word == prefix || strings.HasPrefix(word, prefix+"/") {
			word = "~" + strings.TrimPrefix(word, prefix)
		}
	}
	if strings.ContainsAny(word, "$`") {
		return ""
	}
	word = expandHome(word)
	if strings.HasPrefix(word, "~") {
		return ""
	}
	if !filepath.IsAbs(word) {
		if directory == "" {
			return ""
		}
		word = filepath.Join(directory, word)
	}
	path := filepath.Clean(word)
	if contains(strings.Fields("/dev/null /dev/stdout /dev/stderr /dev/stdin /dev/tty /dev/zero /dev/random /dev/urandom /dev/full"), path) || strings.HasPrefix(path, "/dev/fd/") || strings.HasPrefix(path, "/proc/self/fd/") {
		return ""
	}
	return path
}
func operands(a []string, takes string) []string {
	r := []string{}
	options := true
	for i := 0; i < len(a); i++ {
		s := a[i]
		if options && s == "--" {
			options = false
		} else if options && strings.HasPrefix(s, "-") && s != "-" {
			if contains(strings.Fields(takes), s) {
				i++
			}
		} else {
			r = append(r, s)
		}
	}
	return r
}
func optionValues(a []string, short, long string) []string {
	r := []string{}
	for i, s := range a {
		if (s == short || s == long) && i+1 < len(a) {
			r = append(r, a[i+1])
		} else if strings.HasPrefix(s, long+"=") {
			r = append(r, strings.TrimPrefix(s, long+"="))
		}
	}
	return r
}
func unwrap(a []string) []string {
	wrappers := map[string]string{"sudo": "-u -g -h -p -C -D -r -t -T -U", "doas": "-u -C", "env": "-u -C -S --unset --chdir --split-string", "nohup": "", "time": "-f -o", "command": "", "builtin": "", "exec": "-a", "nice": "-n --adjustment", "timeout": "-s -k --signal --kill-after", "stdbuf": "-i -o -e", "noglob": ""}
	for n := 0; n < 8 && len(a) > 0; n++ {
		name := filepath.Base(a[0])
		takes, ok := wrappers[name]
		if !ok {
			break
		}
		a = a[1:]
		for len(a) > 0 && (strings.HasPrefix(a[0], "-") || (name == "env" && regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\+?=`).MatchString(a[0]))) {
			option := a[0]
			a = a[1:]
			if option == "--" {
				break
			}
			if contains(strings.Fields(takes), option) && len(a) > 0 {
				a = a[1:]
			}
		}
		if name == "timeout" && len(a) > 0 {
			a = a[1:]
		}
	}
	return a
}
func writtenBy(name string, a []string, directory string) []string {
	writers := map[string]string{"touch": "-d -t -r --date --reference", "truncate": "-s -r --size --reference", "rm": "", "unlink": "", "shred": "-n -s --iterations --size", "tee": ""}
	if takes, ok := writers[name]; ok {
		return operands(a, takes)
	}
	if writes, copier := CopierWriteCandidates(name, a, directory); copier {
		return writes
	}
	if name == "dd" {
		r := []string{}
		for _, s := range a {
			if strings.HasPrefix(s, "of=") {
				r = append(r, s[3:])
			}
		}
		return r
	}
	if contains([]string{"sed", "gsed", "perl"}, name) {
		inPlace := false
		for _, s := range a {
			if s == "--in-place" || strings.HasPrefix(s, "--in-place=") || (strings.HasPrefix(s, "-") && !strings.HasPrefix(s, "--") && strings.Contains(strings.SplitN(strings.TrimPrefix(s, "-"), ".", 2)[0], "i") && (name == "perl" || !strings.HasPrefix(s, "-e"))) {
				inPlace = true
			}
		}
		if !inPlace {
			return nil
		}
		scripts := "-e -f --expression --file -E"
		if name == "perl" {
			scripts = "-e -E -M -I"
		}
		given := false
		for _, s := range a {
			if contains(strings.Fields(scripts), s) || strings.HasPrefix(s, "--expression=") || strings.HasPrefix(s, "--file=") {
				given = true
			}
		}
		takes := scripts
		if name != "perl" {
			takes += " -l"
		}
		files := operands(a, takes)
		if !given && len(files) > 0 {
			files = files[1:]
		}
		return files
	}
	if name == "curl" {
		return optionValues(a, "-o", "--output")
	}
	if name == "wget" {
		return optionValues(a, "-O", "--output-document")
	}
	return nil
}
func analyseShell(command, directory string) ([]string, []string) {
	writes, named := []string{}, []string{}
	add := func(word, here string, write bool) {
		p := shellResolve(word, here)
		if p != "" {
			named = append(named, p)
			if write {
				writes = append(writes, p)
			}
		}
	}
	simple := func(tokens []shellToken, here string) string {
		argv := []string{}
		for i := 0; i < len(tokens); i++ {
			t := tokens[i]
			if t.op {
				if i+1 < len(tokens) && !tokens[i+1].op {
					operator, target := strings.TrimLeft(t.text, "0123456789"), tokens[i+1].text
					i++
					if contains([]string{">", ">>", ">|", "&>", "&>>", "<>"}, operator) || (operator == ">&" && !match(`[0-9]+|-`, target)) {
						add(target, here, true)
					} else if operator == "<" {
						add(target, here, false)
					}
				}
			} else {
				argv = append(argv, t.text)
			}
		}
		for len(argv) > 0 && regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\+?=`).MatchString(argv[0]) {
			argv = argv[1:]
		}
		argv = unwrap(argv)
		if len(argv) == 0 {
			return here
		}
		name := filepath.Base(argv[0])
		if name == "cd" || name == "pushd" {
			target := "~"
			for _, s := range argv[1:] {
				if !strings.HasPrefix(s, "-") {
					target = s
					break
				}
			}
			if p := shellResolve(target, here); p != "" {
				return p
			}
			return here
		}
		for _, word := range writtenBy(name, argv[1:], here) {
			add(word, here, true)
		}
		for _, word := range operands(argv[1:], "") {
			if !strings.HasPrefix(word, "-") && !strings.Contains(word, "://") && (strings.Contains(word, "/") || strings.HasPrefix(word, "~") || match(`[^\s=:]+\.[A-Za-z0-9]{1,8}`, word)) {
				add(word, here, false)
			}
		}
		return here
	}
	outer := []string{}
	current := []shellToken{}
	for _, t := range append(shellTokens(command), shellToken{true, "\n"}) {
		if t.op && contains([]string{"\n", ";", ";;", "&", "&&", "||", "|", "|&", "(", ")"}, t.text) {
			if len(current) > 0 {
				directory = simple(current, directory)
				current = nil
			}
			if t.text == "(" {
				outer = append(outer, directory)
			} else if t.text == ")" && len(outer) > 0 {
				directory = outer[len(outer)-1]
				outer = outer[:len(outer)-1]
			}
		} else {
			current = append(current, t)
		}
	}
	return unique(writes), unique(named)
}
func shingles(text string) map[string]bool {
	r := []rune{}
	for _, c := range strings.ToLower(cutText(text, 65536)) {
		if unicode.IsLetter(c) || unicode.IsDigit(c) {
			r = append(r, c)
			if len(r) == 16384 {
				break
			}
		}
	}
	found := map[string]bool{}
	if len(r) < 5 {
		if len(r) > 0 {
			found[string(r)] = true
		}
		return found
	}
	for i := 0; i+5 <= len(r); i++ {
		found[string(r[i:i+5])] = true
	}
	return found
}
func reworded(later, refused map[string]bool) object {
	if len(later) == 0 || len(refused) == 0 {
		return nil
	}
	shared := 0
	for s := range later {
		if refused[s] {
			shared++
		}
	}
	containment, coverage := float64(shared)/float64(len(later)), float64(shared)/float64(len(refused))
	if containment >= 0.8 && (coverage >= 0.8 || (coverage >= 0.2 && shared >= 20) || shared >= 200) {
		return object{"containment": rounded(containment), "coverage": rounded(coverage)}
	}
	return nil
}
