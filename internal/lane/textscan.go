package lane

import (
	"path/filepath"
	"regexp"
	"strings"

	"laneboss.io/laneboss/internal/textcontext"
)

var inlinePython = regexp.MustCompile(`^(?:python|pypy)(?:[23](?:\.[0-9]+)*)?$`)
var shellAssignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\+?=`)

func interpreterOptions(name string) []string {
	if inlinePython.MatchString(name) {
		return []string{"-c"}
	}
	switch name {
	case "node", "nodejs":
		return []string{"-e", "--eval", "-p", "--print"}
	case "perl", "julia":
		return []string{"-e", "-E", "--eval"}
	case "ruby", "lua", "Rscript":
		return []string{"-e"}
	case "R":
		return []string{"-e", "--expression"}
	case "php":
		return []string{"-r"}
	case "osascript":
		return []string{"-e"}
	}
	return nil
}

// shellArgv preserves token metadata while sharing the path scanner's wrappers.
func shellArgv(tokens []shellToken) []shellToken {
	argv := []shellToken{}
	for i := 0; i < len(tokens); i++ {
		if tokens[i].op {
			if i+1 < len(tokens) && !tokens[i+1].op {
				i++
			}
		} else {
			argv = append(argv, tokens[i])
		}
	}
	for len(argv) > 0 && shellAssignment.MatchString(argv[0].text) {
		argv = argv[1:]
	}
	words := make([]string, len(argv))
	for i, token := range argv {
		words[i] = token.text
	}
	return argv[len(argv)-len(unwrap(words)):]
}

func optionValue(word, option string) bool {
	if strings.HasPrefix(option, "--") {
		return strings.HasPrefix(word, option+"=")
	}
	return len(word) > len(option) && strings.HasPrefix(word, option)
}

// Known value options may precede a subcommand, as with a model before exec.
func textToolPrefix(argv []shellToken, tool textcontext.Tool) int {
	if len(tool.Command) == 0 || len(argv) == 0 || filepath.Base(argv[0].text) != tool.Command[0] {
		return -1
	}
	i := 1
	for _, part := range tool.Command[1:] {
		for i < len(argv) && contains(tool.ValueOptions, argv[i].text) {
			if i+1 >= len(argv) {
				return -1
			}
			i += 2
		}
		if i >= len(argv) || argv[i].text != part {
			return -1
		}
		i++
	}
	return i
}

func simpleTextSubstitution(tokens []shellToken, tools []textcontext.Tool) bool {
	for _, token := range tokens {
		if token.backtick && !token.heredoc {
			return true
		}
	}
	argv := shellArgv(tokens)
	if len(argv) == 0 {
		return false
	}
	name := filepath.Base(argv[0].text)
	codeOptions := interpreterOptions(name)
	if len(codeOptions) > 0 {
		for _, token := range tokens {
			if token.heredoc && (token.backtick || token.dollar) {
				return true
			}
		}
	}
	allowed := make([]bool, len(argv))
	markOptions := func(options []string) {
		for i := 1; i < len(argv); i++ {
			for _, option := range options {
				if argv[i].text == option && i+1 < len(argv) {
					allowed[i+1] = true
				} else if optionValue(argv[i].text, option) {
					allowed[i] = true
				}
			}
		}
	}
	markOptions(codeOptions)
	markOptions([]string{"-m", "--message", "--body", "--title", "--text", "--description"})
	for _, tool := range tools {
		prefixEnd := textToolPrefix(argv, tool)
		if prefixEnd < 0 {
			continue
		}
		from := tool.TextFrom + prefixEnd - len(tool.Command)
		if tool.TextOption != "" {
			from = len(argv)
			for i := prefixEnd; i < len(argv); i++ {
				if argv[i].text == tool.TextOption {
					from = i + 1
					break
				}
				if contains(tool.ValueOptions, argv[i].text) && i+1 < len(argv) {
					i++
					continue
				}
				if optionValue(argv[i].text, tool.TextOption) {
					allowed[i] = true
					from = i + 1
					break
				}
			}
		}
		for i := from; i < len(argv); i++ {
			if contains(tool.ValueOptions, argv[i].text) && i+1 < len(argv) {
				allowed[i], allowed[i+1] = false, false
				i++
			} else if !strings.HasPrefix(argv[i].text, "-") {
				allowed[i] = true
			}
		}
	}
	// File options name inputs, not prose, even on a configured message tool.
	for i := 1; i < len(argv); i++ {
		if argv[i].text == "-F" || argv[i].text == "--file" {
			allowed[i] = false
			if i+1 < len(argv) {
				allowed[i+1] = false
				i++
			}
		} else if optionValue(argv[i].text, "-F") || optionValue(argv[i].text, "--file") {
			allowed[i] = false
		}
	}
	for i, token := range argv {
		if token.dollar && allowed[i] {
			return true
		}
	}
	return false
}

func shellTextSubstitution(tokens []shellToken, tools []textcontext.Tool) bool {
	current := []shellToken{}
	for _, token := range append(tokens, shellToken{op: true, text: "\n"}) {
		if token.op && contains([]string{"\n", ";", ";;", "&", "&&", "||", "|", "|&", "(", ")"}, token.text) {
			if simpleTextSubstitution(current, tools) {
				return true
			}
			current = current[:0]
		} else {
			current = append(current, token)
		}
	}
	return false
}
