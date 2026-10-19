package orghook

import (
	"path/filepath"
	"strings"
)

const maxShellCodeDepth = 32
const obscuredShellDepthReason = "uninspectable obscured shell: shell code exceeds the nesting limit"

var errObscuredShellDepth = invalid(obscuredShellDepthReason)

// This fallback recognizes command positions, not general shell effects. Only
// explicit shell/eval arguments and active substitutions are read again as code;
// quoted message arguments and heredoc bodies remain data. No text is expanded.
type lanebossCodeScanner struct {
	text   string
	index  int
	budget *int
}

type codeHeredoc struct {
	delimiter string
	tabs      bool
}

func shellCodeHasLaneboss(text string, depth int, budget *int) bool {
	// True also denotes an unfinished inspection: the caller must refuse the
	// obscured candidate rather than interpret a resource/parse limit as no call.
	if depth > maxShellCodeDepth || strings.ContainsRune(text, 0) || *budget <= 0 {
		return true
	}
	s := lanebossCodeScanner{text: text, budget: budget}
	return s.code(0, depth)
}

func (s *lanebossCodeScanner) command(words []string, depth int) bool {
	words = codeCommandWords(words)
	if len(words) == 0 {
		return false
	}
	switch filepath.Base(words[0]) {
	case "laneboss":
		return true
	case "sh", "bash", "zsh", "dash", "ksh":
		return len(words) >= 3 && contains([]string{"-c", "-lc", "-cl"}, words[1]) &&
			shellCodeHasLaneboss(words[2], depth+1, s.budget)
	case "eval":
		return shellCodeHasLaneboss(strings.Join(words[1:], " "), depth+1, s.budget)
	case "alias":
		// Preserve the previous literal alias-definition check. Do not resolve
		// alias uses or infer the identity of a renamed executable.
		for _, word := range words[1:] {
			if _, value, ok := strings.Cut(word, "="); ok {
				argv := rawEffectiveWords(strings.Fields(value))
				if len(argv) > 0 && filepath.Base(argv[0]) == "laneboss" {
					return true
				}
			}
		}
	}
	return false
}

// Only leading wrappers and assignments affect command position. In
// particular, a brace or command name appearing in an ordinary argument must
// not discard the executable and turn message text into a new command.
func codeCommandWords(words []string) []string {
	for len(words) > 0 {
		for len(words) > 0 && assignment.MatchString(words[0]) {
			words = words[1:]
		}
		if len(words) == 0 {
			return nil
		}
		name := filepath.Base(words[0])
		takes, wrapper := wrappers[name]
		if !wrapper {
			return words
		}
		index := 1
		for index < len(words) && strings.HasPrefix(words[index], "-") {
			option := words[index]
			index++
			if option == "--" {
				break
			}
			if contains(takes, option) && index < len(words) {
				index++
			}
		}
		if name == "timeout" && index < len(words) {
			index++
		}
		words = words[index:]
	}
	return nil
}

// code consumes a command list, optionally ending at a substitution delimiter.
func (s *lanebossCodeScanner) code(stop byte, depth int) bool {
	if depth > maxShellCodeDepth {
		return true
	}
	words := []string{}
	heredocs := []codeHeredoc{}
	for s.index < len(s.text) && *s.budget > 0 {
		*s.budget--
		c := s.text[s.index]
		if stop != 0 && c == stop {
			if *s.budget <= 0 || len(heredocs) != 0 {
				return true
			}
			s.index++
			return s.command(words, depth)
		}
		switch c {
		case ' ', '\t', '\r':
			s.index++
		case '#':
			for s.index < len(s.text) && s.text[s.index] != '\n' && *s.budget > 0 {
				s.index++
				*s.budget--
			}
		case ';', '&', '|', '\n', ')':
			if c == ')' {
				return true // An unmatched closing delimiter is not a completed scan.
			}
			if s.command(words, depth) {
				return true
			}
			words = nil
			s.index++
			if c == '\n' {
				for _, doc := range heredocs {
					if !s.skipHeredoc(doc) {
						return true
					}
				}
				heredocs = nil
			}
		case '(':
			if s.command(words, depth) {
				return true
			}
			words = nil
			s.index++
			if s.code(')', depth+1) {
				return true
			}
		case '<', '>':
			// A redirection operand is not an executable. Substitutions in an
			// ordinary operand still execute; a heredoc delimiter does not.
			start := s.index
			op := string(c)
			for _, candidate := range []string{"<<-", "<<<", "<<", ">>", ">|", "<&", ">&", "<>"} {
				if strings.HasPrefix(s.text[start:], candidate) {
					op = candidate
					break
				}
			}
			s.index += len(op)
			for s.index < len(s.text) && (s.text[s.index] == ' ' || s.text[s.index] == '\t') && *s.budget > 0 {
				s.index++
				*s.budget--
			}
			if *s.budget <= 0 {
				return true
			}
			here := op == "<<" || op == "<<-"
			operandStart := s.index
			word, found := s.word(stop, depth, !here)
			if found {
				return true
			}
			if s.index == operandStart {
				return true // A redirection without its operand cannot be inspected.
			}
			if here && s.index > operandStart {
				heredocs = append(heredocs, codeHeredoc{delimiter: word, tabs: op == "<<-"})
			}
		default:
			start := s.index
			word, found := s.word(stop, depth, true)
			if found {
				return true
			}
			// Preserve command heads after literal control keywords. Quoted
			// keywords and keywords in message arguments are ordinary words.
			if len(words) == 0 && s.text[start:s.index] == word &&
				contains([]string{"if", "then", "elif", "else", "while", "until", "do", "!", "{"}, word) {
				continue
			}
			words = append(words, word)
		}
	}
	if *s.budget <= 0 || stop != 0 || len(heredocs) != 0 {
		return true
	}
	return s.command(words, depth)
}

func (s *lanebossCodeScanner) skipHeredoc(doc codeHeredoc) bool {
	for s.index < len(s.text) {
		line, _, newline := strings.Cut(s.text[s.index:], "\n")
		s.index += len(line)
		*s.budget -= len(line)
		if newline {
			s.index++
			*s.budget--
		}
		if *s.budget <= 0 {
			return false
		}
		if doc.tabs {
			line = strings.TrimLeft(line, "\t")
		}
		if line == doc.delimiter {
			return true
		}
	}
	return false
}

// Arithmetic is data rather than a command list. Only command substitutions
// embedded in the expression introduce shell code.
func (s *lanebossCodeScanner) arithmetic(depth int) bool {
	if depth > maxShellCodeDepth {
		return true
	}
	level, quote := 2, byte(0)
	for s.index < len(s.text) && *s.budget > 0 {
		*s.budget--
		c := s.text[s.index]
		if c == '\\' && quote != '\'' && s.index+1 < len(s.text) {
			s.index += 2
			continue
		}
		if quote != '\'' && strings.HasPrefix(s.text[s.index:], "$(") {
			s.index += 2
			if s.index < len(s.text) && s.text[s.index] == '(' {
				s.index++
				if s.arithmetic(depth + 1) {
					return true
				}
			} else if s.code(')', depth+1) {
				return true
			}
			continue
		}
		if c == '`' && quote != '\'' {
			s.index++
			if s.code('`', depth+1) {
				return true
			}
			continue
		}
		if c == '\'' || c == '"' {
			if quote == 0 {
				quote = c
			} else if quote == c {
				quote = 0
			}
		} else if quote == 0 && c == '(' {
			level++
		} else if quote == 0 && c == ')' {
			level--
		}
		s.index++
		if level == 0 {
			return false
		}
	}
	return true // The expression or its quoting never closed, or work ran out.
}

// word removes one quoting layer. A single-quoted argument is only re-read if
// command identifies it as an explicit shell/eval body. Active substitutions
// in unquoted or double-quoted arguments are separate command lists.
func (s *lanebossCodeScanner) word(stop byte, depth int, expansions bool) (string, bool) {
	var word strings.Builder
	quote := byte(0)
	for s.index < len(s.text) && *s.budget > 0 {
		*s.budget--
		c := s.text[s.index]
		if quote == 0 && (c == stop || strings.ContainsRune(" \t\r\n;&|()<>", rune(c))) {
			break
		}
		if c == '\\' && quote != '\'' {
			if s.index+1 == len(s.text) {
				return "", true
			}
			if s.index+1 < len(s.text) && (quote == 0 || strings.ContainsRune("\"\\$`\n", rune(s.text[s.index+1]))) {
				s.index++
				if s.text[s.index] != '\n' {
					word.WriteByte(s.text[s.index])
				}
				s.index++
				continue
			}
		}
		if c == '\'' || c == '"' {
			if quote == 0 {
				quote = c
				s.index++
				continue
			}
			if quote == c {
				quote = 0
				s.index++
				continue
			}
		}
		if expansions && quote != '\'' && (c == '`' || c == '$' && s.index+1 < len(s.text) && s.text[s.index+1] == '(') {
			start := s.index
			if strings.HasPrefix(s.text[s.index:], "$((") {
				s.index += 3
				if s.arithmetic(depth + 1) {
					return "", true
				}
				word.WriteString(s.text[start:s.index])
				continue
			}
			end := byte('`')
			s.index++
			if c == '$' {
				s.index++
				end = ')'
			}
			if s.code(end, depth+1) {
				return "", true
			}
			word.WriteString(s.text[start:s.index])
			continue
		}
		word.WriteByte(c)
		s.index++
	}
	if quote != 0 || *s.budget <= 0 {
		return "", true
	}
	return word.String(), false
}
