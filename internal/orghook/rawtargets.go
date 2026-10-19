package orghook

import (
	"os"
	"path"
	"path/filepath"
	"strings"
)

type rawTarget struct {
	word, directory string
	assignments     map[string]string
}

// decodeANSICWord decodes the ANSI-C word form used by sh, bash and zsh. The
// raw inspector does not evaluate substitutions; it only turns escaped bytes
// into the literal shell body so an explicitly invoked nested shell can be
// inspected. A non-ANSI word is returned as absent so ordinary quoted data is
// never re-lexed as shell syntax.
func decodeANSICWord(word string) (string, bool) {
	if len(word) < 3 || !strings.HasPrefix(word, "$'") || word[len(word)-1] != '\'' {
		return "", false
	}
	body := word[2 : len(word)-1]
	var decoded strings.Builder
	for index := 0; index < len(body); index++ {
		if body[index] != '\\' || index+1 >= len(body) {
			decoded.WriteByte(body[index])
			continue
		}
		index++
		switch body[index] {
		case 'a':
			decoded.WriteByte('\a')
		case 'b':
			decoded.WriteByte('\b')
		case 'e', 'E':
			decoded.WriteByte(0x1b)
		case 'f':
			decoded.WriteByte('\f')
		case 'n':
			decoded.WriteByte('\n')
		case 'r':
			decoded.WriteByte('\r')
		case 't':
			decoded.WriteByte('\t')
		case 'v':
			decoded.WriteByte('\v')
		case '\\', '\'', '"':
			decoded.WriteByte(body[index])
		case 'x':
			value, count := ansiHex(body[index+1:], 2)
			if count == 0 {
				decoded.WriteByte('x')
				continue
			}
			decoded.WriteByte(byte(value))
			index += count
		case 'u', 'U':
			width := 4
			if body[index] == 'U' {
				width = 8
			}
			value, count := ansiHex(body[index+1:], width)
			if count != width {
				decoded.WriteByte(body[index])
				continue
			}
			decoded.WriteRune(rune(value))
			index += count
		default:
			if body[index] >= '0' && body[index] <= '7' {
				value := int(body[index] - '0')
				count := 1
				for count < 3 && index+count < len(body) && body[index+count] >= '0' && body[index+count] <= '7' {
					value = value*8 + int(body[index+count]-'0')
					count++
				}
				decoded.WriteByte(byte(value))
				index += count - 1
			} else {
				// Bash removes the escape before an otherwise literal byte.
				decoded.WriteByte(body[index])
			}
		}
	}
	return decoded.String(), true
}

func ansiHex(text string, width int) (uint64, int) {
	value := uint64(0)
	count := 0
	for count < width && count < len(text) {
		var digit byte
		switch c := text[count]; {
		case c >= '0' && c <= '9':
			digit = c - '0'
		case c >= 'a' && c <= 'f':
			digit = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			digit = c - 'A' + 10
		default:
			return 0, 0
		}
		value = value*16 + uint64(digit)
		count++
	}
	return value, count
}

// rawCommandWords reads the original tokens. A quoted arrow or a quoted space
// remains data; only an operator token introduces a redirect.
func rawCommandWords(segment rawSegment) []string {
	if segment.tokens == nil {
		words := append([]string(nil), segment.words...)
		for index, word := range words {
			if decoded, ok := decodeANSICWord(word); ok {
				words[index] = decoded
			}
		}
		return words
	}
	words := []string{}
	for index := 0; index < len(segment.tokens); index++ {
		token := segment.tokens[index]
		if token.operator {
			if index+1 < len(segment.tokens) && !segment.tokens[index+1].operator &&
				strings.ContainsAny(token.word, "<>") {
				index++
			}
			continue
		}
		word := token.word
		if token.ansiC {
			word = token.decoded
		}
		words = append(words, word)
	}
	return words
}

func rawEffectWords(segment rawSegment) []string {
	words := rawCommandWords(segment)
	for _, token := range segment.tokens {
		if len(words) == 0 || token.operator || token.quoted || token.word != words[0] ||
			!contains([]string{"if", "then", "elif", "else", "do", "!", "{"}, token.word) {
			break
		}
		words = words[1:]
	}
	return words
}

func rawRedirectTargets(segment rawSegment) []string {
	if segment.tokens == nil {
		// Keep c6eec72's conservative fallback for an unlexable part. The
		// unresolved-tail matcher still requires an anchored protected tail.
		result := []string{}
		for _, word := range strings.Fields(segment.text) {
			result = append(result, strings.Trim(word, "'\";"))
		}
		return result
	}
	targets := []string{}
	for index := 0; index+1 < len(segment.tokens); index++ {
		token := segment.tokens[index]
		if !token.operator {
			continue
		}
		operator := strings.TrimLeft(token.word, "0123456789")
		if !contains([]string{">", ">>", ">|", "<>", "&>", "&>>", ">&"}, operator) ||
			segment.tokens[index+1].operator {
			continue
		}
		target := segment.tokens[index+1].word
		if segment.tokens[index+1].ansiC {
			target = segment.tokens[index+1].decoded
		}
		if operator == ">&" && (digits(target) || target == "-") {
			continue
		}
		targets = append(targets, target)
	}
	return targets
}

func rawWriteTargets(segment rawSegment) []string {
	targets := rawRedirectTargets(segment)
	if effect, ok := literalWriteCommand(rawEffectWords(segment), segment.directory); ok {
		return append(targets, effect.writes...)
	}
	words := rawEffectiveWords(rawCommandWords(segment))
	for index, word := range words {
		name, arguments := filepath.Base(word), words[index+1:]
		if takes, writer := operandWriters[name]; writer {
			return append(targets, operands(arguments, takes)...)
		}
		if _, copier := copiers[name]; copier {
			files := operands(arguments, copiers[name])
			directories := optionValues(arguments, "-t", "--target-directory")
			targets = append(targets, directories...)
			if len(directories) == 0 && len(files) >= 2 {
				targets = append(targets, files[len(files)-1])
				if name == "mv" {
					// Moving a source removes its original protected pathname.
					targets = append(targets, files[:len(files)-1]...)
				}
			} else if name == "mv" {
				targets = append(targets, files...)
			}
			return targets
		}
		if name == "dd" {
			for _, argument := range arguments {
				if strings.HasPrefix(argument, "of=") {
					targets = append(targets, strings.TrimPrefix(argument, "of="))
				}
			}
			return targets
		}
		if contains([]string{"mkdir", "rmdir", "chmod", "chown", "chgrp"}, name) {
			files := operands(arguments, nil)
			if contains([]string{"chmod", "chown", "chgrp"}, name) && len(files) > 0 {
				files = files[1:]
			}
			return append(targets, files...)
		}
		if name == "sort" {
			targets = append(targets, optionValues(arguments, "-o", "--output")...)
			targets = append(targets, optionValues(arguments, "-T", "--temporary-directory")...)
			return targets
		}
	}
	return targets
}

// rawAliasSegments expands only aliases that are defined and then invoked in
// the same raw shell input. Alias definitions are data until an invocation is
// observed; the expanded text is parsed as shell input with the invocation's
// directory, without re-lexing unrelated quoted arguments.
func rawAliasSegments(segments []rawSegment) []rawSegment {
	aliases := map[string]string{}
	ansiAliases := map[string]bool{}
	result := []rawSegment{}
	for _, segment := range segments {
		words := rawCommandWords(segment)
		if len(words) > 0 && filepath.Base(words[0]) == "alias" {
			for _, word := range words[1:] {
				name, value, ok := strings.Cut(word, "=")
				if ok && targetName(name) {
					aliases[name] = value
					ansiAliases[name] = segment.ansiC
				}
			}
			continue
		}
		if len(segment.words) == 0 {
			continue
		}
		name := filepath.Base(segment.words[0])
		if script, ok := aliases[name]; ok {
			result = append(result, rawShellSegmentsTainted(script, segment.directory, segment.ansiC || ansiAliases[name])...)
		}
	}
	return result
}

// rawNestedShellSegments inspects literal sh -c/bash -c/zsh -c bodies only
// when the command explicitly invokes a shell. This preserves quoted redirect
// data as data for ordinary commands while retaining the nested shell's real
// write effects, including env -C/--chdir directory changes.
func rawNestedShellSegments(segments []rawSegment) []rawSegment {
	result := []rawSegment{}
	for _, segment := range segments {
		words := rawCommandWords(segment)
		for index, word := range words {
			if !contains([]string{"sh", "bash", "zsh", "dash", "ksh"}, filepath.Base(word)) || index+2 >= len(words) ||
				!contains([]string{"-c", "-lc", "-cl"}, words[index+1]) {
				continue
			}
			directory := segment.directory
			for option := 0; option < index; option++ {
				if (words[option] == "-C" || words[option] == "--chdir") && option+1 < index {
					if candidate, err := pathAt(words[option+1], segment.directory); err == nil {
						directory = candidate
					}
				} else if strings.HasPrefix(words[option], "--chdir=") {
					if candidate, err := pathAt(strings.TrimPrefix(words[option], "--chdir="), segment.directory); err == nil {
						directory = candidate
					}
				}
			}
			result = append(result, rawShellSegmentsTainted(words[index+2], directory, segment.ansiC)...)
			break
		}
		effective := rawEffectiveWords(words)
		if len(effective) > 1 && filepath.Base(effective[0]) == "eval" {
			result = append(result, rawShellSegmentsTainted(strings.Join(effective[1:], " "), segment.directory, segment.ansiC)...)
		}
	}
	return result
}

func appendUniqueRawSegments(existing []rawSegment, additions ...[]rawSegment) []rawSegment {
	seen := make(map[string]bool, len(existing))
	for _, segment := range existing {
		seen[rawSegmentKey(segment)] = true
	}
	for _, group := range additions {
		for _, segment := range group {
			key := rawSegmentKey(segment)
			if seen[key] {
				continue
			}
			seen[key] = true
			existing = append(existing, segment)
		}
	}
	return existing
}

func rawSegmentKey(segment rawSegment) string {
	key := segment.directory + "\x00" + segment.text + "\x00" + strings.Join(segment.words, "\x00")
	if segment.ansiC {
		key += "\x00ansi-c"
	}
	return key
}

func targetNameStart(letter byte) bool {
	return letter == '_' || letter >= 'A' && letter <= 'Z' || letter >= 'a' && letter <= 'z'
}

func targetNamePart(letter byte) bool {
	return targetNameStart(letter) || letter >= '0' && letter <= '9'
}

func targetName(name string) bool {
	if name == "" || !targetNameStart(name[0]) {
		return false
	}
	for index := 1; index < len(name); index++ {
		if !targetNamePart(name[index]) {
			return false
		}
	}
	return true
}

// targetExpansion identifies simple parameters without evaluating shell code.
// Complex substitutions stay unresolved and only their trailing literal text
// can take part in the conservative suffix check.
func targetExpansion(word string, index int) (end int, name string) {
	if word[index] == byte(96) {
		for end = index + 1; end < len(word); end++ {
			if word[end] == '\\' {
				end++
			} else if word[end] == byte(96) {
				return end + 1, ""
			}
		}
		return len(word), ""
	}
	if index+1 == len(word) {
		return len(word), ""
	}
	next := word[index+1]
	if next == '{' || next == '(' {
		close := byte('}')
		if next == '(' {
			close = ')'
		}
		nesting := 1
		for end = index + 2; end < len(word); end++ {
			if word[end] == next {
				nesting++
			} else if word[end] == close {
				nesting--
				if nesting == 0 {
					value := word[index+2 : end]
					if next == '{' && targetName(value) {
						return end + 1, value
					}
					return end + 1, ""
				}
			}
		}
		return len(word), ""
	}
	if targetNameStart(next) {
		end = index + 2
		for end < len(word) && targetNamePart(word[end]) {
			end++
		}
		return end, word[index+1 : end]
	}
	return index + 2, ""
}

func braceAlternatives(word string) []string {
	start := strings.IndexByte(word, '{')
	if start < 0 {
		return []string{word}
	}
	depth, close := 0, -1
	for index := start; index < len(word); index++ {
		switch word[index] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				close = index
			}
		}
		if close >= 0 {
			break
		}
	}
	if close < 0 {
		return []string{word}
	}
	parts := []string{}
	last, nested := start+1, 0
	for index := start + 1; index < close; index++ {
		switch word[index] {
		case '{':
			nested++
		case '}':
			nested--
		case ',':
			if nested == 0 {
				parts = append(parts, word[last:index])
				last = index + 1
			}
		}
	}
	if len(parts) == 0 {
		return []string{word}
	}
	parts = append(parts, word[last:close])
	result := []string{}
	for _, part := range parts {
		for _, suffix := range braceAlternatives(word[close+1:]) {
			result = append(result, word[:start]+part+suffix)
		}
	}
	return result
}

func rawTargetMatchesProtected(word, directory, protected string) bool {
	for _, alternative := range braceAlternatives(word) {
		if strings.ContainsAny(alternative, "*?[") {
			pattern := filepath.ToSlash(alternative)
			if !filepath.IsAbs(alternative) {
				pattern = filepath.ToSlash(filepath.Join(directory, alternative))
			}
			matched, err := path.Match(pattern, filepath.ToSlash(protected))
			if err == nil && matched {
				return true
			}
			continue
		}
		resolved, err := pathAt(alternative, directory)
		if err == nil && (inside(resolved, protected) || inside(protected, resolved)) {
			return true
		}
	}
	return false
}

type targetResolution struct {
	word, tail string
	unresolved bool
}

func resolveWriteTarget(word string, lookup func(string) (string, bool)) targetResolution {
	var result, tail strings.Builder
	unresolved := false
	index := 0
	if word == "~" || strings.HasPrefix(word, "~/") {
		if home, ok := lookup("HOME"); ok {
			result.WriteString(home)
			tail.WriteString(home)
		} else {
			result.WriteByte('~')
			unresolved = true
		}
		index = 1
	}
	for index < len(word) {
		if word[index] != '$' && word[index] != byte(96) {
			result.WriteByte(word[index])
			tail.WriteByte(word[index])
			index++
			continue
		}
		end, name := targetExpansion(word, index)
		value, ok := "", false
		if name != "" {
			value, ok = lookup(name)
			ok = ok && len(value) <= maxCommand && !strings.ContainsAny(value, "$") && !strings.ContainsRune(value, rune(96))
		}
		if ok {
			result.WriteString(value)
			tail.WriteString(value)
		} else {
			result.WriteString(word[index:end])
			tail.Reset()
			unresolved = true
		}
		index = end
	}
	return targetResolution{word: result.String(), tail: tail.String(), unresolved: unresolved}
}

func shellEnvironment(data map[string]any) map[string]string {
	result := map[string]string{}
	for _, key := range []string{"env", "additional_env"} {
		if values, ok := object(data[key]); ok {
			for name, value := range values {
				if text, ok := value.(string); ok {
					result[name] = text
				}
			}
		}
	}
	return result
}

func targetLookup(assignments, environment map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		if value, exists := assignments[name]; exists {
			// A nonliteral assignment shadows lower-precedence values, but is
			// never executed or recursively expanded.
			return value, !strings.ContainsAny(value, "$") && !strings.ContainsRune(value, rune(96))
		}
		if value, exists := environment[name]; exists {
			return value, true
		}
		// Look up only names used by this target. No environment enumeration,
		// logging or resolved values enter a receipt or refusal.
		return os.LookupEnv(name)
	}
}

func recordTargetAssignments(segment rawSegment, assignments map[string]string) {
	words := rawCommandWords(segment)
	if segment.tokens == nil {
		words = strings.Fields(segment.text)
	}
	if len(words) > 0 && contains([]string{"export", "readonly", "declare", "typeset", "local"}, words[0]) {
		words = words[1:]
	}
	for _, word := range words {
		name, value, found := strings.Cut(word, "=")
		if !found || !targetName(name) {
			break
		}
		assignments[name] = value
	}
}

func copyTargetAssignments(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for name, value := range values {
		result[name] = value
	}
	return result
}

// The caller uses this only while an expansion remains unresolved. Match from
// the last unresolved expansion, never within an arbitrary literal project path.
func protectedRedirectSuffix(rest, protected, policy, org string) bool {
	tail := path.Clean("/" + filepath.ToSlash(rest))
	if tail == "/org.toml" && filepath.Base(protected) == "org.toml" {
		return true
	}
	if tail == "/instance.toml" && filepath.Base(protected) == "instance.toml" {
		return true
	}
	suffixes := []string{}
	for _, root := range []string{policy, org} {
		relative, err := filepath.Rel(root, protected)
		if err == nil && relative != "." && relative != ".." &&
			!strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			suffixes = append(suffixes, filepath.ToSlash(relative))
		}
	}
	absolute := strings.Split(strings.Trim(filepath.ToSlash(protected), "/"), "/")
	if len(absolute) >= 2 {
		suffixes = append(suffixes, strings.Join(absolute[len(absolute)-2:], "/"))
	}
	for _, suffix := range suffixes {
		if !strings.Contains(suffix, "/") && suffix != "org.toml" && suffix != "instance.toml" {
			continue
		}
		prefix := "/" + suffix
		if tail == prefix || strings.HasPrefix(tail, prefix+"/") {
			return true
		}
	}
	if filepath.Base(protected) == "configs" {
		parts := strings.Split(strings.TrimPrefix(tail, "/"), "/")
		if len(parts) >= 2 && parts[0] == "configs" && parts[1] != "" &&
			(len(parts) == 2 || (len(parts) == 3 && parts[2] == "config.toml")) {
			return true
		}
		if len(parts) >= 2 && parts[0] == "laneboss" && parts[1] == "configs" {
			return true
		}
	}
	return false
}
