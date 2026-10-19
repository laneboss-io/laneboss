package orghook

import (
	"path/filepath"
	"strings"
)

// ANSI-C quoting remains an observation gap. Decode literal read operands only
// for the secret-policy backstop; ordinary encoded paths remain allowed in
// blacklist mode. Decoded operands are never executed; only explicitly invoked
// shell, eval and alias bodies are lexed by the bounded walk below.
func ansiSecretReadRefusal(inst *instance, raw, cwd string, rules []rule) (string, error) {
	if !strings.Contains(raw, "$'") {
		return "", nil
	}
	segments := rawShellSegments(raw, cwd)
	frontier := append([]rawSegment{}, segments...)
	for depth := 0; depth <= 4 && len(frontier) > 0; depth++ {
		for _, segment := range frontier {
			if !segment.ansiC {
				continue
			}
			if reason, err := ansiSegmentReadRefusal(inst, segment, rules, depth); reason != "" || err != nil {
				return reason, err
			}
		}
		aliasInput := append(append([]rawSegment{}, segments...), frontier...)
		nested := []rawSegment{}
		for _, segment := range frontier {
			words := rawEffectiveWords(rawCommandWords(segment))
			if ansiShellBody(words) {
				nested = append(nested, rawNestedShellSegments([]rawSegment{segment})...)
			}
		}
		nested = append(nested, rawAliasSegments(aliasInput)...)
		before := len(segments)
		segments = appendUniqueRawSegments(segments, nested)
		frontier = segments[before:]
		if depth == 4 {
			// Do not inspect a fifth body. Only a lexically simple output-only
			// command is safe to leave as an observation gap at this boundary.
			for _, segment := range frontier {
				if (segment.ansiC || strings.Contains(segment.text, "$'")) && !ansiOutputSegment(segment) {
					return errorRefusal("ANSI-C shell quoting cannot be inspected"), nil
				}
			}
		}
	}
	return "", nil
}

func ansiSegmentReadRefusal(inst *instance, segment rawSegment, rules []rule, depth int) (string, error) {
	decodedWords := rawEffectiveWords(rawCommandWords(segment))
	commands := []command{}
	// Shell bodies and alias definitions are inspected by the bounded walk,
	// with their ANSI-C provenance retained. Do not recursively inspect them
	// here with a fresh depth budget.
	definition := len(decodedWords) > 0 && filepath.Base(decodedWords[0]) == "alias"
	if !ansiShellBody(decodedWords) && !definition {
		var inspectErr error
		commands, inspectErr = inspectArgv(decodedWords, segment.directory, depth)
		incomplete := inspectErr != nil
		for _, cmd := range commands {
			incomplete = incomplete || cmd.opaque
		}
		if incomplete && !ansiOutputSegment(segment) {
			return errorRefusal("ANSI-C shell quoting cannot be inspected"), nil
		}
	}
	redirect := command{directory: segment.directory}
	for index := 0; index+1 < len(segment.tokens); index++ {
		token, target := segment.tokens[index], segment.tokens[index+1]
		if token.operator && !target.operator && contains([]string{"<", "<>"}, strings.TrimLeft(token.word, "0123456789")) {
			word := target.word
			if target.ansiC {
				word = target.decoded
			}
			redirect.reads = append(redirect.reads, word)
		}
	}
	commands = append(commands, redirect)
	_, reads, metadata, _, err := actionEffects(action{commands: commands, gap: true}, segment.directory)
	if err != nil {
		return errorRefusal("ANSI-C shell quoting cannot be inspected"), nil
	}
	for _, row := range rules {
		if row.data["kind"] != "secret-read" || !applies(row, inst) {
			continue
		}
		names, err := policyWords(row.data["names"], inst, "secret_names")
		if err != nil {
			return "", err
		}
		for _, effect := range reads {
			matched, err := secretRead(effect.word, effect.directory, names, inst)
			if err != nil {
				return errorRefusal("ANSI-C shell quoting cannot be inspected"), nil
			}
			if matched {
				return errorRefusal("ANSI-C shell quoting cannot be inspected"), nil
			}
		}
		for _, effect := range metadata {
			path, err := pathAt(effect.word, effect.directory)
			if err != nil {
				return errorRefusal("ANSI-C shell quoting cannot be inspected"), nil
			}
			matched, err := secretNameMatch(effect.word, path, names, inst)
			if err != nil {
				return errorRefusal("ANSI-C shell quoting cannot be inspected"), nil
			}
			if matched {
				return errorRefusal("ANSI-C shell quoting cannot be inspected"), nil
			}
		}
	}
	return "", nil
}

func ansiShellBody(words []string) bool {
	return len(words) > 1 && (filepath.Base(words[0]) == "eval" ||
		len(words) >= 3 && contains([]string{"sh", "bash", "zsh", "dash", "ksh"}, filepath.Base(words[0])) &&
			contains([]string{"-c", "-lc", "-cl"}, words[1]))
}

func ansiOutputWords(words []string) bool {
	return len(words) > 0 && contains([]string{"echo", "printf", "pwd", "true", "false", ":"}, words[0])
}

func ansiOutputSegment(segment rawSegment) bool {
	if segment.tokens == nil {
		return false
	}
	for _, token := range segment.tokens {
		if token.operator || strings.ContainsAny(token.decoded, "`\x00") || strings.Contains(token.decoded, "$(") {
			return false
		}
	}
	return ansiOutputWords(rawEffectiveWords(rawCommandWords(segment)))
}
