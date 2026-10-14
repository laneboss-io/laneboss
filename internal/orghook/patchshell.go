package orghook

import (
	"regexp"
	"strings"
)

var patchDelimiter = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

func firstShellWord(script string) string {
	script = strings.TrimLeft(script, " \t\r\n")
	end := strings.IndexAny(script, " \t\r\n<>&|;()")
	if end < 0 {
		return script
	}
	return script[:end]
}

func patchWord(word string) bool { return word == "apply_patch" || word == "applypatch" }

// Recognize only the complete literal invocation intercepted by the vendor.
// Quoted bodies remain data: apostrophes, dollars and backticks are not expanded.
func literalShellPatch(script string) (string, bool) {
	if len(script) > maxCommand || strings.ContainsRune(script, 0) {
		return "", false
	}
	script = strings.TrimLeft(script, " \t\r\n")
	word := firstShellWord(script)
	if !patchWord(word) {
		return "", false
	}
	rest := strings.TrimLeft(script[len(word):], " \t")
	if strings.HasPrefix(rest, "'") {
		rest = strings.TrimRight(rest, " \t\r\n")
		if len(rest) < 2 || rest[len(rest)-1] != '\'' || strings.ContainsRune(rest[1:len(rest)-1], '\'') {
			return "", false
		}
		return rest[1 : len(rest)-1], true
	}
	header, body, newline := strings.Cut(rest, "\n")
	if !newline || !strings.HasPrefix(header, "<<") || strings.HasPrefix(header, "<<-") {
		return "", false
	}
	marker := strings.TrimSpace(header[2:])
	if len(marker) < 3 || (marker[0] != '\'' && marker[0] != '"') || marker[len(marker)-1] != marker[0] {
		return "", false
	}
	delimiter := marker[1 : len(marker)-1]
	if !patchDelimiter.MatchString(delimiter) {
		return "", false
	}
	offset := 0
	for _, line := range strings.Split(body, "\n") {
		if line == delimiter {
			tail := body[offset+len(line):]
			if tail != "" && tail != "\n" {
				return "", false
			}
			return body[:offset], true
		}
		offset += len(line) + 1
	}
	return "", false
}

func shellWriteIntent(script string) bool {
	word := firstShellWord(script)
	if patchWord(word) {
		return true
	}
	if _, known := operandWriters[word]; known {
		return true
	}
	if _, known := copiers[word]; known {
		return true
	}
	if contains([]string{"dd", "mkdir", "rmdir", "chmod", "chown", "chgrp"}, word) {
		return true
	}
	quote := byte(0)
	for i := 0; i < len(script); i++ {
		letter := script[i]
		if quote != '\'' && letter == '\\' {
			i++
			continue
		}
		if quote == 0 && letter == '>' {
			return true
		}
		if letter == '\'' || letter == '"' {
			if quote == 0 {
				quote = letter
			} else if quote == letter {
				quote = 0
			}
		}
	}
	for _, field := range strings.Fields(script) {
		if strings.ContainsAny(field, "'\"") {
			break
		}
		if (word == "sed" && strings.HasPrefix(field, "-") && strings.ContainsAny(field, "iI")) ||
			(word == "sort" && (field == "-o" || strings.HasPrefix(field, "--output"))) {
			return true
		}
	}
	return false
}
