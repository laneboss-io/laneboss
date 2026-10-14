package orghook

import "strings"

// Only literal scripts whose complete grammar is understood are read-only.
// File scripts, file/command effects, blocks, branches and ambiguous syntax
// remain opaque. In particular r/R cannot introduce an unreported secret read.
func sedReads(arguments []string) ([]string, bool) {
	scripts, files := []string{}, []string{}
	options, explicit, positional := true, false, false
	for index := 0; index < len(arguments); index++ {
		word := arguments[index]
		if options && word == "--" {
			if positional {
				return nil, false
			}
			options = false
			continue
		}
		if options && strings.HasPrefix(word, "-") && word != "-" {
			if positional {
				return nil, false
			}
			if strings.HasPrefix(word, "--") {
				flag, value, joined := strings.Cut(word, "=")
				if flag == "--expression" {
					if !joined {
						index++
						if index >= len(arguments) {
							return nil, false
						}
						value = arguments[index]
					}
					scripts, explicit = append(scripts, value), true
				} else if joined || !contains([]string{"--quiet", "--silent", "--regexp-extended", "--unbuffered", "--separate", "--posix", "--sandbox"}, flag) {
					return nil, false
				}
				continue
			}
			for offset := 1; offset < len(word); offset++ {
				flag := word[offset]
				if flag == 'e' {
					value := word[offset+1:]
					if value == "" {
						index++
						if index >= len(arguments) {
							return nil, false
						}
						value = arguments[index]
					}
					scripts, explicit = append(scripts, value), true
					break
				}
				// i/I and f, including clusters and suffixes, are not supported.
				if !strings.ContainsRune("nErsu", rune(flag)) {
					return nil, false
				}
			}
			continue
		}
		positional = true
		if len(scripts) == 0 && !explicit {
			scripts = append(scripts, word)
		} else if word != "-" {
			files = append(files, word)
		}
	}
	if len(scripts) == 0 {
		return nil, false
	}
	for _, script := range scripts {
		if !readOnlySed(script) {
			return nil, false
		}
	}
	return files, true
}

// Bracket expressions have vendor-specific delimiter handling. Keep them
// opaque until that grammar is modeled; escapes never become script syntax.
func sedDelimited(script string, offset int, delimiter byte, pattern bool) (int, bool) {
	for offset < len(script) {
		letter := script[offset]
		if letter == '\\' {
			offset += 2
			if offset > len(script) {
				return 0, false
			}
			continue
		}
		if pattern && (letter == '[' || letter == ']') {
			return 0, false
		}
		offset++
		if letter == delimiter {
			return offset, true
		}
	}
	return 0, false
}

func sedAddress(script string, offset int) (int, bool) {
	if offset >= len(script) {
		return offset, false
	}
	if script[offset] == '/' {
		return sedDelimited(script, offset+1, '/', true)
	}
	start := offset
	for offset < len(script) && script[offset] >= '0' && script[offset] <= '9' {
		offset++
	}
	return offset, offset > start
}

func readOnlySed(script string) bool {
	// Shell lexing does not retain enough quoting information to prove that
	// expansion metacharacters remain literal, so those forms stay opaque.
	if strings.ContainsAny(script, "\r\n*?[]{}~") {
		return false
	}
	script = strings.TrimSpace(script)
	offset := 0
	if end, address := sedAddress(script, offset); address {
		offset = end
		if offset < len(script) && script[offset] == ',' {
			var ok bool
			offset, ok = sedAddress(script, offset+1)
			if !ok {
				return false
			}
		}
	}
	for offset < len(script) && (script[offset] == ' ' || script[offset] == '\t') {
		offset++
	}
	if offset < len(script) && script[offset] == '!' {
		offset++
	}
	for offset < len(script) && (script[offset] == ' ' || script[offset] == '\t') {
		offset++
	}
	if offset >= len(script) {
		return false
	}
	verb := script[offset]
	offset++
	if strings.ContainsRune("pPdDnNhHgGxl=qQ", rune(verb)) {
		return strings.TrimSpace(script[offset:]) == ""
	}
	if verb != 's' || offset >= len(script) || !strings.ContainsRune("/#|:%_", rune(script[offset])) {
		return false
	}
	delimiter := script[offset]
	end, ok := sedDelimited(script, offset+1, delimiter, true)
	if !ok {
		return false
	}
	end, ok = sedDelimited(script, end, delimiter, false)
	if !ok {
		return false
	}
	for _, flag := range strings.TrimSpace(script[end:]) {
		if !strings.ContainsRune("gpIiMm0123456789", flag) {
			return false
		}
	}
	return true
}
