package orghook

import "strings"

type readOptionSpec struct {
	flags                       string
	longFlags, values, optional []string
}

// Known GNU/BSD option arities and file effects. Abbreviated long options,
// options after operands, indirect file lists and external helpers stay opaque.
var strictReaders = map[string]readOptionSpec{
	"head": {flags: "qvz", longFlags: []string{"--quiet", "--silent", "--verbose", "--zero-terminated"},
		values: []string{"-n", "-c", "--lines", "--bytes"}},
	"tail": {flags: "fFqvrz", longFlags: []string{"--retry", "--quiet", "--silent", "--verbose", "--zero-terminated"},
		values: []string{"-n", "-c", "-s", "--lines", "--bytes", "--sleep-interval", "--pid", "--max-unchanged-stats"}, optional: []string{"--follow"}},
	"wc": {flags: "clmwL", longFlags: []string{"--bytes", "--chars", "--lines", "--words", "--max-line-length"}, values: []string{"--total"}},
	"nl": {flags: "p", longFlags: []string{"--no-renumber"},
		values: []string{"-b", "-d", "-f", "-h", "-i", "-l", "-n", "-s", "-v", "-w", "--body-numbering", "--section-delimiter", "--footer-numbering", "--header-numbering", "--line-increment", "--join-blank-lines", "--number-format", "--number-separator", "--starting-line-number", "--number-width"}},
	"cut": {flags: "nsz", longFlags: []string{"--only-delimited", "--complement", "--zero-terminated"},
		values: []string{"-b", "-c", "-d", "-f", "--bytes", "--characters", "--delimiter", "--fields", "--output-delimiter"}},
	"sort": {flags: "bdfgMhnRrucCsVmz", longFlags: []string{"--ignore-leading-blanks", "--dictionary-order", "--ignore-case", "--general-numeric-sort", "--ignore-nonprinting", "--month-sort", "--human-numeric-sort", "--numeric-sort", "--random-sort", "--reverse", "--unique", "--stable", "--version-sort", "--merge", "--zero-terminated"},
		values: []string{"-k", "-t", "-S", "-o", "-T", "--key", "--field-separator", "--buffer-size", "--output", "--temporary-directory", "--parallel", "--batch-size", "--random-source", "--sort"}, optional: []string{"--check"}},
	"grep": {flags: "EFGPivwxqsclLnHhRrzoabUIZ", longFlags: []string{"--extended-regexp", "--fixed-strings", "--basic-regexp", "--perl-regexp", "--ignore-case", "--no-ignore-case", "--invert-match", "--word-regexp", "--line-regexp", "--quiet", "--silent", "--no-messages", "--files-with-matches", "--files-without-match", "--line-number", "--with-filename", "--no-filename", "--recursive", "--dereference-recursive", "--null-data", "--only-matching", "--text", "--byte-offset", "--binary", "--null", "--count", "--line-buffered"},
		values: []string{"-e", "-f", "-A", "-B", "-C", "-m", "-d", "-D", "--regexp", "--file", "--after-context", "--before-context", "--context", "--max-count", "--directories", "--devices", "--include", "--exclude", "--exclude-dir", "--binary-files", "--label"}, optional: []string{"--color", "--colour"}},
}

func literalReadValue(value string) bool {
	return value != "" && !strings.ContainsAny(value, "$`*?[]{}") && !strings.HasPrefix(value, "~") && !hasControl(value)
}

func readerEffects(name string, arguments []string, directory string) ([]string, []string, bool) {
	spec := strictReaders[name]
	reads, writes, files := []string{}, []string{}, []string{}
	options, positional, pattern := true, false, false
	consume := func(option, value string) bool {
		if !literalReadValue(value) {
			return false
		}
		if name == "grep" && contains([]string{"-e", "--regexp", "-f", "--file"}, option) {
			pattern = true
			if option == "-f" || option == "--file" {
				reads = append(reads, value)
			}
		}
		if name == "sort" {
			if contains([]string{"-o", "--output", "-T", "--temporary-directory"}, option) {
				writes = append(writes, value)
			}
			if option == "--random-source" {
				reads = append(reads, value)
			}
		}
		return true
	}
	for index := 0; index < len(arguments); index++ {
		word := arguments[index]
		if options && word == "--" {
			if positional {
				return nil, nil, false
			}
			options = false
			continue
		}
		if options && strings.HasPrefix(word, "-") && word != "-" {
			if positional {
				return nil, nil, false
			}
			if (name == "head" || name == "tail") && digits(word[1:]) {
				continue
			}
			if strings.HasPrefix(word, "--") {
				option, value, joined := strings.Cut(word, "=")
				if contains(spec.longFlags, option) {
					if joined {
						return nil, nil, false
					}
					continue
				}
				if contains(spec.optional, option) {
					if joined && !consume(option, value) {
						return nil, nil, false
					}
					continue
				}
				if !contains(spec.values, option) {
					return nil, nil, false
				}
				if !joined {
					index++
					if index >= len(arguments) {
						return nil, nil, false
					}
					value = arguments[index]
				}
				if !consume(option, value) {
					return nil, nil, false
				}
				continue
			}
			for offset := 1; offset < len(word); offset++ {
				option := "-" + word[offset:offset+1]
				if contains(spec.values, option) {
					value := word[offset+1:]
					if value == "" {
						index++
						if index >= len(arguments) {
							return nil, nil, false
						}
						value = arguments[index]
					}
					if !consume(option, value) {
						return nil, nil, false
					}
					break
				}
				if !strings.ContainsRune(spec.flags, rune(word[offset])) {
					return nil, nil, false
				}
			}
			continue
		}
		positional = true
		if name == "grep" && !pattern {
			if !literalReadValue(word) {
				return nil, nil, false
			}
			pattern = true
		} else if word != "-" {
			files = append(files, word)
		}
	}
	if name == "grep" {
		if !pattern {
			return nil, nil, false
		}
		if len(files) == 0 {
			files = append(files, directory)
		}
	}
	return append(reads, files...), writes, true
}
