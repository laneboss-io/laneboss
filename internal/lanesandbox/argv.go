package lanesandbox

import (
	"errors"
	"path/filepath"
	"strings"
)

// runnerInvocation looks through modeled env wrappers only. Arguments to the
// runner cannot select a different provider or contribute environment values.
func runnerInvocation(argv, environment []string) (string, []string, map[string]string, error) {
	effective := map[string]string{}
	for _, word := range environment {
		if key, value, ok := strings.Cut(word, "="); ok {
			effective[key] = value
		}
	}
	index := 0
	for index < len(argv) && filepath.Base(argv[index]) == "env" {
		index++
	wrapper:
		for index < len(argv) {
			word := argv[index]
			switch word {
			case "--":
				index++
				break wrapper
			case "-i", "--ignore-environment":
				effective = map[string]string{}
				index++
				continue
			case "-u", "--unset":
				if index+1 >= len(argv) {
					return "", nil, nil, errors.New("runner env unset option is incomplete")
				}
				delete(effective, argv[index+1])
				index += 2
				continue
			}
			if strings.HasPrefix(word, "--unset=") {
				delete(effective, strings.TrimPrefix(word, "--unset="))
				index++
				continue
			}
			if strings.HasPrefix(word, "-") {
				return "", nil, nil, errors.New("lane sandbox replacement requires modeled env options")
			}
			if key, value, ok := strings.Cut(word, "="); ok && key != "" {
				effective[key] = value
				index++
				continue
			}
			break
		}
	}
	if index >= len(argv) || argv[index] == "" {
		return "", nil, nil, errors.New("runner command has no program")
	}
	return filepath.Base(argv[index]), argv[index+1:], effective, nil
}
