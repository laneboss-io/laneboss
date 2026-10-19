package hookconfig

import (
	"errors"
	"strings"
)

// Remove every existing sandbox selector before rendering the single documented
// --sandbox danger-full-access option. Other config overrides remain vetted.
func replaceCodexSandbox(args []string) ([]string, error) {
	result := []string{}
	for i := 0; i < len(args); i++ {
		word := args[i]
		if word == "--" {
			return append(result, args[i:]...), nil
		}
		flag, value, inline := codexFlag(word)
		if strings.HasPrefix(word, "-") && (flag == "--sandbox" || flag == "-s") {
			if !inline {
				i++
				if i >= len(args) {
					return nil, errors.New("Codex sandbox selector is incomplete")
				}
			}
			continue
		}
		if strings.HasPrefix(word, "-") && (flag == "-c" || flag == "--config") {
			if !inline {
				if i+1 >= len(args) {
					return nil, errors.New("Codex command config is incomplete")
				}
				value = args[i+1]
			}
			key, _, _ := strings.Cut(value, "=")
			if strings.Trim(strings.TrimSpace(key), "\"'") == "sandbox_mode" {
				if !inline {
					i++
				}
				continue
			}
		}
		result = append(result, word)
	}
	return result, nil
}

func verifyCodexReplacement(args []string) error {
	count := 0
	for i := 0; i < len(args) && args[i] != "--"; i++ {
		flag, value, inline := codexFlag(args[i])
		if flag != "--sandbox" && flag != "-s" {
			continue
		}
		if !inline {
			i++
			if i >= len(args) {
				return errors.New("Codex lane sandbox replacement is incomplete")
			}
			value = args[i]
		}
		if value != "danger-full-access" {
			return errors.New("Codex runner's sandbox must be off under the Laneboss macOS sandbox")
		}
		count++
	}
	if count != 1 {
		return errors.New("Codex lane sandbox replacement requires exactly one full-access selector")
	}
	return nil
}
