package hookconfig

import (
	"errors"
	"path/filepath"
	"strings"
)

// Revet runs in the executing supervisor, using the exact command environment.
func Revet(argv []string, cwd string, environment []string) error {
	effective := map[string]string{}
	for _, entry := range environment {
		if key, value, ok := strings.Cut(entry, "="); ok {
			effective[key] = value
		}
	}
	index := 0
	for index < len(argv) && filepath.Base(argv[index]) == "env" {
		index++
		for index < len(argv) {
			word := argv[index]
			if word == "--" {
				index++
				break
			}
			if word == "-i" || word == "--ignore-environment" {
				effective = map[string]string{}
				index++
				continue
			}
			if word == "-u" || word == "--unset" {
				if index+1 >= len(argv) {
					return errors.New(CodexTrustRefusal)
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
				return errors.New("unmodeled env options cannot carry Codex hook trust")
			}
			if key, value, ok := strings.Cut(word, "="); ok && !strings.HasPrefix(word, "-") {
				effective[key] = value
				index++
				continue
			}
			break
		}
	}
	if index >= len(argv) || !strings.HasPrefix(filepath.Base(argv[index]), "codex") {
		for _, word := range argv {
			if strings.Contains(word, CodexTrustBypass) {
				return errors.New("hook trust flag requires a parsed direct Codex invocation")
			}
		}
		return nil
	}
	count := 0
	for i, word := range argv {
		if word == CodexTrustBypass && i > index {
			count++
		} else if strings.Contains(word, CodexTrustBypass) {
			return errors.New("quoted or embedded hook trust flags are refused")
		}
	}
	if count != 1 {
		return errors.New("Codex supervisor requires one vetted trust flag")
	}
	if err := vetEnvironment(effective); err != nil {
		return err
	}
	if err := vetConfigArgs(argv[index+1:]); err != nil {
		return err
	}
	pluginsOff := false
	for i := index + 1; i < len(argv) && argv[i] != "--"; i++ {
		if argv[i] == "--disable" && i+1 < len(argv) && argv[i+1] == "plugins" {
			pluginsOff = true
		}
	}
	if !pluginsOff {
		return errors.New("Codex supervisor requires --disable plugins with hook trust")
	}
	if _, err := writableRoots(filepath.Join(effective["CODEX_HOME"], "config.toml"), cwd, argv[index+1:]); err != nil {
		return err
	}
	return VetCodex(effective["CODEX_HOME"], cwd, effective["HOME"])
}
