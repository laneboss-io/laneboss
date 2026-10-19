package hookpaths

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/BurntSushi/toml"
	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/decisionsrv"
)

// The judge command is defined by the named configuration. Protect that file
// even when absent; changing or creating it changes what the guard enforces.
// A malformed guide is diagnosed after baseline inspection, not used to change
// the baseline's refusal text or silently select another configuration.
func judgeDefinition(home string) ([]string, error) {
	// Every source contributes independently. Neither an override nor a failed
	// guide/history resolution can remove a configuration named by another source.
	names := []string{os.Getenv("LANEBOSS_CONFIG")}
	if guide, err := decisionsrv.OpenGuide(home); err == nil {
		names = append(names, guide.Settings.Configuration)
	} else if settings, _, err := decisionsrv.ReadGuideSettings(home); err == nil {
		names = append(names, settings.Configuration)
	}
	if name := orgJudgeName(home); name != "" && !dropOrgJudge() {
		names = append(names, name)
	}
	for _, relative := range []string{"shared/services/guide.toml", "shared/services/history.toml"} {
		if data, ok := readJudgeSource(filepath.Join(home, relative)); ok {
			names = append(names, rawJudgeNames(data)...)
		}
	}
	candidates := map[string]bool{}
	for _, name := range names {
		if name != "" && config.CheckName(name) == nil {
			candidates[name] = true
		}
	}
	if len(candidates) == 0 {
		return nil, nil
	}
	configurationHome, err := config.Home()
	if err != nil {
		return nil, fmt.Errorf("the judge configuration home is invalid")
	}
	paths := make([]string, 0, len(candidates))
	for name := range candidates {
		paths = append(paths, filepath.Join(configurationHome, "configs", name, "config.toml"))
	}
	sort.Strings(paths)
	return paths, nil
}

// Match the original source reader's bounds and no-follow/non-blocking opens.
// An unavailable source never prevents another source from contributing.
func readJudgeSource(path string) ([]byte, bool) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, false
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 65536 {
		return nil, false
	}
	data, err := io.ReadAll(io.LimitReader(file, 65537))
	return data, err == nil && len(data) <= 65536
}

func orgJudgeName(home string) string {
	data, ok := readJudgeSource(filepath.Join(home, "org.toml"))
	if !ok {
		return ""
	}
	var document map[string]any
	if _, err := toml.Decode(string(data), &document); err != nil {
		return ""
	}
	history, _ := document["history"].(map[string]any)
	name, _ := history["configuration"].(string)
	return name
}

func rawJudgeNames(data []byte) []string {
	var document map[string]any
	if _, err := toml.Decode(string(data), &document); err == nil {
		name, _ := document["configuration"].(string)
		if name != "" {
			return []string{name}
		}
		return nil
	}
	// Recover independently parseable root assignments from a broken file.
	// TOML still decodes each value; comments, table keys and string contents
	// cannot masquerade as configuration assignments.
	names := []string{}
	root, multiline := true, ""
	var statement strings.Builder
	for _, line := range strings.Split(string(data), "\n") {
		if multiline == "" && strings.HasPrefix(strings.TrimSpace(line), "[") {
			var table map[string]any
			if _, err := toml.Decode(line, &table); err == nil {
				root = false
			}
		}
		if root {
			if multiline == "" {
				statement.Reset()
			} else {
				statement.WriteByte('\n')
			}
			statement.WriteString(line)
		}
		multiline = judgeMultiline(line, multiline)
		if root && multiline == "" {
			var field map[string]any
			if _, err := toml.Decode(statement.String(), &field); err == nil {
				if name, ok := field["configuration"].(string); ok {
					names = append(names, name)
				}
			}
		}
	}
	return names
}

// Track TOML strings across lines, including escaped basic-string quotes.
func judgeMultiline(line, delimiter string) string {
	quote := byte(0)
	for at := 0; at < len(line); {
		if delimiter != "" {
			if delimiter[0] == '"' && line[at] == '\\' {
				at += 2
			} else if strings.HasPrefix(line[at:], delimiter) {
				for at < len(line) && line[at] == delimiter[0] {
					at++
				}
				delimiter = ""
			} else {
				at++
			}
			continue
		}
		if quote != 0 {
			if quote == '"' && line[at] == '\\' {
				at += 2
				continue
			}
			if line[at] == quote {
				quote = 0
			}
			at++
			continue
		}
		if line[at] == '#' {
			break
		}
		if line[at] == '"' || line[at] == '\'' {
			if at+2 < len(line) && line[at+1] == line[at] && line[at+2] == line[at] {
				delimiter = line[at : at+3]
				at += 3
				continue
			}
			quote = line[at]
		}
		at++
	}
	return delimiter
}
