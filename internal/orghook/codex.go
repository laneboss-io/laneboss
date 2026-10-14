package orghook

import (
	"bytes"
	"os"
	"reflect"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

// Preserve existing text for ordinary table/dotted forms; verify every proposed edit.
// Unusual inline forms are encoded from the complete parsed document, retaining all values.
func codexConfigBytes(path string) ([]byte, error) {
	data := []byte{}
	config := map[string]any{}
	if _, err := os.Lstat(path); err == nil {
		data, err = readBytes(path, "Codex config.toml")
		if err != nil {
			return nil, err
		}
		config, err = parseTOML(data, "Codex config.toml")
		if err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, invalid("Codex config.toml is unreadable")
	}
	features := map[string]any{}
	agents, agentsExisted := object(config["agents"])
	if _, present := config["agents"]; present && !agentsExisted {
		return nil, invalid("Codex config.toml agents must be a table")
	}
	if !agentsExisted {
		agents = map[string]any{}
	}
	for key := range agents {
		if key != "enabled" {
			return nil, invalid("Codex config.toml agents role or setting cannot be rendered: " + key)
		}
	}
	agentsDisabled := agents["enabled"] == false
	sandbox, existed := object(config["sandbox_workspace_write"])
	if _, present := config["sandbox_workspace_write"]; present && !existed {
		return nil, invalid("Codex config.toml sandbox_workspace_write must be a table")
	}
	if !existed {
		sandbox = map[string]any{}
	}
	secure := sandbox["exclude_slash_tmp"] == true && sandbox["exclude_tmpdir_env_var"] == true
	if value, exists := config["features"]; exists {
		var ok bool
		features, ok = object(value)
		if !ok {
			return nil, invalid("Codex config.toml features must be a table")
		}
		if features["hooks"] == true && secure && agentsDisabled && features["multi_agent_v2"] == false && features["collab"] == false {
			return data, nil
		}
	}
	features["hooks"] = true
	_, hadMulti := features["multi_agent_v2"]
	_, hadCollab := features["collab"]
	features["multi_agent_v2"], features["collab"] = false, false
	agents["enabled"] = false
	config["agents"] = agents
	config["features"] = features
	sandbox["exclude_slash_tmp"], sandbox["exclude_tmpdir_env_var"] = true, true
	config["sandbox_workspace_write"] = sandbox
	decorate := func(candidate []byte) []byte {
		insertion := ""
		if !hadMulti {
			insertion += "multi_agent_v2 = false\n"
		}
		if !hadCollab {
			insertion += "collab = false\n"
		}
		section := regexp.MustCompile(`(?m)^[ \t]*\[(?:features|"features"|'features')\][ \t]*(?:#[^\r\n]*)?(?:\r?\n|$)`)
		if insertion != "" {
			if indexes := section.FindIndex(candidate); indexes != nil {
				prefix := string(candidate[:indexes[1]])
				if !strings.HasSuffix(prefix, "\n") {
					prefix += "\n"
				}
				candidate = append([]byte(prefix+insertion), candidate[indexes[1]:]...)
			}
		}
		if !existed {
			candidate = append(append([]byte{}, candidate...), []byte("\n[sandbox_workspace_write]\nexclude_slash_tmp = true\nexclude_tmpdir_env_var = true\n")...)
		}
		if !agentsExisted {
			candidate = append(append([]byte{}, candidate...), []byte("\n[agents]\nenabled = false\n")...)
		}
		return candidate
	}
	valid := func(candidate []byte) bool {
		parsed, err := parseTOML(candidate, "Codex config.toml")
		return err == nil && reflect.DeepEqual(parsed, config)
	}
	boolean := regexp.MustCompile(`(?m)^([ \t]*(?:hooks|features\.hooks|"hooks"|'hooks')[ \t]*=[ \t]*)(true|false)([ \t]*(?:#[^\r\n]*)?(?:\r?\n|$))`)
	for _, indexes := range boolean.FindAllSubmatchIndex(data, -1) {
		candidate := append(append(append([]byte{}, data[:indexes[4]]...), []byte("true")...), data[indexes[5]:]...)
		candidate = decorate(candidate)
		if valid(candidate) {
			return candidate, nil
		}
	}
	header := regexp.MustCompile(`(?m)^[ \t]*\[(?:features|"features"|'features')\][ \t]*(?:#[^\r\n]*)?(?:\r?\n|$)`)
	var candidate []byte
	if features["hooks"] == true && !existed && valid(decorate(data)) {
		return decorate(data), nil
	}
	if indexes := header.FindIndex(data); indexes != nil {
		prefix := string(data[:indexes[1]])
		if !strings.HasSuffix(prefix, "\n") {
			prefix += "\n"
		}
		candidate = append([]byte(prefix+"hooks = true\n"), data[indexes[1]:]...)
	} else {
		candidate = append(append([]byte{}, data...), []byte("\n[features]\nhooks = true\n")...)
	}
	candidate = decorate(candidate)
	if valid(candidate) {
		return candidate, nil
	}
	var encoded bytes.Buffer
	if err := toml.NewEncoder(&encoded).Encode(config); err != nil {
		return nil, invalid("Codex config.toml cannot be encoded")
	}
	return encoded.Bytes(), nil
}
