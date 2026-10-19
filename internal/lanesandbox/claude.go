package lanesandbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const claudeOverlayDir = ".laneboss-lanes"

// ClaudeOverlay leaves native invocations and org policy unchanged. Only an
// active Darwin replacement receives a private per-run copy of the settings.
func ClaudeOverlay(argv []string, data map[string]any) ([]string, error) {
	if !ReplacesRunner(data) {
		return argv, nil
	}
	program, args, _, err := runnerInvocation(argv, nil)
	if err != nil {
		return nil, err
	}
	if program != "claude" && program != "claudock" {
		return argv, nil
	}
	source, err := claudeSettingsPath(program, args)
	if err != nil {
		return nil, err
	}
	home := filepath.Dir(source)
	canonical, err := filepath.EvalSymlinks(home)
	if err != nil || canonical != home || filepath.Base(home) != ".claude" {
		return nil, errors.New("Claude overlay requires a canonical rendered vendor home")
	}
	info, err := os.Lstat(source)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 2*1024*1024 {
		return nil, errors.New("Claude overlay source must be a bounded regular settings file")
	}
	input, err := os.ReadFile(source)
	if err != nil {
		return nil, errors.New("Claude overlay source cannot be read")
	}
	var document map[string]any
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	if decoder.Decode(&document) != nil || document == nil {
		return nil, errors.New("Claude overlay source must be a settings object")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return nil, errors.New("Claude overlay source must contain one settings object")
	}
	sandbox, ok := document["sandbox"].(map[string]any)
	if _, exists := document["sandbox"]; exists && !ok {
		return nil, errors.New("Claude sandbox settings must be an object")
	}
	if sandbox == nil {
		sandbox = map[string]any{}
	}
	sandbox["enabled"] = false
	document["sandbox"] = sandbox
	output, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, errors.New("Claude overlay cannot be encoded")
	}
	container := filepath.Join(home, claudeOverlayDir)
	if err := os.Mkdir(container, 0700); err != nil && !os.IsExist(err) {
		return nil, errors.New("Claude overlay container cannot be created")
	}
	info, err = os.Lstat(container)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("Claude overlay container must be an ordinary directory")
	}
	directory, err := os.MkdirTemp(container, "lane-")
	if err != nil {
		return nil, errors.New("Claude per-run overlay directory cannot be created")
	}
	path := filepath.Join(directory, "settings.json")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, errors.New("Claude per-run overlay cannot be created")
	}
	if _, err = file.Write(append(output, '\n')); err != nil {
		file.Close()
		return nil, errors.New("Claude per-run overlay cannot be written")
	}
	if err = file.Chmod(0444); err != nil {
		file.Close()
		return nil, errors.New("Claude per-run overlay cannot be protected")
	}
	if err = file.Close(); err != nil {
		return nil, errors.New("Claude per-run overlay cannot be closed")
	}
	prepared := append([]string{}, argv...)
	first := len(argv) - len(args)
	for i := first; i < len(prepared); i++ {
		if prepared[i] == "--settings" && i+1 < len(prepared) && prepared[i+1] == source {
			prepared[i+1] = path
			return prepared, nil
		}
		if prepared[i] == "--settings="+source {
			prepared[i] = "--settings=" + path
			return prepared, nil
		}
	}
	return nil, errors.New("Claude settings selector changed while preparing its overlay")
}

func claudeDataHome(settings string) string {
	directory := filepath.Dir(settings)
	if filepath.Base(filepath.Dir(directory)) == claudeOverlayDir {
		return filepath.Dir(filepath.Dir(directory))
	}
	return directory
}

func claudeSettingsPath(program string, args []string) (string, error) {
	if program == "claudock" {
		separator := -1
		for i, word := range args {
			if word == "--" {
				separator = i
				break
			}
		}
		if separator < 0 {
			return "", errors.New("Claudock lane sandbox replacement requires literal Claude options after --")
		}
		args = args[separator+1:]
	}
	path := ""
	for i := 0; i < len(args) && args[i] != "--"; i++ {
		word := args[i]
		if word == "--settings" {
			i++
			if i >= len(args) {
				return "", errors.New("Claude settings option is incomplete")
			}
			word = "--settings=" + args[i]
		}
		if !strings.HasPrefix(word, "--settings=") {
			continue
		}
		if path != "" {
			return "", errors.New("Claude lane sandbox replacement requires exactly one rendered settings file")
		}
		path = strings.TrimPrefix(word, "--settings=")
		if !validPath(path) || filepath.Base(path) != "settings.json" {
			return "", errors.New("Claude lane sandbox replacement requires an absolute rendered settings.json path")
		}
	}
	if path == "" {
		return "", errors.New("Claude and Claudock lane sandbox replacement requires the rendered --settings file")
	}
	return path, nil
}
