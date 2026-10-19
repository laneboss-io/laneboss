// Package textcontext reads org-owned descriptions of positional prose arguments.
// These descriptions affect observations only, never hook permission decisions.
package textcontext

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
	"laneboss.io/laneboss/internal/rolepolicy"
)

const Source = ".laneboss/shared/services/" + "text-observations.toml"

type Tool struct {
	Command      []string `toml:"command"`
	TextFrom     int      `toml:"text_from"`
	TextOption   string   `toml:"text_option"`
	ValueOptions []string `toml:"value_options"`
}

// Load uses the configuration's org binding; lanes cannot supply a policy path.
// Missing policy means no additional positional-prose tools are configured.
// Scanner callers supply their existing credential screens for the raw source.
func Load(home string, configuration map[string]any, screens ...func([]byte) error) ([]Tool, error) {
	path, err := rolepolicy.ConfigRoot(home, configuration)
	if err != nil || path == "" {
		return nil, err
	}
	root, err := os.OpenRoot(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%s: org folder cannot be read", Source)
	}
	defer root.Close()
	file, err := root.OpenFile(Source, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%s: policy cannot be read as an org-owned file", Source)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: policy must be a regular file", Source)
	}
	data, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil || len(data) > 65536 {
		return nil, fmt.Errorf("%s: policy must be readable and at most 64 KiB", Source)
	}
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("%s: policy must be UTF-8", Source)
	}
	for _, screen := range screens {
		if err := screen(data); err != nil {
			return nil, fmt.Errorf("%s: policy must not contain credential shapes", Source)
		}
	}
	return Parse(data)
}

func Parse(data []byte) ([]Tool, error) {
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("%s: policy must be UTF-8", Source)
	}
	var policy struct {
		Schema int    `toml:"schema_version"`
		Tools  []Tool `toml:"tools"`
	}
	metadata, err := toml.Decode(string(data), &policy)
	if err != nil || policy.Schema != 1 || len(metadata.Undecoded()) != 0 || len(policy.Tools) > 64 {
		return nil, fmt.Errorf("%s: expected schema_version 1 and at most 64 tools, with no unknown fields", Source)
	}
	word := regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._:/+-]{0,127}$`)
	for i := range policy.Tools {
		tool := &policy.Tools[i]
		if len(tool.Command) == 0 || len(tool.Command) > 16 || strings.Contains(tool.Command[0], "/") || len(tool.ValueOptions) > 32 {
			return nil, fmt.Errorf("%s: tools[%d] requires a bounded command prefix beginning with a basename", Source, i)
		}
		for _, item := range tool.Command {
			if !word.MatchString(item) {
				return nil, fmt.Errorf("%s: tools[%d].command requires literal shell words", Source, i)
			}
		}
		if tool.TextFrom == 0 {
			tool.TextFrom = len(tool.Command)
		}
		if tool.TextFrom < len(tool.Command) || tool.TextFrom > 10000 || tool.TextOption != "" && (!word.MatchString(tool.TextOption) || !strings.HasPrefix(tool.TextOption, "-")) {
			return nil, fmt.Errorf("%s: tools[%d] has an invalid text_from or text_option", Source, i)
		}
		for _, option := range tool.ValueOptions {
			if !word.MatchString(option) || !strings.HasPrefix(option, "-") {
				return nil, errors.New(Source + ": value_options requires literal option names")
			}
		}
	}
	return policy.Tools, nil
}
