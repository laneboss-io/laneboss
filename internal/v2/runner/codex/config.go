package codex

import (
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/BurntSushi/toml"

	"laneboss.io/laneboss/internal/v2/api"
)

func checkConfig(name string, data []byte) error {
	if !utf8.Valid(data) {
		return problem(api.CodeIntegrity, "Codex configuration must be valid UTF-8")
	}
	var document map[string]any
	if strings.HasSuffix(name, ".toml") {
		if _, err := toml.Decode(string(data), &document); err != nil {
			return problem(api.CodeIntegrity, "Codex configuration TOML is invalid")
		}
	} else if err := decodeJSON(data, &document, false); err != nil {
		return wrap("read Codex hook configuration", err)
	}
	return configValues(document)
}

// This is a blacklist of credential/home/provider redirection fields, not a
// command list. Ordinary settings, tools, skills and programs stay available.
func configValues(value any) error {
	switch document := value.(type) {
	case map[string]any:
		for key, item := range document {
			switch strings.ToLower(key) {
			case "cli_auth_credentials_store":
				if item != "file" {
					return problem(api.CodeForbidden, "Codex file login cannot select a keyring or automatic credential store")
				}
			case "model_provider", "model_providers", "api_key", "api_key_helper", "apikeyhelper", "credential_helper",
				"credentials_store", "auth", "auth_mode", "env_key", "env_http_headers", "http_headers",
				"forced_login_method", "forced_chatgpt_workspace_id", "chatgpt_base_url", "base_url", "experimental_bearer_token", "bearer_token":
				return problem(api.CodeForbidden, "Codex file-login configuration cannot redirect authentication or provider")
			case "home", "codex_home", "xdg_config_home", "xdg_cache_home", "xdg_state_home", "tmpdir", "path",
				"openai_api_key", "openai_base_url", "codex_api_key", "codex_auth_json", "ld_preload", "dyld_insert_libraries":
				return problem(api.CodeForbidden, "Codex configuration cannot replace private paths or inherited credentials")
			}
			if err := configValues(item); err != nil {
				return err
			}
		}
	case []any:
		for _, item := range document {
			if err := configValues(item); err != nil {
				return err
			}
		}
	case []map[string]any:
		for _, item := range document {
			if err := configValues(item); err != nil {
				return err
			}
		}
	}
	return nil
}

// CheckProjectConfig examines every project config that the vendor can load
// between the granted materialized project root and cwd. Supply PHYSICAL paths
// from the data worker; a logical sandbox path is not host-read authority.
func CheckProjectConfig(projectRoot, workdir string) error {
	if !absolute(projectRoot) || !absolute(workdir) || !within(projectRoot, workdir) {
		return problem(api.CodeInvalid, "Codex project configuration needs bounded absolute workspace paths")
	}
	root, err := os.OpenRoot(projectRoot)
	if err != nil {
		return problem(api.CodeUnavailable, "Codex project root cannot be inspected")
	}
	defer root.Close()
	named, nameErr := os.Lstat(projectRoot)
	opened, openErr := root.Stat(".")
	if nameErr != nil || openErr != nil || !named.IsDir() || !os.SameFile(named, opened) {
		return problem(api.CodeIntegrity, "Codex project root does not match its opened directory")
	}
	for current := workdir; ; current = filepath.Dir(current) {
		relative, err := filepath.Rel(projectRoot, current)
		if err != nil {
			return problem(api.CodeIntegrity, "Codex project configuration scope cannot be resolved")
		}
		for ancestor := relative; ; ancestor = filepath.Dir(ancestor) {
			info, err := root.Lstat(ancestor)
			if err != nil || !info.IsDir() {
				return problem(api.CodeIntegrity, "Codex project cwd must have real existing directory components")
			}
			if ancestor == "." {
				break
			}
		}
		container := filepath.Join(relative, ".codex")
		info, err := root.Lstat(container)
		if err == nil {
			if !info.IsDir() {
				return problem(api.CodeIntegrity, "Codex project configuration container cannot be a link or special file")
			}
			for _, file := range []string{"config.toml", "hooks.json"} {
				name := filepath.Join(container, file)
				before, err := root.Lstat(name)
				if err == nil {
					if !before.Mode().IsRegular() || linked(before) || before.Size() > maxRecordBytes {
						return problem(api.CodeIntegrity, "Codex project configuration must be a bounded ordinary file")
					}
					f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
					if err != nil {
						return problem(api.CodeUnavailable, "Codex project configuration cannot be opened")
					}
					after, statErr := f.Stat()
					data, readErr := io.ReadAll(io.LimitReader(f, maxRecordBytes+1))
					closeErr := f.Close()
					if statErr != nil || readErr != nil || closeErr != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || linked(after) || len(data) > maxRecordBytes {
						return problem(api.CodeIntegrity, "Codex project configuration changed or could not be read completely")
					}
					if err := checkConfig(name, data); err != nil {
						return wrap("check Codex project configuration", err)
					}
				} else if !os.IsNotExist(err) {
					return problem(api.CodeUnavailable, "Codex project configuration cannot be inspected")
				}
			}
		} else if !os.IsNotExist(err) {
			return problem(api.CodeUnavailable, "Codex project configuration container cannot be inspected")
		}
		if current == projectRoot {
			break
		}
	}
	return nil
}

// Environment supplies only nonsecret private path values to the trusted
// launcher. Never append os.Environ or merge caller settings into this result.
// Native auth.json injection belongs to the selected credential worker slot.
func Environment(home api.PrivateHome, searchPath string) ([]string, error) {
	if !privateHome(home) || !absolute(home.VendorDirectory) || searchPath == "" {
		return nil, problem(api.CodeInvalid, "Codex environment needs a private home and explicit search path")
	}
	for _, part := range filepath.SplitList(searchPath) {
		if !absolute(part) {
			return nil, problem(api.CodeInvalid, "Codex search path has an empty or relative component")
		}
	}
	base := filepath.Dir(home.VendorDirectory)
	values := map[string]string{"CODEX_HOME": home.VendorDirectory, "HOME": base, "PATH": searchPath,
		"TMPDIR": filepath.Join(base, "tmp"), "XDG_CACHE_HOME": filepath.Join(base, ".cache"),
		"XDG_CONFIG_HOME": filepath.Join(base, ".config"), "XDG_STATE_HOME": filepath.Join(base, ".local/state")}
	names := environmentNames()
	sort.Strings(names)
	result := make([]string, 0, len(names))
	for _, name := range names {
		result = append(result, name+"="+values[name])
	}
	return result, nil
}
