// Package boxcfg locates and validates box configurations without creating files.
package boxcfg

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
	"laneboss.io/laneboss/internal/boxcore"
)

// Env is the configuration home, state home and home used for tilde expansion.
type Env struct {
	Home      string // Configuration home, normally supplied by EnvFrom.
	StateHome string // State home for default ledger and run paths.
	UserHome  string // User home for bare tilde and tilde-slash expansion.
}

// EnvFrom uses absolute overrides, falling back to directories under userHome.
func EnvFrom(getenv func(string) string, userHome string) Env {
	env := Env{
		Home:      filepath.Join(userHome, ".config", "laneboss"),
		StateHome: filepath.Join(userHome, ".local", "state", "laneboss"),
		UserHome:  userHome,
	}
	if getenv != nil {
		if value := getenv("LANEBOSS_HOME"); filepath.IsAbs(value) {
			env.Home = value
		}
		if value := getenv("LANEBOSS_STATE_HOME"); filepath.IsAbs(value) {
			env.StateHome = value
		}
	}
	return env
}

// LocateOptions gives the flag, environment and named configuration locations.
type LocateOptions struct {
	Flag       string // --box-config path.
	EnvValue   string // LANEBOSS_BOX_CONFIG path.
	ConfigName string // Named configuration under Home/configs.
	Home       string // Env.Home.
}

// Locate selects the first supplied location and requires a regular file.
func Locate(o LocateOptions) (string, error) {
	path := o.Flag
	tried := "--box-config"
	if path == "" {
		path = o.EnvValue
		tried += ", LANEBOSS_BOX_CONFIG"
	}
	if path == "" {
		tried += ", Home/configs/ConfigName/box.toml"
		if !grammar(`[a-z0-9][a-z0-9-]{0,31}`)(o.ConfigName) {
			return "", fmt.Errorf("box config lookup: tried %s; a valid configuration name is required", tried)
		}
		path = filepath.Join(o.Home, "configs", o.ConfigName, "box.toml")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("box config lookup: tried %s; a regular file is required", tried)
	}
	return path, nil
}

// Load reads a bounded UTF-8 TOML file, validates it and applies absent defaults.
func Load(path string, env Env) (*boxcore.Config, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, invalid("box.toml", "file", "cannot resolve the file path")
	}
	data, err := readConfig(abs)
	if err != nil {
		return nil, err
	}
	if !utf8.Valid(data) {
		return nil, invalid(abs, "file", "must be UTF-8 text")
	}
	var values map[string]any
	if _, err := toml.Decode(string(data), &values); err != nil {
		var parse toml.ParseError
		if errors.As(err, &parse) {
			return nil, fmt.Errorf("%s: TOML syntax error at line %d column %d",
				abs, parse.Position.Line, parse.Position.Col)
		}
		return nil, fmt.Errorf("%s: TOML syntax error at line %d column %d", abs, 1, 1)
	}
	if key, ok := credentialPath(values, ""); ok {
		return nil, invalid(abs, key, "credential-shaped text is forbidden")
	}
	v := &validation{file: abs, env: env}
	root := section{v: v, data: values}
	root.allowed("schema_version org ledger defaults guest aws gcp")
	root.integer("schema_version", 0, true, 1, 1)
	c := &boxcore.Config{Path: abs}
	c.Org = root.text("org", "", true, boxcore.PlainName)
	c.Ledger = loadLedger(root.child("ledger"))
	c.Defaults = loadDefaults(root.child("defaults"))
	c.Guest = loadGuest(root.child("guest"))
	if _, present := values["aws"]; present {
		c.AWS = loadAWS(root.child("aws"), c.Org)
	}
	if _, present := values["gcp"]; present {
		c.GCP = loadGCP(root.child("gcp"))
	}
	if c.Defaults.Provider == "aws" && c.AWS == nil ||
		c.Defaults.Provider == "gcp" && c.GCP == nil {
		v.fail("defaults.provider", "requires its provider table")
	}
	if v.err != nil {
		return nil, v.err
	}
	return c, nil
}

func readConfig(path string) (data []byte, err error) {
	// Nonblocking open avoids waiting on a special file before checking its type.
	f, openErr := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if openErr != nil {
		return nil, invalid(path, "file", "cannot open the file")
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			err = errors.Join(err, invalid(path, "file", "cannot close the file"))
		}
	}()
	info, statErr := f.Stat()
	if statErr != nil || !info.Mode().IsRegular() {
		return nil, invalid(path, "file", "must be a regular file")
	}
	const limit = 256 * 1024
	if info.Size() > limit {
		return nil, invalid(path, "file", "exceeds the file size limit")
	}
	data, readErr := io.ReadAll(io.LimitReader(f, limit+1))
	if readErr != nil {
		return nil, invalid(path, "file", "cannot read the file")
	}
	if len(data) > limit {
		return nil, invalid(path, "file", "exceeds the file size limit")
	}
	return data, nil
}
