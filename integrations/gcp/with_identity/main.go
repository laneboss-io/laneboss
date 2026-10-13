// Command with_identity replaces itself with one command under a named identity.
package main

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
	"golang.org/x/sys/unix"
)

const usage = "usage: with_identity.py --identities FILE NAME -- COMMAND [ARGUMENT ...]\n\nRun COMMAND under the identity NAME of the identities file FILE, with an environment built from\nscratch: of the caller's environment only PATH, HOME, TMPDIR, LANG and TERM are copied. Every\nrefusal is one line starting `refused:` on standard error and exit 2."

var nameRule = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
var projectRule = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)

func refuse(message string) int { fmt.Fprintln(os.Stderr, "refused: "+message); return 2 }
func main()                     { os.Exit(run(os.Args[1:])) }
func run(args []string) (code int) {
	defer func() {
		if recover() != nil {
			fmt.Fprintln(os.Stderr, "internal error")
			code = 70
		}
	}()
	if len(args) > 0 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Println(usage)
		return 0
	}
	if len(args) < 5 || args[0] != "--identities" || args[3] != "--" || args[4] == "" {
		return refuse("the command line must be --identities FILE NAME -- COMMAND [ARGUMENT ...]")
	}
	path, name, command := args[1], args[2], args[4]
	if !nameRule.MatchString(name) {
		return refuse("NAME must match [a-z0-9][a-z0-9-]{0,31}")
	}
	info, err := os.Stat(path)
	if err != nil {
		return refuse("the identities file was not found")
	}
	if !info.Mode().IsRegular() {
		return refuse("the identities file is not a regular file")
	}
	if info.Size() > 65536 {
		return refuse("the identities file is larger than 64 KiB")
	}
	f, err := os.Open(path)
	if err != nil {
		return refuse("the identities file could not be read")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 65537))
	f.Close()
	if err != nil {
		return refuse("the identities file could not be read")
	}
	if len(raw) > 65536 {
		return refuse("the identities file is larger than 64 KiB")
	}
	data := map[string]any{}
	if !utf8.Valid(raw) {
		return refuse("the identities file is not valid TOML")
	}
	if _, err = toml.Decode(string(raw), &data); err != nil {
		return refuse("the identities file is not valid TOML")
	}
	if v, ok := data["schema_version"].(int64); !ok || v != 1 {
		return refuse("schema_version must be the integer 1")
	}
	for key := range data {
		if key != "schema_version" && key != "identities" {
			return refuse("only schema_version and identities are allowed at the top level")
		}
	}
	identities, ok := data["identities"].(map[string]any)
	if !ok {
		return refuse("identities must be a table")
	}
	table, ok := identities[name].(map[string]any)
	if !ok {
		return refuse("identities." + name + " is not a table")
	}
	for key := range table {
		if key != "config_dir" && key != "project" && key != "key_file" {
			return refuse("identities." + name + " has a key that is not allowed (only config_dir, project and key_file)")
		}
	}
	label := "identities." + name + "."
	value, present := table["config_dir"]
	if !present {
		return refuse(label + "config_dir is required")
	}
	directory, ok := value.(string)
	if !ok {
		return refuse(label + "config_dir must be a string")
	}
	if !strings.HasPrefix(directory, "/") {
		return refuse(label + "config_dir must be an absolute path")
	}
	if info, err = os.Stat(directory); err != nil || !info.IsDir() {
		return refuse(label + "config_dir is not an existing directory")
	}
	if value, present = table["project"]; present {
		if project, ok := value.(string); !ok || !projectRule.MatchString(project) {
			return refuse(label + "project must match [a-z][a-z0-9-]{4,28}[a-z0-9]")
		}
	}
	if value, present = table["key_file"]; present {
		key, ok := value.(string)
		if !ok || !strings.HasPrefix(key, "/") {
			return refuse(label + "key_file must be an absolute path")
		}
		if info, err = os.Stat(key); err != nil || !info.Mode().IsRegular() {
			return refuse(label + "key_file is not an existing regular file")
		}
	}
	env := map[string]string{}
	for _, key := range []string{"PATH", "HOME", "TMPDIR", "LANG", "TERM"} {
		if v, ok := os.LookupEnv(key); ok {
			env[key] = v
		}
	}
	candidates := []string{command}
	if !strings.Contains(command, "/") {
		candidates = nil
		search := env["PATH"]
		if search == "" {
			search = "/usr/bin:/bin"
		}
		for _, dir := range strings.Split(search, ":") {
			if dir != "" {
				candidates = append(candidates, filepath.Join(dir, command))
			}
		}
	}
	found := ""
	for _, candidate := range candidates {
		if info, err = os.Stat(candidate); err == nil && info.Mode().IsRegular() && unix.Access(candidate, unix.X_OK) == nil {
			found = candidate
			break
		}
	}
	if found == "" {
		return refuse("the command was not found")
	}
	if filepath.Base(found) == "gcloud" && len(args) > 6 {
		pair := args[5] + " " + args[6]
		switch pair {
		case "auth login", "auth activate-service-account", "auth application-default", "config set", "config configurations":
			return refuse("this wrapper does not log in or change the configuration")
		}
	}
	env["CLOUDSDK_CONFIG"], env["WITH_IDENTITY_NAME"] = directory, name
	if v, ok := table["project"]; ok {
		env["CLOUDSDK_CORE_PROJECT"] = v.(string)
	}
	if v, ok := table["key_file"]; ok {
		env["GOOGLE_APPLICATION_CREDENTIALS"] = v.(string)
	}
	variables := make([]string, 0, len(env))
	for key, value := range env {
		variables = append(variables, key+"="+value)
	}
	signal.Reset(syscall.SIGPIPE, syscall.SIGXFSZ)
	if err = syscall.Exec(found, args[4:], variables); err != nil {
		fmt.Fprintln(os.Stderr, "internal error")
		return 70
	}
	return 70
}
