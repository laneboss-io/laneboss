// Package plugin locates the agent plugin shipped alongside the Go launcher.
package plugin

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"laneboss.io/laneboss/internal/cliargs"
	"laneboss.io/laneboss/internal/eventstore"
)

const withheld = "[withheld]"

func usage(stderr io.Writer, message string) int {
	fmt.Fprintln(stderr, "usage: laneboss plugin [-h] ACTION ...")
	fmt.Fprintln(stderr, "laneboss plugin: error: "+cliargs.Screen(message))
	return 2
}

// resourceRoot uses an explicit asset root or the resolved binary's location.
// The installer puts bin/laneboss and plugins/ in the same version directory.
func resourceRoot() (string, error) {
	if root := os.Getenv("LANEBOSS_PLUGIN_ROOT"); root != "" {
		if !filepath.IsAbs(root) {
			return "", fmt.Errorf("LANEBOSS_PLUGIN_ROOT must name an absolute launcher root")
		}
		real, err := filepath.EvalSymlinks(root)
		if err != nil {
			return "", fmt.Errorf("LANEBOSS_PLUGIN_ROOT does not name a readable launcher root")
		}
		return real, nil
	}
	executable, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("cannot locate the Go launcher executable")
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return "", fmt.Errorf("cannot resolve the Go launcher executable")
	}
	directory := filepath.Dir(executable)
	if filepath.Base(directory) == "bin" {
		return filepath.Dir(directory), nil
	}
	return directory, nil
}

// Run implements plugin path. It never runs an agent or alters its settings.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return usage(stderr, cliargs.Required("ACTION"))
	}
	if args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(stdout, "usage: laneboss plugin [-h] ACTION ...\n\nLocate the plugin that ships with the launcher.\n\nActions:\n  path  the directory of the installed plugin, as one JSON value\n  list  installed launcher plugins and their recorded status")
		return 0
	}
	if args[0] == "list" {
		if len(args) != 1 {
			return usage(stderr, cliargs.Reject(""))
		}
		rows, err := Inventory()
		if err != nil {
			fmt.Fprintln(stderr, "refused: installed plugins could not be read")
			return 2
		}
		if json.NewEncoder(stdout).Encode(eventstore.ScreenValue(rows)) != nil {
			return 70
		}
		return 0
	}
	if args[0] != "path" {
		return usage(stderr, cliargs.Reject("ACTION"))
	}
	agent := "claude-code"
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if arg == "--help" || arg == "-h" {
			fmt.Fprintln(stdout, "usage: laneboss plugin path [-h] [--agent AGENT]\n\n--agent AGENT  known: claude-code (default claude-code)")
			return 0
		}
		label, value, attached := strings.Cut(arg, "=")
		if !strings.HasPrefix(label, "--") || !strings.HasPrefix("--agent", label) {
			return usage(stderr, cliargs.Reject(""))
		}
		if !attached {
			if i+1 == len(args) || strings.HasPrefix(args[i+1], "--") {
				return usage(stderr, cliargs.Expected("--agent"))
			}
			i++
			value = args[i]
		}
		agent = value
	}
	if agent != "claude-code" {
		fmt.Fprintln(stderr, "refused: unknown agent; the known agents are: claude-code")
		return 2
	}
	root, err := resourceRoot()
	if err != nil {
		fmt.Fprintln(stderr, "refused: "+err.Error())
		return 2
	}
	directory := filepath.Join(root, "plugins", agent)
	if findCredential(directory) != nil {
		fmt.Fprintln(stderr, "refused: the plugin path looks like a credential; its value is withheld")
		return 2
	}
	info, err := os.Stat(directory)
	if err != nil || !info.IsDir() {
		fmt.Fprintln(stderr, "refused: the claude-code plugin is not installed with this launcher; install the launcher with scripts/install.sh from a checkout that has plugins/")
		return 2
	}
	enc := json.NewEncoder(stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(directory); err != nil {
		fmt.Fprintln(stderr, "internal error: cannot write the plugin path")
		return 70
	}
	return 0
}
