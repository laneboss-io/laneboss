// Package plugin locates the agent plugin shipped alongside the Go launcher.
package plugin

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const withheld = "[withheld]"
const usageRefused = "not accepted; a typed value is never repeated here, see the usage line above or run with --help"

func usage(stderr io.Writer, message string) int {
	fmt.Fprintln(stderr, "usage: laneboss plugin [-h] ACTION ...")
	fmt.Fprintln(stderr, "laneboss plugin: error: "+message)
	return 2
}

// resourceRoot uses the forwarding launcher's own LANEBOSS_PLUGIN_ROOT, or the
// resolved binary's location for a direct installed invocation. PYTHONPATH can
// identify an explicitly used checkout; its files are only inspected, and Python
// is never evaluated or imported by this package.
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
	for _, path := range filepath.SplitList(os.Getenv("PYTHONPATH")) {
		if !filepath.IsAbs(path) {
			continue
		}
		if info, err := os.Stat(filepath.Join(path, "laneboss", "plugincmd.py")); err == nil && info.Mode().IsRegular() {
			return filepath.Dir(filepath.Clean(path)), nil
		}
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
		return usage(stderr, "the following arguments are required: ACTION")
	}
	if args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(stdout, "usage: laneboss plugin [-h] ACTION ...\n\nLocate the plugin that ships with the launcher.\n\nActions:\n  path  the directory of the installed plugin, as one JSON value")
		return 0
	}
	if args[0] != "path" {
		return usage(stderr, "argument ACTION: "+usageRefused)
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
			return usage(stderr, "the command line was "+usageRefused)
		}
		if !attached {
			if i+1 == len(args) || strings.HasPrefix(args[i+1], "--") {
				return usage(stderr, "argument --agent: expected one argument")
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
