package hookconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const CodexEnable = "features.hooks=true"
const CodexFeatureRefusal = "Codex hooks feature must be enabled: the selected binary must report hooks on with the lane's configuration flags"
const CodexPluginRefusal = "Codex plugins feature must be disabled: the selected binary must report plugins off with the lane's configuration flags"

// CodexGate is owned by one planned run, never a process-global or disk cache.
type CodexGate struct {
	checked map[string]bool
	// LaneSandbox is supplied by the configuration-owned Darwin wrapper plan,
	// never by a runner argument or environment variable.
	LaneSandbox bool
}

type probeOutput struct {
	bytes.Buffer
	overflow bool
}

func (b *probeOutput) Write(data []byte) (int, error) {
	n := len(data)
	left := 65536 - b.Len()
	if len(data) > left {
		b.overflow = true
		data = data[:left]
	}
	b.Buffer.Write(data)
	return n, nil
}

func probeCodex(path, cwd string, environment, args []string, laneSandbox ...bool) (string, error) {
	if err := vetSandboxArgs(args, laneSandbox...); err != nil {
		return "", err
	}
	if err := VetCodexEnvironment(environment); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Dir, cmd.Env = cwd, environment
	cmd.WaitDelay = 2 * time.Second
	var output probeOutput
	cmd.Stdout, cmd.Stderr = &output, io.Discard
	if cmd.Run() != nil || output.overflow {
		return "", errors.New(CodexFeatureRefusal)
	}
	return output.String(), nil
}

func codexPath(name, cwd, search string) (string, error) {
	candidates := []string{name}
	if !strings.ContainsRune(name, filepath.Separator) {
		candidates = nil
		for _, directory := range filepath.SplitList(search) {
			candidates = append(candidates, filepath.Join(directory, name))
		}
	}
	for _, candidate := range candidates {
		if !filepath.IsAbs(candidate) {
			candidate = filepath.Join(cwd, candidate)
		}
		info, err := os.Stat(candidate)
		if err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
			return filepath.Abs(candidate)
		}
	}
	return "", errors.New(CodexFeatureRefusal)
}

// Prepare pins the executable, adds the product flag and probes that exact invocation.
// Literal env wrappers are retained; their assignments also apply to both probes.
func (g *CodexGate) Prepare(argv []string, cwd string, environment []string) ([]string, error) {
	for _, word := range argv {
		if strings.Contains(word, CodexTrustBypass) {
			return nil, errors.New("caller-supplied hook trust bypass is refused")
		}
	}
	if len(argv) == 0 {
		return argv, nil
	}
	effective := map[string]string{}
	for _, word := range environment {
		if key, value, ok := strings.Cut(word, "="); ok {
			effective[key] = value
		}
	}
	scope := launcherScope(effective)
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
					return nil, errors.New(CodexFeatureRefusal)
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
				return nil, errors.New("Claude/Codex env wrapper has unsupported options; use literal environment assignments")
			}
			if key, value, ok := strings.Cut(word, "="); ok {
				effective[key] = value
				index++
				continue
			}
			break
		}
	}
	if index >= len(argv) || !strings.HasPrefix(filepath.Base(argv[index]), "codex") {
		for _, word := range argv {
			for _, token := range strings.Fields(word) {
				if strings.HasPrefix(filepath.Base(strings.Trim(token, "\"';|&()")), "codex") {
					return nil, errors.New("wrapped Codex launches are refused; use a direct Codex command with literal env assignments")
				}
			}
		}
		return argv, nil
	}
	if err := vetEnvironment(effective); err != nil {
		return nil, err
	}
	if err := vetLauncherScope(scope, effective); err != nil {
		return nil, err
	}
	if err := vetLanePath(effective["CODEX_HOME"], cwd, effective); err != nil {
		return nil, err
	}
	path, err := codexPath(argv[index], cwd, effective["PATH"])
	if err != nil {
		return nil, err
	}
	prepared := append([]string{}, argv[:index]...)
	prepared = append(prepared, path, "-c", CodexEnable)
	runnerArgs := argv[index+1:]
	if g.LaneSandbox {
		if err := vetSandboxArgs(runnerArgs, true); err != nil {
			return nil, err
		}
		runnerArgs, err = replaceCodexSandbox(runnerArgs)
		if err != nil {
			return nil, err
		}
		prepared = append(prepared, "--sandbox", "danger-full-access")
	}
	prepared = append(prepared, runnerArgs...)
	flags := []string{}
	for i := index + 1; i < len(prepared); i++ {
		word := prepared[i]
		if word == "--" {
			break
		}
		switch word {
		case "-c", "--config", "--enable", "--disable", "-p", "--profile", "-C", "--cd", "--sandbox", "-s":
			if i+1 >= len(prepared) {
				return nil, errors.New(CodexFeatureRefusal)
			}
			flags = append(flags, word, prepared[i+1])
			i++
		default:
			if strings.HasPrefix(word, "-C") && len(word) > 2 {
				return nil, errors.New("Codex directory overrides cannot be vetted; use the lane worktree")
			}
			if strings.HasPrefix(word, "-p") && !strings.HasPrefix(word, "--") && len(word) > 2 {
				flags = append(flags, "-p", strings.TrimPrefix(word[2:], "="))
				continue
			}
			if strings.HasPrefix(word, "--config=") || strings.HasPrefix(word, "--enable=") || strings.HasPrefix(word, "--disable=") || strings.HasPrefix(word, "--profile=") || strings.HasPrefix(word, "--cd=") || (strings.HasPrefix(word, "-c") && len(word) > 2) {
				flags = append(flags, word)
			}
		}
	}
	if err := vetConfigArgs(flags, g.LaneSandbox); err != nil {
		return nil, err
	}
	if err := vetSandboxArgs(prepared[index+1:], g.LaneSandbox); err != nil {
		return nil, err
	}
	if _, err := writableRootsIn(filepath.Join(effective["CODEX_HOME"], "config.toml"), cwd, g.LaneSandbox, effective, prepared[index+1:]); err != nil {
		return nil, err
	}
	if err := vetCodexIn(effective["CODEX_HOME"], cwd, effective, effective["HOME"]); err != nil {
		return nil, err
	}
	if err := renderStateRoot(effective["CODEX_HOME"], effective); err != nil {
		return nil, err
	}
	if err := vetCodexIn(effective["CODEX_HOME"], cwd, effective, effective["HOME"]); err != nil {
		return nil, err
	}
	verb := -1
	for i := index + 1; i < len(prepared); i++ {
		if prepared[i] == CodexTrustBypass {
			return nil, errors.New("hook trust bypass is supplied only by laneboss after vetting")
		}
		if prepared[i] == "exec" && verb == -1 {
			verb = i
		}
	}
	if verb == -1 {
		return nil, errors.New("headless Codex lanes must use codex exec")
	}
	prepared = append(prepared[:verb+1], append([]string{CodexTrustBypass, "--disable", "plugins"}, prepared[verb+1:]...)...)
	flags = append(flags, "--disable", "plugins")
	probeEnv := make([]string, 0, len(effective))
	for key, value := range effective {
		probeEnv = append(probeEnv, key+"="+value)
	}
	version, err := probeCodex(path, cwd, probeEnv, append(append([]string{}, flags...), "--version"), g.LaneSandbox)
	if err != nil || !regexp.MustCompile(`[0-9]+\.[0-9]+\.[0-9]+`).MatchString(version) {
		return nil, errors.New(CodexFeatureRefusal)
	}
	keyBytes, _ := json.Marshal([]any{path, version, cwd, flags, effective["CODEX_HOME"]})
	key := string(keyBytes)
	if g.checked[key] {
		return prepared, nil
	}
	output, err := probeCodex(path, cwd, probeEnv, append(append([]string{}, flags...), "features", "list"), g.LaneSandbox)
	if err != nil {
		return nil, err
	}
	count, enabled := 0, false
	pluginCount, disabled := 0, false
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "hooks" {
			count++
			enabled = fields[len(fields)-1] == "true"
		}
		if len(fields) >= 3 && fields[0] == "plugins" {
			pluginCount++
			disabled = fields[len(fields)-1] == "false"
		}
	}
	if count != 1 || !enabled {
		return nil, errors.New(CodexFeatureRefusal)
	}
	if pluginCount != 1 || !disabled {
		return nil, errors.New(CodexPluginRefusal)
	}
	if g.checked == nil {
		g.checked = map[string]bool{}
	}
	g.checked[key] = true
	return prepared, nil
}
