// Package brief implements brief rendering without invoking the Python launcher.
package brief

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"unicode/utf8"

	protocol "laneboss.io/laneboss/src/laneboss/protocol"
)

const (
	program         = "laneboss"
	launcherVersion = "0.6.0-dev4"
	beginMarker     = "<!-- laneboss launcher block: begin"
	maxBriefBytes   = 4 * 1024 * 1024
	maxFileBytes    = 1024 * 1024
	maxInputBytes   = 8 * 1024 * 1024
)

type problem struct {
	code            int
	prefix, message string
}

func (p *problem) Error() string { return p.message }
func refused(format string, args ...any) error {
	return &problem{2, "refused", fmt.Sprintf(format, args...)}
}
func integrity(format string, args ...any) error {
	return &problem{3, "integrity problem", fmt.Sprintf(format, args...)}
}
func invalid(label, field, message string) error {
	if field == "" {
		field = "(top level)"
	}
	return &problem{2, "invalid configuration", label + ": " + field + ": " + message}
}

type options struct {
	config, lane, source, target, project string
	configSet, projectSet                 bool
	touches                               []string
}

const usage = "usage: laneboss brief render [--config NAME] --lane LANE --in BRIEF --out RENDERED [--project NAME] [--touches billing|deploy]\n"

// Run executes the brief command group. Standard input is deliberately unused:
// documents must come from checked files.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		_, err := io.WriteString(stdout, usage)
		if err != nil {
			return 70
		}
		return 0
	}
	if len(args) == 1 && args[0] == "--version" {
		_, version, err := protocol.Load()
		if err != nil {
			return report(integrity("%s", err), stderr)
		}
		return emit(map[string]any{"program": program, "version": launcherVersion, "protocol_version": version}, stdout, stderr)
	}
	if len(args) > 0 && args[0] == "render" {
		for _, arg := range args[1:] {
			if arg == "--help" || arg == "-h" {
				_, err := io.WriteString(stdout, usage)
				if err != nil {
					return 70
				}
				return 0
			}
		}
	}
	o, err := parseOptions(args)
	if err != nil {
		return report(err, stderr)
	}
	// File-size limits must produce write errors so cleanup can run.
	signal.Ignore(syscall.SIGXFSZ)
	result, err := render(o)
	if err != nil {
		return report(err, stderr)
	}
	return emit(result, stdout, stderr)
}

func report(err error, stderr io.Writer) int {
	var p *problem
	if !errors.As(err, &p) {
		fmt.Fprintln(stderr, "internal error: brief rendering failed")
		return 70
	}
	for _, line := range strings.Split(p.message, "\n") {
		fmt.Fprintln(stderr, p.prefix+": "+line)
	}
	return p.code
}

func emit(value any, stdout, stderr io.Writer) int {
	data, err := canonical(value)
	if err != nil {
		return report(err, stderr)
	}
	_, err = stdout.Write(append(data, '\n'))
	if errors.Is(err, syscall.EPIPE) {
		return 0
	}
	if err != nil {
		return report(err, stderr)
	}
	return 0
}

func parseOptions(args []string) (options, error) {
	var o options
	if len(args) == 0 || args[0] != "render" {
		return o, refused("brief: a render action is required")
	}
	seen := map[string]bool{}
	for i := 1; i < len(args); i++ {
		key, value, hasValue := strings.Cut(args[i], "=")
		switch key {
		case "--config", "--lane", "--in", "--out", "--project", "--touches":
		default:
			return o, refused("brief render: an unknown argument was supplied")
		}
		if !hasValue {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return o, refused("%s: requires a value", key)
			}
			i++
			value = args[i]
		}
		seen[key] = true
		switch key {
		case "--config":
			o.config, o.configSet = value, true
		case "--lane":
			o.lane = value
		case "--in":
			o.source = value
		case "--out":
			o.target = value
		case "--project":
			o.project, o.projectSet = value, true
		case "--touches":
			if value != "billing" && value != "deploy" {
				return o, refused("--touches: must be billing or deploy")
			}
			o.touches = append(o.touches, value)
		}
	}
	for _, key := range []string{"--lane", "--in", "--out"} {
		if !seen[key] {
			return o, refused("%s: is required", key)
		}
	}
	o.touches = uniqueSorted(o.touches)
	return o, nil
}

func uniqueSorted(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if !seen[value] {
			result = append(result, value)
			seen[value] = true
		}
	}
	sort.Strings(result)
	return result
}

func digest(data []byte) string { hash := sha256.Sum256(data); return hex.EncodeToString(hash[:]) }
func randomID() (string, error) {
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", err
	}
	data[6] = (data[6] & 0x0f) | 0x40
	data[8] = (data[8] & 0x3f) | 0x80
	return hex.EncodeToString(data[:]), nil
}

type ruleFile struct {
	path string
	data []byte
}

func ended(data []byte) []byte {
	if bytes.HasSuffix(data, []byte{'\n'}) {
		return data
	}
	return append(bytes.Clone(data), '\n')
}

func compose(c *configuration, o options, brief, protocolBytes []byte, version string, rules []ruleFile) []byte {
	project := "none"
	if o.projectSet {
		project = o.project
	}
	var result bytes.Buffer
	if len(brief) > 0 {
		result.Write(ended(brief))
	}
	result.WriteString(strings.Join([]string{
		"", beginMarker + " (protocol " + version + ") -->", "", "---", "", "# Launcher block", "",
		"Everything above this block is the brief exactly as written. " + program + " " + launcherVersion + " appended this block.", "",
		"- Configuration: " + c.name, "- Project: " + project, "- Lane: " + o.lane,
		"- Protocol version: " + version, "- Brief sha256: " + digest(brief), "", "",
	}, "\n"))
	result.Write(ended(protocolBytes))
	for _, rule := range rules {
		fmt.Fprintf(&result, "\n## Standing rules: %s (sha256 %s)\n\n", rule.path, digest(rule.data))
		result.Write(ended(rule.data))
	}
	result.WriteString("\n<!-- " + program + " launcher block: end -->\n")
	return result.Bytes()
}

func render(o options) (map[string]any, error) {
	c, z, err := bind(o)
	if err != nil {
		return nil, err
	}
	if !lanePattern.MatchString(o.lane) {
		return nil, refused("--lane: must match [a-z0-9][a-z0-9._-]{0,63}")
	}
	if o.projectSet {
		if _, ok := c.projects[o.project]; !ok {
			name := "<name>"
			if namePattern.MatchString(o.project) && findCredential(o.project) == nil {
				name = o.project
			}
			return nil, refused("--project: configuration %s has no project file projects/%s.toml", shownName(c.name), name)
		}
	}
	brief, err := z.readExternal(o.source, "--in", maxBriefBytes)
	if err != nil {
		return nil, err
	}
	if !utf8.Valid(brief) {
		return nil, refused("--in: the brief must be UTF-8 text")
	}
	text := string(brief)
	if strings.Contains(text, beginMarker) {
		return nil, refused("--in: the brief already contains a launcher block; render the original brief")
	}
	if found := findCredential(text); found != nil {
		return nil, refused("brief line %d: looks like a credential (%s); nothing was written", found.line, found.rule)
	}
	if err := checkSections(text, o.touches); err != nil {
		return nil, err
	}
	protocolBytes, version, err := protocol.Load()
	if err != nil {
		return nil, integrity("%s", err)
	}
	rules := c.rules(o)
	output := compose(c, o, brief, protocolBytes, version, rules)
	out, name, err := z.openOutput(o.target)
	if err != nil {
		return nil, err
	}
	defer out.close()
	state, err := openState(c, z)
	if err != nil {
		return nil, err
	}
	defer state.dir.close()
	unlock, err := state.dir.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	return writeRendered(state, out, name, o, version, brief, protocolBytes, rules, output)
}
