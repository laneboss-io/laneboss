package orghook

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

// The dispatcher supplies its embedded internal/cli/syntax.json at startup.
// This avoids an import cycle and never looks for source files at runtime.
// Missing or malformed syntax leaves every laneboss command opaque.
var lanebossSyntax struct {
	sync.Once
	root *hookSyntax
	err  error
}

type hookSyntax struct {
	Name     string         `json:"name"`
	Args     []hookArgument `json:"args"`
	Commands []hookSyntax   `json:"commands"`
	Hook     *cliEffects    `json:"hook"`
}

type hookArgument struct {
	Name     string         `json:"name"`
	Metavar  string         `json:"metavar"`
	Short    string         `json:"short"`
	Aliases  []string       `json:"aliases"`
	Flag     bool           `json:"flag"`
	Required bool           `json:"required"`
	Optional bool           `json:"optional"`
	Repeat   bool           `json:"repeat"`
	Type     string         `json:"type"`
	Choices  []any          `json:"choices"`
	Path     *cliPathEffect `json:"hook_path"`
}

// Path effects live beside the grammar argument, including positional operands.
type cliPathEffect struct {
	OrgHistory string `json:"org_history,omitempty"`
	Read       bool   `json:"read"`
	Write      bool   `json:"write"`
	SQLite     bool   `json:"sqlite"`
	Named      bool   `json:"named"`
	Selector   bool   `json:"selector"`
	Metadata   bool   `json:"metadata"`
}

type cliEffects struct {
	State  string              `json:"state"`
	Config string              `json:"config"`
	Reads  []string            `json:"reads"`
	Limits map[string][]string `json:"limits"`
	Report bool                `json:"report"`
}

type cliCall struct {
	effects   *cliEffects
	values    map[string][]string
	reads     []string
	writes    []string
	metadata  []string
	databases []string
	history   map[string]string
	partial   bool
	help      bool
	version   bool
}

// SetLanebossSyntax is called once during executable initialization. Both the
// unified CLI and the retained org executable supply the same embedded bytes.
func SetLanebossSyntax(data []byte) error {
	lanebossSyntax.Do(func() {
		var root hookSyntax
		if err := json.Unmarshal(data, &root); err != nil {
			lanebossSyntax.err = invalid("the embedded laneboss syntax is malformed")
			return
		}
		if root.Name != "laneboss" || len(root.Commands) == 0 {
			lanebossSyntax.err = invalid("the embedded laneboss syntax has no command tree")
			return
		}
		lanebossSyntax.root = &root
	})
	return lanebossSyntax.err
}

func hookOption(node *hookSyntax, name string) *hookArgument {
	for index := range node.Args {
		argument := &node.Args[index]
		if strings.HasPrefix(argument.Name, "-") &&
			(argument.Name == name || argument.Short == name || contains(argument.Aliases, name)) {
			return argument
		}
	}
	return nil
}

func hookValue(argument hookArgument, value string) bool {
	if argument.Type != "" {
		number, err := strconv.ParseInt(value, 10, 64)
		if err != nil || argument.Type == "positive" && number <= 0 ||
			argument.Type == "non_negative" && number < 0 {
			return false
		}
	}
	if len(argument.Choices) == 0 {
		return true
	}
	for _, choice := range argument.Choices {
		if value == fmt.Sprint(choice) {
			return true
		}
	}
	return false
}

// Parse only literal, declared spellings. Unlike the root help parser this
// inspector does not guess abbreviated options, or accept unknown arguments.
func parseHookCLI(node *hookSyntax, words []string, call *cliCall) bool {
	positions := []hookArgument{}
	for _, argument := range node.Args {
		if !strings.HasPrefix(argument.Name, "-") {
			positions = append(positions, argument)
		}
	}
	seen := map[string]bool{}
	position, literal := 0, false
	for index := 0; index < len(words); index++ {
		word := words[index]
		if !literal && word == "--" {
			if len(node.Commands) > 0 {
				return false
			}
			literal = true
			continue
		}
		if !literal && strings.HasPrefix(word, "-") && word != "-" {
			name, value, joined := strings.Cut(word, "=")
			argument := hookOption(node, name)
			if argument == nil || seen[argument.Name] && !argument.Repeat {
				return false
			}
			if argument.Flag {
				if joined {
					return false
				}
				value = "true"
				if argument.Name == "--help" {
					call.help = true
					return true
				}
				if argument.Name == "--version" {
					call.version = true
				}
			} else {
				if !joined {
					index++
					if index == len(words) || strings.HasPrefix(words[index], "--") {
						return false
					}
					value = words[index]
				}
				if value == "" || !hookValue(*argument, value) {
					return false
				}
			}
			seen[argument.Name] = true
			call.values[argument.Name] = append(call.values[argument.Name], value)
			if !call.pathEffects(*argument, value) {
				return false
			}
			continue
		}
		if position < len(positions) {
			argument := positions[position]
			if !hookValue(argument, word) {
				return false
			}
			seen[argument.Name] = true
			call.values[argument.Name] = append(call.values[argument.Name], word)
			if !call.pathEffects(argument, word) {
				return false
			}
			position++
			continue
		}
		for child := range node.Commands {
			if node.Commands[child].Name == word {
				return parseHookCLI(&node.Commands[child], words[index+1:], call)
			}
		}
		return false
	}
	for _, argument := range node.Args {
		if argument.Required && !seen[argument.Name] {
			return false
		}
	}
	call.effects = node.Hook
	return true
}

func (call *cliCall) pathEffects(argument hookArgument, value string) bool {
	effect := argument.Path
	if effect == nil || value == "-" {
		return true
	}
	if effect.Named {
		name, path, ok := strings.Cut(value, "=")
		if !ok || name == "" || path == "" {
			return false
		}
		value = path
	}
	if effect.Selector && historyInstanceName(value) {
		return true // An instance name selects implicit org policy, not a path operand.
	}
	if effect.OrgHistory != "" {
		if call.history == nil {
			call.history = map[string]string{}
		}
		call.history[value] = effect.OrgHistory
	}
	if effect.Read {
		call.reads = append(call.reads, value)
	}
	if effect.Metadata {
		call.metadata = append(call.metadata, value)
	}
	if effect.Write && !effect.SQLite {
		appendLanebossWrite(&call.writes, value)
	}
	if effect.SQLite {
		call.databases = append(call.databases, value)
	}
	return true
}

// decisionsrv.discover treats slash-containing and .toml selectors as paths;
// its bare-name branch accepts only this 64-character identity grammar.
func historyInstanceName(value string) bool {
	if len(value) == 0 || len(value) > 64 || strings.HasSuffix(value, ".toml") {
		return false
	}
	for index, c := range value {
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			continue
		}
		if index == 0 || !strings.ContainsRune("._-", c) {
			return false
		}
	}
	return true
}

func inspectCLI(words []string) (cliCall, bool) {
	call := cliCall{values: map[string][]string{}}
	if lanebossSyntax.root == nil || !parseHookCLI(lanebossSyntax.root, words, &call) {
		return call, false
	}
	if call.help || call.version {
		return call, true
	}
	if call.effects == nil || !contains([]string{"read", "write"}, call.effects.State) {
		call.partial = true
		return call, true
	}
	for name, choices := range call.effects.Limits {
		for _, value := range call.values[name] {
			if !contains(choices, value) {
				call.partial = true
			}
		}
	}
	return call, true
}

// LanebossFlag lets a rendered brief name an optional command flag only when
// the same embedded grammar used by the hook actually declares that flag.
func LanebossFlag(path []string, flag string) bool {
	node := lanebossSyntax.root
	if node == nil {
		return false
	}
	for _, name := range path {
		var child *hookSyntax
		for index := range node.Commands {
			if node.Commands[index].Name == name {
				child = &node.Commands[index]
				break
			}
		}
		if child == nil {
			return false
		}
		node = child
	}
	argument := hookOption(node, flag)
	return argument != nil && argument.Flag
}
