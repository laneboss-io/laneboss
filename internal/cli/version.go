package cli

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"strings"
	"unicode"
)

// The syntax tree preserves the launcher's parser declarations. It is used only
// for root options, including --version before a command: parsing must finish
// without executing that command or reading its configuration.
//
//go:embed syntax.json
var syntaxData []byte

type argumentSyntax struct {
	Name      string `json:"name"`
	Short     string `json:"short"`
	Metavar   string `json:"metavar"`
	Help      string `json:"help"`
	Type      string `json:"type"`
	Choices   []any  `json:"choices"`
	Flag      bool   `json:"flag"`
	Optional  bool   `json:"optional"`
	Required  bool   `json:"required"`
	Exclusive int    `json:"exclusive"`
}

type exclusiveSyntax struct {
	Required bool     `json:"required"`
	Names    []string `json:"names"`
}

type commandSyntax struct {
	Name               string            `json:"name"`
	Description        string            `json:"description"`
	Help               string            `json:"help"`
	Args               []argumentSyntax  `json:"args"`
	Commands           []commandSyntax   `json:"commands"`
	Exclusive          []exclusiveSyntax `json:"exclusive"`
	Subcommand         string            `json:"subcommand"`
	SubcommandRequired bool              `json:"subcommand_required"`
}

var rootSyntax = func() commandSyntax {
	var root commandSyntax
	if err := json.Unmarshal(syntaxData, &root); err != nil {
		panic("invalid embedded command syntax")
	}
	return root
}()

var negativeNumber = regexp.MustCompile(`^-[0-9]+$|^-[0-9]*\.[0-9]+$`)
var decimalInteger = regexp.MustCompile(`^[+-]?[0-9]+(_[0-9]+)*$`)

func (a argumentSyntax) positional() bool { return !strings.HasPrefix(a.Name, "-") }
func (a argumentSyntax) label() string {
	if a.positional() {
		return a.metavar()
	}
	if a.Short != "" {
		return a.Short + "/" + a.Name
	}
	return a.Name
}
func (a argumentSyntax) metavar() string {
	if a.Metavar != "" {
		return a.Metavar
	}
	if len(a.Choices) > 0 {
		parts := make([]string, len(a.Choices))
		for i, choice := range a.Choices {
			parts[i] = fmt.Sprint(choice)
		}
		return "{" + strings.Join(parts, ",") + "}"
	}
	if a.positional() {
		return a.Name
	}
	return strings.ToUpper(strings.ReplaceAll(strings.TrimLeft(a.Name, "-"), "-", "_"))
}

func syntaxError(p *commandSyntax, path, message string, stderr io.Writer) int {
	fmt.Fprint(stderr, syntaxUsage(p, path))
	fmt.Fprintln(stderr, path+": error: "+message)
	return 2
}

func optionLike(arg string) bool {
	return len(arg) > 1 && strings.HasPrefix(arg, "-") && !negativeNumber.MatchString(arg) && !strings.Contains(arg, " ")
}

func matchOption(p *commandSyntax, arg string) (*argumentSyntax, string, bool, bool) {
	label, value, attached := strings.Cut(arg, "=")
	for i := range p.Args {
		a := &p.Args[i]
		if !a.positional() && (a.Name == label || a.Short == label) {
			return a, value, attached, false
		}
	}
	var found *argumentSyntax
	if strings.HasPrefix(label, "--") {
		for i := range p.Args {
			a := &p.Args[i]
			if !a.positional() && strings.HasPrefix(a.Name, label) {
				if found != nil {
					return nil, "", false, true
				}
				found = a
			}
		}
		return found, value, attached, false
	}
	if strings.HasPrefix(arg, "-h") {
		for i := range p.Args {
			if p.Args[i].Short == "-h" {
				// A cluster containing only -h options is a valid help request.
				tail := arg[2:]
				if strings.Trim(tail, "h") == "" {
					return &p.Args[i], "", false, false
				}
				return &p.Args[i], tail, true, false
			}
		}
	}
	return nil, "", false, false
}

// parseSyntax returns -1 after successful parsing, or a final help/error status.
// The second result says whether unknown options or surplus arguments remain.
func parseSyntax(p *commandSyntax, path string, args []string, stdout, stderr io.Writer, version *bool) (int, bool) {
	seen := map[string]bool{}
	var positional []argumentSyntax
	for _, a := range p.Args {
		if a.positional() {
			positional = append(positional, a)
		}
	}
	position, unknown, literal, selected := 0, false, false, false
	fail := func(message string) (int, bool) { return syntaxError(p, path, message, stderr), false }
	mark := func(a argumentSyntax) string {
		if a.Exclusive > 0 {
			for _, name := range p.Exclusive[a.Exclusive-1].Names {
				if name != a.Name && seen[name] {
					return "argument " + a.label() + ": not allowed with argument " + name
				}
			}
		}
		seen[a.Name] = true
		return ""
	}
	// argparse identifies ambiguous options before executing a help action.
	for _, arg := range args {
		if arg == "--" {
			break
		}
		if optionLike(arg) {
			_, _, _, ambiguous := matchOption(p, arg)
			if ambiguous {
				return fail("the command line was " + refused)
			}
		}
		// Subparsers take over all arguments after their action token.
		if !optionLike(arg) && p.Subcommand != "" {
			break
		}
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !literal && arg == "--" && p.Subcommand == "" {
			literal = true
			continue
		}
		if !literal && optionLike(arg) && arg != "--" {
			a, value, attached, ambiguous := matchOption(p, arg)
			if ambiguous {
				return fail("the command line was " + refused)
			}
			if a == nil {
				unknown = true
				continue
			}
			if a.Flag {
				if attached {
					return fail("argument " + a.label() + ": " + refused)
				}
				if a.Name == "--help" {
					return write(stdout, stderr, syntaxHelp(p, path)), false
				}
				if a.Name == "--version" {
					*version = true
				}
			} else {
				if !attached {
					if i+1 == len(args) || optionLike(args[i+1]) {
						return fail("argument " + a.label() + ": expected one argument")
					}
					i++
					value = args[i]
				}
				if !syntaxValue(*a, value) {
					return fail("argument " + a.label() + ": " + refused)
				}
			}
			if message := mark(*a); message != "" {
				return fail(message)
			}
			continue
		}
		if position < len(positional) {
			a := positional[position]
			if !syntaxValue(a, arg) {
				return fail("argument " + a.label() + ": " + refused)
			}
			if message := mark(a); message != "" {
				return fail(message)
			}
			position++
			continue
		}
		if p.Subcommand != "" && !selected {
			var child *commandSyntax
			for j := range p.Commands {
				if p.Commands[j].Name == arg {
					child = &p.Commands[j]
					break
				}
			}
			if child == nil {
				return fail("argument " + p.Subcommand + ": " + refused)
			}
			status, extra := parseSyntax(child, path+" "+arg, args[i+1:], stdout, stderr, version)
			if status >= 0 {
				return status, false
			}
			unknown = unknown || extra
			selected = true
			break
		}
		unknown = true
	}
	var missing []string
	for _, a := range p.Args {
		if a.Required && !seen[a.Name] {
			missing = append(missing, a.label())
		}
	}
	if p.SubcommandRequired && !selected {
		missing = append(missing, p.Subcommand)
	}
	if len(missing) > 0 {
		return fail("the following arguments are required: " + strings.Join(missing, ", "))
	}
	for _, group := range p.Exclusive {
		found := false
		for _, name := range group.Names {
			found = found || seen[name]
		}
		if group.Required && !found {
			return fail("one of the arguments " + strings.Join(group.Names, " ") + " is required")
		}
	}
	return -1, unknown
}

func syntaxValue(a argumentSyntax, value string) bool {
	if a.Type != "" {
		// Decimal input accepts the same surrounding whitespace and digit
		// separators as the original integer argument types.
		value = strings.TrimSpace(value)
		var normalized strings.Builder
		digits := 0
		for _, r := range value {
			if unicode.IsDigit(r) {
				digits++
				if r > '9' {
					for _, span := range unicode.Digit.R16 {
						if uint32(r) >= uint32(span.Lo) && uint32(r) <= uint32(span.Hi) && (uint32(r)-uint32(span.Lo))%uint32(span.Stride) == 0 {
							r = '0' + rune((uint32(r)-uint32(span.Lo))/uint32(span.Stride)%10)
							break
						}
					}
					if r > '9' {
						for _, span := range unicode.Digit.R32 {
							if uint32(r) >= span.Lo && uint32(r) <= span.Hi && (uint32(r)-span.Lo)%span.Stride == 0 {
								r = '0' + rune((uint32(r)-span.Lo)/span.Stride%10)
								break
							}
						}
					}
				}
			}
			normalized.WriteRune(r)
		}
		value = normalized.String()
		if digits > 4300 || !decimalInteger.MatchString(value) {
			return false
		}
		n, ok := new(big.Int).SetString(strings.ReplaceAll(value, "_", ""), 10)
		if !ok || a.Type == "non_negative" && n.Sign() < 0 || a.Type == "positive" && n.Sign() <= 0 {
			return false
		}
		value = n.String()
	}
	if len(a.Choices) == 0 {
		return true
	}
	for _, choice := range a.Choices {
		if fmt.Sprint(choice) == value {
			return true
		}
	}
	return false
}
