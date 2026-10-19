package orghook

import (
	"errors"
	"strings"

	"laneboss.io/laneboss/internal/faults"
)

// Conditions are never evaluated. Every simple command in every arm contributes
// its existing file effects, even when a literal condition looks true or false.
type compoundParser struct {
	tokens      []shellToken
	index       int
	directory   string
	directories []string
	uncertain   bool
	depth       int
}

func (p *compoundParser) candidateDirectories() []string {
	return uniqueDirectories(append([]string{p.directory}, p.directories...)...)
}

func (p *compoundParser) attachDirectories(commands []command) {
	directories := p.candidateDirectories()
	for index := range commands {
		commands[index].directories = directories
		commands[index].directoryUncertain = commands[index].directoryUncertain || p.uncertain || len(directories) > 1
	}
}

func shellKeyword(token shellToken, words ...string) bool {
	return !token.operator && !token.quoted && contains(words, token.word)
}

func inspectShell(text, directory string, depth int) ([]command, error) {
	if strings.TrimSpace(text) == "" || len(text) > maxCommand || strings.ContainsAny(text, "\x00\r") {
		return nil, invalid("a shell command is empty, invalid or exceeds the inspection limit")
	}
	tokens, err := lexShell(strings.TrimRight(text, " \t\n"))
	if err != nil {
		p := compoundParser{tokens: tokens, directory: directory, directories: []string{directory}, depth: depth}
		commands, _ := p.list(nil, 0)
		return commands, err
	}
	structured, boundary := false, true
	for index, token := range tokens {
		if token.operator {
			if contains([]string{"(", ")", "&", "|&", ";;"}, token.word) {
				p := compoundParser{tokens: tokens[:index], directory: directory, directories: []string{directory}, depth: depth}
				commands, _ := p.list(nil, 0)
				return commands, invalid("unsupported shell command control syntax cannot be inspected")
			}
			if contains([]string{";", "\n", "&&", "||", "|"}, token.word) {
				structured, boundary = true, true
			}
			continue
		}
		if boundary {
			structured = structured || shellKeyword(token, "if", "then", "elif", "else", "fi", "!", "test", "[", "[[")
		}
		boundary = false
	}
	if !structured {
		return inspectFlatShell(text, directory, depth)
	}
	p := compoundParser{tokens: tokens, directory: directory, directories: []string{directory}, depth: depth}
	commands, err := p.list(nil, 0)
	if err != nil || p.index != len(tokens) {
		if err == nil {
			err = invalid("a compound shell command is incomplete")
		}
		return commands, err
	}
	return commands, nil
}

func (p *compoundParser) keyword(words ...string) bool {
	return p.index < len(p.tokens) && shellKeyword(p.tokens[p.index], words...)
}

func (p *compoundParser) operator(words ...string) bool {
	return p.index < len(p.tokens) && p.tokens[p.index].operator && contains(words, p.tokens[p.index].word)
}

func (p *compoundParser) newlines() {
	for p.operator("\n") {
		p.index++
	}
}

func (p *compoundParser) list(until []string, nesting int) ([]command, error) {
	if nesting > 32 {
		return nil, invalid("a compound shell command exceeds the nesting limit")
	}
	p.newlines()
	commands := []command{}
	var firstErr error
	for p.index < len(p.tokens) && !p.keyword(until...) {
		part, err := p.chain(nesting)
		commands = append(commands, part...)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			for p.index < len(p.tokens) && !p.operator(";", "\n") {
				p.index++
			}
			if p.operator(";", "\n") {
				p.index++
				p.newlines()
			}
			continue
		}
		if p.index == len(p.tokens) {
			break
		}
		if !p.operator(";", "\n") {
			if firstErr == nil {
				firstErr = invalid("compound shell commands need a command separator")
			}
			break
		}
		p.index++
		p.newlines()
	}
	if len(commands) == 0 {
		return nil, invalid("a compound shell branch has no command")
	}
	return commands, firstErr
}

func (p *compoundParser) chain(nesting int) ([]command, error) {
	commands := []command{}
	pipe := false
	var firstErr error
	for {
		if pipe && p.keyword("!") {
			if firstErr == nil {
				firstErr = invalid("pipeline negation must precede the pipeline")
			}
			return commands, firstErr
		}
		for p.keyword("!") {
			p.index++
		}
		part, err := p.command(nesting)
		commands = append(commands, part...)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			// Keep inspecting the rest of this &&, || or | chain. The failed
			// segment makes every later directory candidate uncertain, but its
			// error remains visible to the caller as an observation gap.
			p.uncertain = true
		}
		if !p.operator("&&", "||", "|") {
			return commands, firstErr
		}
		pipe = p.operator("|")
		if p.operator("||", "|") {
			// The preceding directory change may not affect this arm or pipeline.
			p.uncertain = p.uncertain || commandsChangeState(part)
		}
		p.index++
		p.newlines()
	}
}

func (p *compoundParser) command(nesting int) ([]command, error) {
	if p.keyword("if") {
		directory, uncertain := p.directory, p.uncertain
		p.index++
		commands := []command{}
		for {
			condition, err := p.list([]string{"then"}, nesting+1)
			commands = append(commands, condition...)
			if err != nil || !p.keyword("then") {
				return commands, invalid("a shell if condition needs then")
			}
			p.index++
			body, err := p.list([]string{"elif", "else", "fi"}, nesting+1)
			commands = append(commands, body...)
			if err != nil {
				return commands, err
			}
			if !p.keyword("elif") {
				break
			}
			p.index++
			p.directory, p.uncertain = directory, uncertain || commandsChangeState(condition)
		}
		if p.keyword("else") {
			p.directory, p.uncertain = directory, uncertain
			p.index++
			elseCommands, err := p.list([]string{"fi"}, nesting+1)
			commands = append(commands, elseCommands...)
			if err != nil {
				return commands, err
			}
		}
		if !p.keyword("fi") {
			return commands, invalid("a shell if command needs fi")
		}
		p.index++
		p.directory, p.uncertain = directory, uncertain || commandsChangeState(commands)
		return commands, nil
	}
	if p.index == len(p.tokens) || p.keyword("then", "elif", "else", "fi", "for", "while", "until", "case", "function", "select", "do", "done", "{") {
		return nil, invalid("unsupported or incomplete shell command structure cannot be inspected")
	}
	if p.keyword("[[") {
		start := p.index
		p.index++
		arguments := []string{}
		reads := []string{}
		for p.index < len(p.tokens) && !p.keyword("]]") {
			token := p.tokens[p.index]
			if token.operator {
				part, ok := testEffects(arguments)
				if !contains([]string{"&&", "||"}, token.word) || !ok || len(arguments) == 0 {
					return nil, invalid("extended shell test operators cannot be inspected")
				}
				reads = append(reads, part...)
				arguments = nil
			} else {
				arguments = append(arguments, token.word)
			}
			p.index++
		}
		part, ok := testEffects(arguments)
		if !ok || len(arguments) == 0 || !p.keyword("]]") {
			return nil, invalid("an extended shell test needs literal operands and closing brackets")
		}
		reads = append(reads, part...)
		p.index++
		argv := []string{}
		for _, token := range p.tokens[start:p.index] {
			argv = append(argv, token.word)
		}
		return []command{{argv: argv, directory: p.directory, metadata: reads}}, nil
	}
	start := p.index
	for p.index < len(p.tokens) && !p.operator(";", "\n", "&&", "||", "|") {
		p.index++
	}
	commands, err := inspectCompoundSimple(p.tokens[start:p.index], p.directory, p.depth)
	for index := range commands {
		commands[index].directoryUncertain = p.uncertain
	}
	p.attachDirectories(commands)
	if err != nil {
		return commands, err
	}
	for _, cmd := range commands {
		if len(cmd.argv) == 0 || !cmd.changesState {
			continue
		}
		if !contains([]string{"cd", "chdir", "pushd"}, cmd.argv[0]) {
			p.uncertain = true
			continue
		}
		targets := operands(cmd.argv[1:], nil)
		if len(targets) != 1 {
			p.uncertain = true
			continue
		}
		candidate, err := pathAt(targets[0], p.directory)
		if err != nil {
			p.uncertain = true
			continue
		}
		p.directories = uniqueDirectories(append(p.directories, candidate)...)
		if faults.Get("orghook-bl-cd-unconditional").Point != "" {
			_ = faults.Reach("orghook-bl-cd-unconditional")
			p.directories = []string{candidate}
			p.uncertain = false
		}
		if isDirectory(candidate) {
			p.directory = candidate
		} else {
			p.uncertain = true
		}
	}
	return commands, nil
}

func commandsChangeState(commands []command) bool {
	for _, cmd := range commands {
		if cmd.changesState {
			return true
		}
	}
	return false
}

func inspectCompoundSimple(tokens []shellToken, directory string, depth int) ([]command, error) {
	argv, writes, reads := []string{}, []string{}, []string{}
	var scanErr error
	partial := func(err error) ([]command, error) {
		resolved, _ := resolveShellCommand(argv)
		commands := []command{{argv: rawEffectiveWords(argv), directory: directory, writes: writes, reads: reads, opaque: true, changesState: resolved.changesState}}
		if effect, ok := literalWriteCommand(argv, directory); ok {
			effect.opaque = true
			commands = append(commands, effect)
		}
		return commands, err
	}
	for index := 0; index < len(tokens); index++ {
		token := tokens[index]
		if !token.operator {
			if token.word != "" && token.word != "[" && token.word != "]" && !literalReadValue(token.word) {
				argv = append(argv, token.word)
				if scanErr == nil {
					scanErr = invalid("compound shell command arguments must be literal without expansions or globs")
				}
				continue
			}
			argv = append(argv, token.word)
			continue
		}
		op := strings.TrimLeft(token.word, "0123456789")
		if !contains([]string{"<", ">", ">>", ">|", "<>", "&>", "&>>", "<&", ">&"}, op) || index+1 >= len(tokens) || tokens[index+1].operator {
			return partial(invalid("a compound shell redirection cannot be inspected"))
		}
		index++
		target := tokens[index].word
		if strings.HasPrefix(target, "!") {
			// zsh reads >!, >>!, &>! and >&! as clobbering redirections to the rest of the word.
			if scanErr == nil {
				scanErr = invalid("a zsh clobber redirection cannot be inspected")
			}
			target = strings.TrimPrefix(target, "!")
			if target == "" && index+1 < len(tokens) && !tokens[index+1].operator {
				index++
				target = tokens[index].word
			}
		}
		if target == "" || !literalReadValue(target) {
			if scanErr == nil {
				scanErr = invalid("a compound shell redirection needs a literal target")
			}
			continue
		}
		if (contains([]string{">", ">>", ">|", "<>", "&>", "&>>"}, op) || (op == ">&" && !digits(target) && target != "-")) && !standardOutputTarget(target) {
			writes = append(writes, target)
		}
		if op == "<" || op == "<>" {
			reads = append(reads, target)
		}
		if op == "<&" && !digits(target) && target != "-" {
			return partial(invalid("an input descriptor redirection cannot be inspected"))
		}
	}
	inspected, err := inspectArgv(argv, directory, depth)
	if scanErr != nil {
		err = scanErr
	}
	head := command{argv: rawEffectiveWords(argv), directory: directory, reads: reads, writes: writes}
	if len(inspected) > 0 {
		head.argv = inspected[0].argv
	}
	if err != nil {
		head.opaque = true
		// Only a nested body may degrade to opaque. The enclosing argv and
		// redirect targets must all have passed their own literal checks.
		var nested *nestedInspectionError
		if scanErr == nil && errors.As(err, &nested) && !errors.Is(err, errObscuredShellDepth) {
			for index := range inspected {
				inspected[index].opaque = true
			}
			return append([]command{head}, inspected...), nil
		}
		return append([]command{head}, inspected...), err
	}
	return append([]command{head}, inspected...), nil
}

// Only fixed-arity predicates shared by bash and zsh are modeled. Numeric
// comparisons take integer literals, never shell arithmetic or variable names.
func testEffects(arguments []string) ([]string, bool) {
	for len(arguments) > 0 && arguments[0] == "!" {
		arguments = arguments[1:]
	}
	for _, word := range arguments {
		if word != "" && !literalReadValue(word) {
			return nil, false
		}
	}
	switch len(arguments) {
	case 0, 1:
		return nil, true
	case 2:
		switch arguments[0] {
		case "-b", "-c", "-d", "-e", "-f", "-g", "-h", "-k", "-L", "-O", "-G", "-p", "-r", "-s", "-S", "-u", "-w", "-x":
			return []string{arguments[1]}, true
		case "-n", "-z":
			return nil, true
		case "-t":
			return nil, digits(arguments[1])
		}
	case 3:
		switch arguments[1] {
		case "=", "==", "!=":
			return nil, true
		case "-nt", "-ot", "-ef":
			return []string{arguments[0], arguments[2]}, true
		case "-eq", "-ne", "-lt", "-le", "-gt", "-ge":
			return nil, integerTestLiteral(arguments[0]) && integerTestLiteral(arguments[2])
		}
	}
	return nil, false
}

func integerTestLiteral(word string) bool {
	if strings.HasPrefix(word, "+") || strings.HasPrefix(word, "-") {
		word = word[1:]
	}
	return digits(word)
}
