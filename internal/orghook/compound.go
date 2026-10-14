package orghook

import "strings"

// Conditions are never evaluated. Every simple command in every arm contributes
// its existing file effects, even when a literal condition looks true or false.
type compoundParser struct {
	tokens    []shellToken
	index     int
	directory string
	depth     int
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
		return nil, err
	}
	structured, boundary := false, true
	for _, token := range tokens {
		if token.operator {
			if contains([]string{"(", ")", "&", "|&", ";;"}, token.word) {
				return nil, invalid("unsupported shell command control syntax cannot be inspected")
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
	p := compoundParser{tokens: tokens, directory: directory, depth: depth}
	commands, err := p.list(nil, 0)
	if err != nil || p.index != len(tokens) {
		if err == nil {
			err = invalid("a compound shell command is incomplete")
		}
		return nil, err
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
	for p.index < len(p.tokens) && !p.keyword(until...) {
		part, err := p.chain(nesting)
		if err != nil {
			return nil, err
		}
		commands = append(commands, part...)
		if p.index == len(p.tokens) {
			break
		}
		if !p.operator(";", "\n") {
			return nil, invalid("compound shell commands need a command separator")
		}
		p.index++
		p.newlines()
	}
	if len(commands) == 0 {
		return nil, invalid("a compound shell branch has no command")
	}
	return commands, nil
}

func (p *compoundParser) chain(nesting int) ([]command, error) {
	commands := []command{}
	pipe := false
	for {
		if pipe && p.keyword("!") {
			return nil, invalid("pipeline negation must precede the pipeline")
		}
		for p.keyword("!") {
			p.index++
		}
		part, err := p.command(nesting)
		if err != nil {
			return nil, err
		}
		commands = append(commands, part...)
		if !p.operator("&&", "||", "|") {
			return commands, nil
		}
		pipe = p.operator("|")
		p.index++
		p.newlines()
	}
}

func (p *compoundParser) command(nesting int) ([]command, error) {
	if p.keyword("if") {
		p.index++
		commands := []command{}
		for {
			condition, err := p.list([]string{"then"}, nesting+1)
			if err != nil || !p.keyword("then") {
				return nil, invalid("a shell if condition needs then")
			}
			commands = append(commands, condition...)
			p.index++
			body, err := p.list([]string{"elif", "else", "fi"}, nesting+1)
			if err != nil {
				return nil, err
			}
			commands = append(commands, body...)
			if !p.keyword("elif") {
				break
			}
			p.index++
		}
		if p.keyword("else") {
			p.index++
			elseCommands, err := p.list([]string{"fi"}, nesting+1)
			if err != nil {
				return nil, err
			}
			commands = append(commands, elseCommands...)
		}
		if !p.keyword("fi") {
			return nil, invalid("a shell if command needs fi")
		}
		p.index++
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
	return inspectCompoundSimple(p.tokens[start:p.index], p.directory, p.depth)
}

func inspectCompoundSimple(tokens []shellToken, directory string, depth int) ([]command, error) {
	argv, writes, reads := []string{}, []string{}, []string{}
	for index := 0; index < len(tokens); index++ {
		token := tokens[index]
		if !token.operator {
			if token.word != "" && token.word != "[" && token.word != "]" && !literalReadValue(token.word) {
				return nil, invalid("compound shell command arguments must be literal without expansions or globs")
			}
			argv = append(argv, token.word)
			continue
		}
		op := strings.TrimLeft(token.word, "0123456789")
		if !contains([]string{"<", ">", ">>", ">|", "<>", "&>", "&>>", "<&", ">&"}, op) || index+1 >= len(tokens) || tokens[index+1].operator {
			return nil, invalid("a compound shell redirection cannot be inspected")
		}
		index++
		target := tokens[index].word
		if strings.HasPrefix(target, "!") {
			// zsh reads >!, >>!, &>! and >&! as clobbering redirections to the rest of the word.
			return nil, invalid("a zsh clobber redirection cannot be inspected")
		}
		if !literalReadValue(target) {
			return nil, invalid("a compound shell redirection needs a literal target")
		}
		if (contains([]string{">", ">>", ">|", "<>", "&>", "&>>"}, op) || (op == ">&" && !digits(target) && target != "-")) && !standardOutputTarget(target) {
			writes = append(writes, target)
		}
		if op == "<" || op == "<>" {
			reads = append(reads, target)
		}
		if op == "<&" && !digits(target) && target != "-" {
			return nil, invalid("an input descriptor redirection cannot be inspected")
		}
	}
	inspected, err := inspectArgv(argv, directory, depth)
	if err != nil {
		return nil, err
	}
	for _, cmd := range inspected {
		if cmd.changesState {
			return nil, invalid("a compound part cannot change directory or shell state")
		}
	}
	return append([]command{{argv: inspected[0].argv, directory: directory, reads: reads, writes: writes}}, inspected...), nil
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
