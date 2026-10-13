package lane

import (
	"bufio"
	"context"
	"io"
	"os"
	"os/exec"
	"regexp/syntax"
	"strconv"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/selfexec"
)

// Configured expressions retain the launcher's backtracking and timeout
// contract. Go's regexp matcher eliminates backtracking, which would silently
// classify a result the launcher could not finish checking as an ordinary miss.
// This interpreter uses Go's parsed program, explores alternatives in order,
// and checks the shared deadline while it does real matching work.
type boundedRegexp struct{ program *syntax.Prog }

type regexResult uint8

const (
	regexMiss regexResult = iota
	regexHit
	regexTimeout
)

func compileBounded(pattern string) (*boundedRegexp, error) {
	tree, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, err
	}
	program, err := syntax.Compile(tree.Simplify())
	if err != nil {
		return nil, err
	}
	return &boundedRegexp{program}, nil
}

func (pattern *boundedRegexp) search(text string, deadline time.Time) regexResult {
	input := []rune(text)
	active := make([]int, len(pattern.program.Inst))
	for i := range active {
		active[i] = -1
	}
	steps := uint64(0)
	var visit func(uint32, int) regexResult
	visit = func(pc uint32, position int) regexResult {
		steps++
		if steps&1023 == 0 && !time.Now().Before(deadline) {
			return regexTimeout
		}
		// Empty repetitions must not revisit the same instruction without
		// consuming input. This is a path-local cycle check, not memoization:
		// every backtracking alternative still performs its own matching.
		if active[pc] == position {
			return regexMiss
		}
		previous := active[pc]
		active[pc] = position
		defer func() { active[pc] = previous }()
		instruction := &pattern.program.Inst[pc]
		switch instruction.Op {
		case syntax.InstMatch:
			return regexHit
		case syntax.InstFail:
			return regexMiss
		case syntax.InstAlt, syntax.InstAltMatch:
			if result := visit(instruction.Out, position); result != regexMiss {
				return result
			}
			return visit(instruction.Arg, position)
		case syntax.InstCapture, syntax.InstNop:
			return visit(instruction.Out, position)
		case syntax.InstEmptyWidth:
			before, after := rune(-1), rune(-1)
			if position > 0 {
				before = input[position-1]
			}
			if position < len(input) {
				after = input[position]
			}
			needed := syntax.EmptyOp(instruction.Arg)
			if syntax.EmptyOpContext(before, after)&needed == needed {
				return visit(instruction.Out, position)
			}
		case syntax.InstRune, syntax.InstRune1, syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
			if position < len(input) {
				matches := instruction.Op == syntax.InstRuneAny ||
					instruction.Op == syntax.InstRuneAnyNotNL && input[position] != '\n'
				if instruction.Op == syntax.InstRune || instruction.Op == syntax.InstRune1 {
					matches = instruction.MatchRune(input[position])
				}
				if matches {
					return visit(instruction.Out, position+1)
				}
			}
		}
		return regexMiss
	}
	for start := 0; start <= len(input); start++ {
		if !time.Now().Before(deadline) {
			return regexTimeout
		}
		if result := visit(uint32(pattern.program.Start), start); result != regexMiss {
			return result
		}
	}
	return regexMiss
}

// These role labels preserve the process identities used by existing launcher
// observers during the migration. They are argv[0] metadata only: Path always
// names this Go executable and no Python code is executed.
const scannerProcessLabel = "laneboss lane scanner (refusals import follow)"
const classifierProcessLabel = "laneboss lane classifier (import json, re, sys)"

func classifyOutput(root *os.Root, offset int64, spec object) (string, any, any) {
	limit, drop := stringsOf(spec["limit_patterns"]), stringsOf(spec["dropped_patterns"])
	if len(limit)+len(drop) == 0 {
		return "exit", nil, nil
	}
	file, err := childOpen(root, "output.log", os.O_RDONLY, 0)
	if err != nil {
		return "exit", nil, "read-error"
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "exit", nil, "read-error"
	}
	begin := info.Size() - 65536
	if begin < offset {
		begin = offset
	}
	if begin > info.Size() {
		begin = info.Size()
	}
	data := make([]byte, info.Size()-begin)
	if _, err = file.ReadAt(data, begin); err != nil && err != io.EOF {
		return "exit", nil, "read-error"
	}
	lines := recordLines(strings.ToValidUTF8(string(data), "�"))
	if begin > offset && len(lines) > 0 {
		lines = lines[1:]
	}
	jobLines := []any{}
	for i := len(lines) - 1; i >= 0; i-- {
		runes := []rune(lines[i])
		if len(runes) > 4096 {
			runes = runes[:4096]
		}
		jobLines = append(jobLines, string(runes))
	}
	job := object{"lines": jobLines, "limit": limit, "dropped": drop}
	binary, err := os.Executable()
	if err != nil {
		return "exit", nil, "read-error"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, selfexec.Args("lane", "__classify")...)
	command.Args[0] = classifierProcessLabel
	command.Stdin = strings.NewReader(string(canonical(job)))
	command.WaitDelay = time.Second
	output, err := command.Output()
	if ctx.Err() != nil {
		return "exit", nil, "timed-out"
	}
	if err != nil {
		return "exit", nil, "read-error"
	}
	value, err := parseJSON(output)
	if err != nil {
		return "exit", nil, "read-error"
	}
	result := obj(value)
	if result == nil || !exactKeys(result, strings.Fields("reason pattern classification")) {
		return "exit", nil, "read-error"
	}
	return str(result["reason"]), result["pattern"], result["classification"]
}

// The launcher's line windows follow str.splitlines: a trailing separator does
// not invent another line, and the Unicode line separators are boundaries too.
func recordLines(text string) []string {
	lines := []string{}
	start, skipLF := 0, false
	for offset, character := range text {
		if skipLF && character == '\n' {
			start = offset + 1
			skipLF = false
			continue
		}
		skipLF = false
		if strings.ContainsRune("\n\r\v\f\x1c\x1d\x1e\u0085\u2028\u2029", character) {
			lines = append(lines, text[start:offset])
			start = offset + len(string(character))
			skipLF = character == '\r'
		}
	}
	if start < len(text) {
		lines = append(lines, text[start:])
	}
	return lines
}

func classifyRecords(stdin io.Reader, stdout io.Writer) int {
	// The independent lifetime bound also applies if the supervisor is killed
	// while matching; the helper never depends on its parent to collect it.
	expiry := time.AfterFunc(3*time.Second, func() { os.Exit(3) })
	defer expiry.Stop()
	data, err := io.ReadAll(io.LimitReader(bufio.NewReader(stdin), 4*1024*1024+1))
	if err != nil || len(data) > 4*1024*1024 {
		return 2
	}
	value, err := parseJSON(data)
	job := obj(value)
	if err != nil || !exactKeys(job, strings.Fields("lines limit dropped")) {
		return 2
	}
	type expression struct {
		reason, name string
		pattern      *boundedRegexp
	}
	patterns := []expression{}
	for _, kind := range []string{"limit", "dropped"} {
		for index, source := range stringsOf(job[kind]) {
			pattern, err := compileBounded(source)
			if err != nil {
				return 2
			}
			patterns = append(patterns, expression{kind, kind + "_patterns[" + strconv.Itoa(index) + "]", pattern})
		}
	}
	result := object{"reason": "exit", "pattern": nil, "classification": "unmatched"}
	deadline := time.Now().Add(3 * time.Second)
	for _, line := range stringsOf(job["lines"]) {
		for _, expression := range patterns {
			switch expression.pattern.search(line, deadline) {
			case regexHit:
				result = object{"reason": expression.reason, "pattern": expression.name, "classification": "matched"}
				_, err = stdout.Write(canonical(result))
				if err != nil {
					return 1
				}
				return 0
			case regexTimeout:
				return 3
			}
		}
	}
	if _, err = stdout.Write(canonical(result)); err != nil {
		return 1
	}
	return 0
}
