package orghook

import (
	"path/filepath"
	"strings"
)

// Retain literal effects even when a command's remaining arguments are opaque.
// This is an effect inventory, not permission to execute an unsupported form.
func literalWriteCommand(argv []string, directory string) (command, bool) {
	words := codeCommandWords(argv)
	cmd := command{argv: words, directory: directory, opaque: true}
	if len(words) == 0 {
		return cmd, false
	}
	name, args := filepath.Base(words[0]), words[1:]
	add := func(values ...string) {
		for _, value := range values {
			if literalReadValue(value) && !contains(cmd.writes, value) {
				cmd.writes = append(cmd.writes, value)
			}
		}
	}
	switch name {
	case "find":
		targets, destructive := findWriteTargets(args)
		add(targets...)
		return cmd, destructive
	case "rsync":
		files := operands(args, copiers[name])
		if len(files) < 2 {
			return cmd, false // A single source is a listing, not a copy destination.
		}
		if !strings.Contains(files[len(files)-1], ":") {
			add(files[len(files)-1])
		}
	case "cp", "mv", "install":
		files, directories := literalCopierOperands(name, args)
		if len(directories) > 0 {
			add(directories...)
		} else if len(files) >= 2 {
			add(files[len(files)-1])
		} else if name != "mv" || len(files) == 0 {
			return cmd, false
		}
		if name == "mv" {
			add(files...)
		}
		_, _, supported := copierOperands(name, args)
		cmd.opaque = !supported || contains(args, "--") || len(directories) > 0
		for _, arg := range args {
			if arg == "--sparse" || strings.HasPrefix(arg, "--sparse=") {
				cmd.opaque = true // Preserve destinations without claiming mode inspection.
			}
		}
	case "ln":
		files := operands(args, copiers[name])
		directories := optionValues(args, "-t", "--target-directory")
		if len(directories) > 0 {
			add(directories...)
		} else if len(files) >= 2 {
			add(files[len(files)-1])
		} else {
			return cmd, false
		}
	case "tar":
		extract := false
		target := "."
		for index := 0; index < len(args); index++ {
			arg := args[index]
			if arg == "-C" || arg == "--directory" {
				if index+1 < len(args) {
					index++
					if filepath.IsAbs(args[index]) {
						target = args[index]
					} else {
						target = joinPathWord(target, args[index])
					}
				}
			} else if strings.HasPrefix(arg, "--directory=") {
				target = strings.TrimPrefix(arg, "--directory=")
			} else if strings.HasPrefix(arg, "-C") && len(arg) > 2 {
				target = arg[2:]
			} else if arg == "--extract" || arg == "--get" {
				extract = true
			} else if !strings.HasPrefix(arg, "--") && (strings.HasPrefix(arg, "-") || index == 0 && arg != "" && strings.ContainsRune("cxturA", rune(arg[0]))) {
				flags := strings.TrimPrefix(arg, "-")
			flagsLoop:
				for offset := 0; offset < len(flags); offset++ {
					switch flags[offset] {
					case 'x':
						extract = true
					case 'f':
						if offset+1 == len(flags) && index+1 < len(args) {
							index++
						}
						break flagsLoop // The rest is the archive name, not flags.
					case 'C':
						value := flags[offset+1:]
						if value == "" && index+1 < len(args) {
							index++
							value = args[index]
						}
						target = value
						break flagsLoop
					}
				}
			}
		}
		if !extract {
			return cmd, false
		}
		add(target)
	case "sed":
		inplace, script := false, false
		for index := 0; index < len(args); index++ {
			arg := args[index]
			if arg == "-e" || arg == "--expression" || arg == "-f" || arg == "--file" {
				index++
				script = true
			} else if arg == "-i" || strings.HasPrefix(arg, "-i") || arg == "--in-place" || strings.HasPrefix(arg, "--in-place=") {
				inplace = true
				if index+1 < len(args) && args[index+1] == "" {
					index++ // BSD's explicit empty backup suffix.
				}
			} else if strings.HasPrefix(arg, "-") {
				continue
			} else if !script {
				script = true
			} else {
				add(arg)
			}
		}
		if !inplace {
			return cmd, false
		}
	case "xargs":
		spec, ok := parseXargs(args)
		if !ok {
			return cmd, false
		}
		nestedWords := codeCommandWords(spec.argv)
		if len(nestedWords) == 0 || filepath.Base(nestedWords[0]) == "xargs" {
			return cmd, false
		}
		nested, known := literalWriteCommand(spec.argv, directory)
		if !known {
			return cmd, false
		}
		if literalReadValue(spec.file) {
			cmd.reads = append(cmd.reads, spec.file)
		}
		add(nested.writes...)
	case "git":
		normalized, dir, _, err := normalise(words, directory, 0)
		if err != nil || len(normalized) < 2 || !contains(gitWriters, normalized[1]) {
			return cmd, false
		}
		cmd.argv, cmd.directory, cmd.opaque = normalized, dir, false
		add(dir)
	case "dd":
		add(writtenBy(name, args, directory)...)
		cmd.opaque = false
	case "chmod", "chown", "chgrp":
		files := operands(args, nil)
		if len(files) > 0 {
			add(files[1:]...)
		}
		cmd.opaque = false
	default:
		if takes, ok := operandWriters[name]; ok {
			add(operands(args, takes)...)
			cmd.opaque = false
		} else {
			return cmd, false
		}
	}
	return cmd, true
}

var findValueOptions = []string{"-name", "-iname", "-path", "-ipath", "-wholename", "-iwholename", "-regex", "-iregex", "-type", "-xtype", "-maxdepth", "-mindepth", "-mtime", "-ctime", "-atime", "-mmin", "-cmin", "-amin", "-size", "-user", "-group", "-uid", "-gid", "-perm", "-links", "-inum", "-newer", "-printf"}

func findWriteTargets(args []string) ([]string, bool) {
	roots, outputs := []string{}, []string{}
	expression, destructive := false, false
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if !expression {
			if contains([]string{"-H", "-L", "-P", "--"}, arg) {
				continue
			}
			if arg == "-D" || arg == "-O" {
				index++
				continue
			}
			if strings.HasPrefix(arg, "-O") && digits(strings.TrimPrefix(arg, "-O")) {
				continue
			}
			if arg == "-f" && index+1 < len(args) {
				index++
				roots = append(roots, args[index])
				continue
			}
			if !strings.HasPrefix(arg, "-") && !contains([]string{"!", "("}, arg) {
				roots = append(roots, arg)
				continue
			}
			expression = true
		}
		switch arg {
		case "-delete":
			destructive = true
		case "-exec", "-execdir", "-ok", "-okdir":
			destructive = true
			for index+1 < len(args) && args[index+1] != ";" && args[index+1] != "+" {
				index++
			}
			if index+1 < len(args) {
				index++
			}
		case "-fprint", "-fprint0", "-fprintf", "-fls":
			destructive = true
			if index+1 < len(args) {
				index++
				outputs = append(outputs, args[index])
			}
			if arg == "-fprintf" && index+1 < len(args) {
				index++ // The format is data, never another action.
			}
		default:
			if contains(findValueOptions, arg) && index+1 < len(args) {
				index++
			}
		}
	}
	if len(roots) == 0 {
		roots = []string{"."}
	}
	return append(roots, outputs...), destructive
}
