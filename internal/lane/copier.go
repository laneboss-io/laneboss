package lane

import (
	"os"
	"strings"
)

var scanCopiers = map[string]string{
	"cp": "-t -S --target-directory --suffix", "mv": "-t -S --target-directory --suffix",
	"ln":      "-t -S --target-directory --suffix",
	"install": "-m -o -g -t -S --mode --owner --group --target-directory",
	"rsync":   "-e --rsh --exclude --include --filter -f",
}

type copierOptionSpec struct {
	flags                             string
	longFlags, values, optionalValues []string
}

// This is shellscan.py's literal grammar, also used by the org hook. Modes
// whose file effects are opaque use conservative candidates in a refusal scan.
var scanCopierOptions = map[string]copierOptionSpec{
	"cp": {
		flags: "adfHiLnPpRrTuvxZ",
		longFlags: []string{"--archive", "--attributes-only", "--copy-contents", "--dereference", "--force",
			"--interactive", "--no-clobber", "--no-dereference", "--no-target-directory",
			"--one-file-system", "--recursive", "--remove-destination", "--strip-trailing-slashes",
			"--verbose", "--help", "--version", "--debug"},
		values:         []string{"--target-directory", "--no-preserve", "--sparse"},
		optionalValues: []string{"--context", "--preserve", "--reflink", "--update"},
	},
	"mv": {
		flags: "finTuvZ",
		longFlags: []string{"--force", "--interactive", "--no-clobber", "--no-target-directory",
			"--strip-trailing-slashes", "--verbose", "--help", "--version", "--context", "--no-copy", "--debug"},
		values:         []string{"--target-directory"},
		optionalValues: []string{"--update"},
	},
	"install": {
		flags:          "cpvZ",
		longFlags:      []string{"--preserve-timestamps", "--verbose", "--help", "--version", "--no-target-directory"},
		values:         []string{"-m", "-o", "-g", "--target-directory", "--mode", "--owner", "--group"},
		optionalValues: []string{"--context"},
	},
}

type copierShortAritySpec struct {
	gnuValues, bsdGetopt string
}

var scanCopierShortArity = map[string]copierShortAritySpec{
	"cp":      {"St", "HLPRacfilNnprSsvXx"},
	"mv":      {"St", "fhinv"},
	"install": {"gmotS", "B:bCcD:df:g:h:l:M:m:N:o:pSsT:Uv"},
}

func copierShortValueArity(name string, letter byte) (bool, bool) {
	spec := scanCopierShortArity[name]
	position := strings.IndexByte(spec.bsdGetopt, letter)
	bsdValue := position >= 0 && position+1 < len(spec.bsdGetopt) && spec.bsdGetopt[position+1] == ':'
	return strings.IndexByte(spec.gnuValues, letter) >= 0, bsdValue
}

func copierOperands(name string, arguments []string) ([]string, []string, bool) {
	spec, known := scanCopierOptions[name]
	if !known {
		return nil, nil, false
	}
	files, target := []string{}, []string{}
	for index := 0; index < len(arguments); {
		argument := arguments[index]
		index++
		if argument == "--" {
			if len(files) > 0 {
				return nil, nil, false
			}
			files = append(files, arguments[index:]...)
			break
		}
		// BSD stops at the first operand; GNU can permute later options.
		if len(files) > 0 && strings.HasPrefix(argument, "-") {
			return nil, nil, false
		}
		option, value := "", ""
		if strings.HasPrefix(argument, "--") {
			var joined bool
			option, value, joined = strings.Cut(argument, "=")
			if contains(spec.longFlags, option) {
				if joined {
					return nil, nil, false
				}
				continue
			}
			if contains(spec.optionalValues, option) {
				if !joined {
					continue
				}
			} else if !contains(spec.values, option) {
				return nil, nil, false
			} else if !joined {
				if index >= len(arguments) {
					return nil, nil, false
				}
				value = arguments[index]
				index++
			}
		} else if strings.HasPrefix(argument, "-") && argument != "-" {
			option, value = argument[:2], argument[2:]
			gnuValue, bsdValue := copierShortValueArity(name, argument[1])
			if gnuValue != bsdValue {
				return nil, nil, false
			}
			if !contains(spec.values, option) {
				for _, letter := range argument[1:] {
					gnuValue, bsdValue := copierShortValueArity(name, byte(letter))
					if !strings.ContainsRune(spec.flags, letter) || gnuValue || bsdValue {
						return nil, nil, false
					}
				}
				continue
			}
			if len(argument) == 2 {
				if index >= len(arguments) {
					return nil, nil, false
				}
				value = arguments[index]
				index++
			}
		} else {
			files = append(files, argument)
			continue
		}
		if value == "" || strings.ContainsAny(value, "$`*?[]{}") || strings.HasPrefix(value, "~") || strings.IndexFunc(value, func(r rune) bool { return r < 32 }) >= 0 {
			return nil, nil, false
		}
		if option == "-t" || option == "--target-directory" {
			if len(target) > 0 {
				return nil, nil, false
			}
			target = append(target, value)
		}
	}
	if len(target) == 0 && len(files) < 2 {
		return nil, nil, false
	}
	sources := files
	if len(target) == 0 {
		sources = files[:len(files)-1]
	}
	// BSD cp copies a slash-ended directory's contents, unlike GNU cp.
	if name == "cp" {
		for _, source := range sources {
			if strings.HasSuffix(source, "/") {
				return nil, nil, false
			}
		}
	}
	return files, target, true
}

// copierFileCandidates keeps BSD operands, including a late -- or option word.
func copierFileCandidates(arguments []string, takes string) []string {
	files := []string{}
	options := true
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		if options && len(files) == 0 && argument == "--" {
			options = false
		} else if options && len(files) == 0 && strings.HasPrefix(argument, "-") && argument != "-" {
			if contains(strings.Fields(takes), argument) {
				index++
			}
		} else {
			files = append(files, argument)
			options = false
		}
	}
	return files
}

func copierTargetValues(arguments []string) []string {
	target := []string{}
	for index, argument := range arguments {
		if argument == "--" {
			break
		}
		if (argument == "-t" || argument == "--target-directory") && index+1 < len(arguments) {
			target = append(target, arguments[index+1])
		} else if strings.HasPrefix(argument, "--target-directory=") {
			target = append(target, strings.TrimPrefix(argument, "--target-directory="))
		} else if strings.HasPrefix(argument, "-t") && len(argument) > 2 {
			target = append(target, argument[2:])
		}
	}
	return target
}

func distinctCopierWords(lists ...[]string) []string {
	found := []string{}
	seen := map[string]bool{}
	for _, list := range lists {
		for _, word := range list {
			if !seen[word] {
				seen[word] = true
				found = append(found, word)
			}
		}
	}
	return found
}

func copierChildWrites(destination string, sources []string) []string {
	writes := []string{}
	for _, source := range sources {
		source = strings.TrimRight(source, "/")
		base := source[strings.LastIndexByte(source, '/')+1:]
		// Keep empty basenames and raw path words as os.path.join does;
		// the scan resolves and normalises them after collecting candidates.
		child := base
		if destination != "" {
			separator := "/"
			if strings.HasSuffix(destination, "/") {
				separator = ""
			}
			child = destination + separator + base
		}
		writes = append(writes, child)
	}
	return writes
}

func copierDestinationIsDirectory(destination string, sources []string, directory string) bool {
	if len(sources) > 1 || strings.HasSuffix(destination, "/") {
		return true
	}
	resolved := shellResolve(destination, directory)
	if resolved == "" {
		return false
	}
	info, err := os.Stat(resolved)
	return err == nil && info.IsDir()
}

// CopierWriteCandidates is shared by ordinary and turn-based lane scans. The
// boolean identifies copier commands; unsupported grammar still yields possible
// writes, as Python's workaround detector has no opaque outcome.
func CopierWriteCandidates(name string, arguments []string, directory string) ([]string, bool) {
	takes, known := scanCopiers[name]
	if !known {
		return nil, false
	}
	files, target := []string{}, []string{}
	if _, strict := scanCopierOptions[name]; strict {
		var supported bool
		files, target, supported = copierOperands(name, arguments)
		if !supported {
			gnuFiles := operands(arguments, takes)
			bsdFiles := copierFileCandidates(arguments, takes)
			files = distinctCopierWords(gnuFiles, bsdFiles)
			writes := append([]string{}, files...)
			for _, destination := range distinctCopierWords(copierTargetValues(arguments)) {
				writes = append(writes, copierChildWrites(destination, files)...)
			}
			// Keep each vendor's positional destination as well as their union.
			for _, interpretation := range [][]string{gnuFiles, bsdFiles} {
				if len(interpretation) < 2 {
					continue
				}
				destination, sources := interpretation[len(interpretation)-1], interpretation[:len(interpretation)-1]
				if copierDestinationIsDirectory(destination, sources, directory) {
					writes = append(writes, copierChildWrites(destination, sources)...)
				}
			}
			if len(writes) == 0 {
				writes = []string{directory}
			}
			return writes, true
		}
	} else {
		files = operands(arguments, takes)
		if name != "rsync" {
			target = copierTargetValues(arguments)
		}
	}
	if len(target) > 0 {
		return copierChildWrites(target[0], files), true
	}
	if len(files) < 2 {
		return []string{}, true
	}
	destination, sources := files[len(files)-1], files[:len(files)-1]
	if copierDestinationIsDirectory(destination, sources, directory) {
		return copierChildWrites(destination, sources), true
	}
	return []string{destination}, true
}
