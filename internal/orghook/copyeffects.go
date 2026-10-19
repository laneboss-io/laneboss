package orghook

import "strings"

// The strict copier adapter decides completeness. This narrower pass only
// preserves literal destinations and move sources when option inspection stops.
func literalCopierOperands(name string, args []string) (files, directories []string) {
	options := true
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if options && arg == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(arg, "--") {
			option, value, joined := strings.Cut(arg, "=")
			if option == "--target-directory" || contains([]string{"--suffix", "--mode", "--owner", "--group"}, option) {
				if !joined && index+1 < len(args) {
					index++
					value = args[index]
				}
				if option == "--target-directory" {
					directories = append(directories, value)
				}
			}
			continue
		}
		if options && strings.HasPrefix(arg, "-") && arg != "-" {
			for offset := 1; offset < len(arg); offset++ {
				option := "-" + arg[offset:offset+1]
				if option == "-t" || contains(copiers[name], option) {
					value := arg[offset+1:]
					if value == "" && index+1 < len(args) {
						index++
						value = args[index]
					}
					if option == "-t" {
						directories = append(directories, value)
					}
					break
				}
			}
			continue
		}
		files = append(files, arg)
	}
	return files, directories
}
