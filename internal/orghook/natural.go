package orghook

import (
	"math"
	"net/url"
	"strconv"
	"strings"
)

// These adapters inspect ordinary process/session and HTTP-reader operations.
// Unknown options remain opaque; tmux payloads are inspected recursively, so
// putting a runner launch or a file write in tmux cannot hide it from policy.
func naturalCommand(name string, args, argv []string, directory string, depth int) ([]command, bool, error) {
	base := command{argv: argv, directory: directory}
	opaque := func() ([]command, bool, error) {
		base.opaque = true
		return []command{base}, true, nil
	}
	switch name {
	case "kill":
		if len(args) == 0 {
			return opaque()
		}
		at := 0
		if strings.HasPrefix(args[0], "-") {
			signal := strings.TrimPrefix(args[0], "-")
			if !contains([]string{"0", "1", "2", "3", "9", "15", "HUP", "INT", "QUIT", "KILL", "TERM"}, signal) {
				return opaque()
			}
			at++
		}
		if at == len(args) {
			return opaque()
		}
		for _, word := range args[at:] {
			pid, err := strconv.Atoi(word)
			if err != nil || pid < 2 {
				return opaque()
			}
		}
		return []command{base}, true, nil
	case "curl":
		addresses := 0
		for at := 0; at < len(args); at++ {
			word := args[at]
			switch word {
			case "-s", "-S", "-f", "-I", "-L", "-sS", "-fsSL", "--silent", "--show-error", "--fail", "--head", "--location":
				continue
			case "--max-time", "--connect-timeout":
				at++
				if at >= len(args) {
					return opaque()
				}
				seconds, err := strconv.ParseFloat(args[at], 64)
				if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds <= 0 || seconds > 3600 {
					return opaque()
				}
				continue
			case "--url":
				at++
				if at >= len(args) {
					return opaque()
				}
				word = args[at]
			default:
				if strings.HasPrefix(word, "-") {
					return opaque()
				}
			}
			address, err := url.Parse(word)
			if err != nil || address.User != nil || address.Host == "" || (address.Scheme != "http" && address.Scheme != "https") {
				return opaque()
			}
			addresses++
		}
		if addresses == 0 {
			return opaque()
		}
		return []command{base}, true, nil
	case "tmux":
		if len(args) == 0 || depth >= 4 {
			return opaque()
		}
		operation := args[0]
		if !contains([]string{"new-session", "list-sessions", "list-windows", "list-panes", "has-session", "kill-session"}, operation) {
			return opaque()
		}
		payload := []string{}
		for at := 1; at < len(args); at++ {
			word := args[at]
			if word == "-d" && operation == "new-session" {
				continue
			}
			if contains([]string{"-s", "-t", "-n", "-F"}, word) {
				at++
				if at >= len(args) || args[at] == "" {
					return opaque()
				}
				continue
			}
			if strings.HasPrefix(word, "-") || operation != "new-session" {
				return opaque()
			}
			payload = args[at:]
			break
		}
		if operation != "new-session" {
			return []command{base}, true, nil
		}
		// An unspecified/default shell is not inspectable.
		if len(payload) == 0 {
			return opaque()
		}
		var nested []command
		var err error
		if len(payload) == 1 {
			nested, err = inspectShell(payload[0], directory, depth+1)
		} else {
			nested, err = inspectArgv(payload, directory, depth+1)
		}
		if err != nil {
			base.opaque = true
			return append([]command{base}, nested...), true, nestedInspection(err)
		}
		return append([]command{base}, nested...), true, nil
	}
	return nil, false, nil
}
