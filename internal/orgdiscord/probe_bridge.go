//go:build laneboss_faults

package orgdiscord

import (
	"fmt"
	"io"
)

func runTestProbe(args []string, stdout, stderr io.Writer) (int, bool) {
	if len(args) == 0 || args[0] != "_probe" {
		return 0, false
	}
	return runProbe(args[1:], stdout, stderr), true
}

func runProbe(args []string, stdout, stderr io.Writer) int {
	result, err := probe(args, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "laneboss org channel: "+err.Error())
		return 2
	}
	if err := writeJSON(stdout, result); err != nil {
		fmt.Fprintln(stderr, "cannot write Discord probe result")
		return 2
	}
	return 0
}

func probe(args []string, stderr io.Writer) (any, error) {
	if len(args) < 2 {
		return nil, refused("probe requires an operation and ORG")
	}
	operation, org := args[0], args[1]
	if operation != "validate" && operation != "read" && operation != "event" && operation != "line" {
		return nil, refused("unknown Discord probe operation")
	}
	messagePath, namesPath := "", ""
	for i := 2; i < len(args); i += 2 {
		if i+1 >= len(args) {
			return nil, refused("Discord probe option requires a file")
		}
		switch args[i] {
		case "--message":
			messagePath = args[i+1]
		case "--channel-names":
			namesPath = args[i+1]
		default:
			return nil, refused("unrecognized Discord probe option")
		}
	}
	if operation == "validate" {
		failures := ValidateOrgChannels(org)
		return map[string]any{"valid": len(failures) == 0, "failures": failures}, nil
	}
	roles, err := ReadRoles(org, false)
	if err != nil {
		return nil, err
	}
	if operation == "read" {
		result := map[string]any{}
		for name, role := range roles {
			result[name] = role.document()
		}
		return result, nil
	}
	if messagePath == "" {
		return nil, refused("Discord event probe requires --message")
	}
	message, err := readProbeJSON(messagePath, "Discord message file")
	if err != nil {
		return nil, err
	}
	var names map[string]any
	if namesPath != "" {
		value, err := readProbeJSON(namesPath, "Discord channel names file")
		if err != nil {
			return nil, err
		}
		var ok bool
		names, ok = value.(map[string]any)
		if !ok {
			return nil, refused("Discord channel names file must contain an object")
		}
	}
	if operation == "line" {
		return EventJSONLine(message, roles, names, stderr)
	}
	return MessageToEvent(message, roles, names, stderr), nil
}
