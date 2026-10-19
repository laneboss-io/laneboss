// Package orgtree implements org init, instance add, render and validate.
// The Go implementation reads policy data, never Python source or executables.
package orgtree

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"laneboss.io/laneboss/internal/cliargs"
	"laneboss.io/laneboss/internal/orgdiscord"
	"laneboss.io/laneboss/internal/orghook"
)

type validationReport struct {
	Valid    bool      `json:"valid"`
	Problems []problem `json:"problems"`
	Warnings []problem `json:"warnings"`
}

func validateOrg(argument string, configured ...string) validationReport {
	t, err := inspect(argument, false)
	if err != nil {
		return validationReport{false, []problem{{"(org folder)", err.Error()}}, []problem{}}
	}
	problems := append([]problem{}, t.problems...)
	laneUses := map[string]bool{}
	lanesChecked := false
	if len(configured) == 1 && configured[0] != "" {
		var err error
		laneUses, err = configuredRoleUses(t.root, configured[0])
		if err != nil {
			problems = append(problems, problem{"(configuration)", err.Error()})
		} else {
			lanesChecked = true
		}
	}
	roleProblems, warnings := t.roleReport(laneUses, lanesChecked)
	warnings = append(warnings, t.hookDeprecations()...)
	problems = append(problems, roleProblems...)
	if len(problems) == 0 {
		// Integration is reached only after the tree itself passes, as in org.py.
		report, err := orghook.CheckHooks(t.root)
		if err != nil {
			problems = append(problems, problem{"(hooks)", "hook settings could not be checked"})
		} else {
			items, checksOK := array(report["checks"])
			overall, ok := report["ok"].(bool)
			if !checksOK || !ok || len(items) == 0 {
				problems = append(problems, problem{"(hooks)", "invalid hook check report"})
			}
			failures := 0
			for _, item := range items {
				check, ok := item.(map[string]any)
				passed, boolOK := check["ok"].(bool)
				if !ok || !boolOK || !passed {
					failures++
					reason, _ := check["reason"].(string)
					if reason == "" || findCredential(reason) != nil {
						reason = "hook check failed"
					}
					problems = append(problems, problem{"(hooks)", reason})
				}
			}
			if ok && !overall && failures == 0 {
				problems = append(problems, problem{"(hooks)", "hook check failed"})
			}
		}
		for _, message := range orgdiscord.ValidateOrgChannels(t.root) {
			if findCredential(message) != nil {
				message = "owner channel check failed"
			}
			problems = append(problems, problem{"(discord)", message})
		}
	}
	return validationReport{len(problems) == 0, problems, warnings}
}

type commandArgs struct {
	positionals []string
	options     map[string][]string
	help        bool
}

// Parse interspersed options, including --flag=value and repeated --secret.
// Errors name the flag or field, never the rejected argument's value.
func parseArgs(args []string, allowed []string) (commandArgs, error) {
	result := commandArgs{options: map[string][]string{}}
	positionalOnly := false
	for i := 0; i < len(args); i++ {
		argument := args[i]
		if !positionalOnly && argument == "--" {
			positionalOnly = true
			continue
		}
		if !positionalOnly && (argument == "-h" || argument == "--help") {
			result.help = true
			continue
		}
		if !positionalOnly && strings.HasPrefix(argument, "-") {
			flag, value, inline := strings.Cut(argument, "=")
			if !contains(allowed, flag) {
				return result, errors.New(cliargs.Reject(""))
			}
			if !inline {
				i++
				if i >= len(args) || strings.HasPrefix(args[i], "--") {
					return result, errors.New(cliargs.Expected(flag))
				}
				value = args[i]
			}
			result.options[flag] = append(result.options[flag], value)
		} else {
			result.positionals = append(result.positionals, argument)
		}
	}
	return result, nil
}

func (a commandArgs) value(flag, fallback string) string {
	values := a.options[flag]
	if len(values) > 0 {
		return values[len(values)-1]
	}
	return fallback
}

func (a commandArgs) optional(flag string) *string {
	if len(a.options[flag]) == 0 {
		return nil
	}
	value := a.value(flag, "")
	return &value
}

func usage(action string) string {
	switch action {
	case "init":
		return "laneboss org init ORG_DIR [--levels LEVELS] [--name NAME]"
	case "instance":
		return "laneboss org instance add ORG_DIR NAME --level N --role ROLE [--discord-channel ID] [--secret NAME]..."
	case "render":
		return "laneboss org render ORG_DIR"
	case "validate":
		return "laneboss org validate ORG_DIR [--format text|json|json-diagnostics] [--config NAME]"
	}
	return "laneboss org ACTION ..."
}

// Run executes one org tree action and returns the process exit code.
func Run(action string, args []string, stdout, stderr io.Writer) int {
	if action == "roles" {
		return runRoles(args, stdout, stderr)
	}
	allowed := []string{}
	expected := 1
	switch action {
	case "init":
		allowed = []string{"--levels", "--name"}
	case "instance":
		if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
			fmt.Fprintln(stdout, "usage: "+usage(action))
			return 0
		}
		if len(args) == 0 || args[0] != "add" {
			fmt.Fprintln(stderr, "usage: "+usage(action))
			fmt.Fprintln(stderr, "laneboss org instance: error: "+cliargs.Reject("ACTION"))
			return 2
		}
		args = args[1:]
		expected = 2
		allowed = []string{"--level", "--role", "--discord-channel", "--secret"}
	case "render":
	case "validate":
		allowed = []string{"--format", "--config"}
	default:
		fmt.Fprintln(stderr, "laneboss org: error: "+cliargs.Reject("ACTION"))
		return 2
	}
	parsed, err := parseArgs(args, allowed)
	if err == nil && parsed.help {
		fmt.Fprintln(stdout, "usage: "+usage(action))
		return 0
	}
	if err == nil && len(parsed.positionals) != expected {
		if len(parsed.positionals) < expected {
			labels := []string{"ORG_DIR", "name"}
			err = errors.New(cliargs.Required(labels[len(parsed.positionals):expected]...))
		} else {
			err = errors.New(cliargs.Reject(""))
		}
	}
	if err == nil && action == "instance" {
		if len(parsed.options["--level"]) == 0 {
			err = errors.New(cliargs.Required("--level"))
		} else if len(parsed.options["--role"]) == 0 {
			err = errors.New(cliargs.Required("--role"))
		}
	}
	format := parsed.value("--format", "text")
	if err == nil && action == "validate" && format != "text" && format != "json" && format != "json-diagnostics" {
		err = errors.New(cliargs.Reject("--format"))
	}
	if err != nil {
		fmt.Fprintln(stderr, "usage: "+usage(action))
		fmt.Fprintln(stderr, "laneboss org: error: "+err.Error())
		return 2
	}
	argument := parsed.positionals[0]
	if action == "validate" {
		report := validateOrg(argument, parsed.value("--config", ""))
		if format == "json" || format == "json-diagnostics" {
			var output any = report
			if format == "json" {
				// Preserve the established machine-readable validation contract.
				// Diagnostics are opt-in; every real problem remains in both forms.
				output = struct {
					Valid    bool      `json:"valid"`
					Problems []problem `json:"problems"`
				}{report.Valid, report.Problems}
			}
			text, err := jsonText(output, false)
			if err != nil {
				fmt.Fprintln(stderr, "cannot encode the validation report")
				return 2
			}
			if _, err := io.WriteString(stdout, text); err != nil {
				return 2
			}
		} else if report.Valid {
			if _, err := fmt.Fprintln(stdout, "org is valid"); err != nil {
				return 2
			}
		} else {
			for _, item := range report.Problems {
				fmt.Fprintln(stderr, item.Path+": "+item.Message)
			}
		}
		// The json form keeps its stdout contract (valid, problems); its warnings,
		// including the 1.0.0 hook deprecation, go to stderr as in the text form.
		if format == "text" || format == "json" {
			for _, item := range report.Warnings {
				fmt.Fprintln(stderr, "warning: "+item.Path+": "+item.Message)
			}
		}
		if report.Valid {
			return 0
		}
		return 2
	}
	var result writeResult
	switch action {
	case "init":
		result, err = initOrg(argument, parsed.value("--levels", "3-6"), parsed.optional("--name"))
	case "render":
		result, err = renderOrg(argument)
	case "instance":
		level, parseErr := strconv.Atoi(parsed.value("--level", ""))
		if parseErr != nil || level < 3 || level > 6 {
			err = errors.New("--level must be an integer from 3 to 6")
		} else {
			result, err = addInstance(argument, parsed.positionals[1], level, parsed.value("--role", ""), parsed.optional("--discord-channel"), parsed.options["--secret"])
		}
	}
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 2
	}
	if action == "render" {
		if tree, inspectErr := inspect(argument, false); inspectErr == nil {
			for _, item := range tree.hookDeprecations() {
				fmt.Fprintln(stderr, "warning: "+item.Path+": "+item.Message)
			}
		}
	}
	text, err := jsonText(result, false)
	if err != nil {
		fmt.Fprintln(stderr, "cannot encode the org result")
		return 2
	}
	if _, err := io.WriteString(stdout, text); err != nil {
		return 2
	}
	return 0
}
