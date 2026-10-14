package orghook

import "strings"

const literalReadRoute = "run one command per file with each path written literally (no loop, variable, glob or $(…)), or use the agent's file-reading tool."
const patchWriteRoute = "use the apply_patch tool, or pass the whole patch as a quoted heredoc (apply_patch <<'PATCH' … PATCH); never put the patch in single quotes."
const holdRoute = "report this refusal verbatim to the supervisor and wait for corrected hook inputs or policy before continuing."
const fileRoute = "use an allowed file tool with one literal non-secret path inside the permitted scope; ask the supervisor when no permitted tool or path fits."
const deviceRoute = "leave device-file targets unchanged; send permitted non-secret output directly to stdout or stderr without file redirection."
const searchRoute = "narrow the read to a literal non-secret file or folder without protected descendants, symlink directories or multiply linked files."
const routeScope = "The alternative must still satisfy every applicable tool, secret, command and write-scope rule."

func ruleRoute(kind string) string {
	switch kind {
	case "secret-read":
		return "read a permitted non-secret source using a literal path; refer to secrets by name only, or ask the supervisor for a public or redacted input."
	case "write-scope":
		return "use an allowed file-writing tool with a literal path inside every applicable write scope; leave protected policy and settings changes to the supervisor."
	case "tool-allowlist":
		return "use a tool permitted by every applicable allowlist, or report this refusal to request a policy change from the supervisor."
	case "command-pattern":
		return "leave the matched command unexecuted and report the refusal to the supervisor for a permitted route."
	default:
		return holdRoute
	}
}

func errorRoute(message string) string {
	switch {
	case strings.Contains(message, "variables cannot be inspected"), strings.Contains(message, "shell quoting"),
		strings.Contains(message, "broken quoting"), strings.Contains(message, "shell command"), strings.Contains(message, "nested shells"):
		return literalReadRoute
	case strings.Contains(message, "content search"), strings.Contains(message, "directory read"), strings.Contains(message, "secret-name policy"):
		return searchRoute
	case strings.Contains(message, "redirection"), strings.Contains(message, "output files"):
		return deviceRoute
	case strings.Contains(message, "file tool"), strings.Contains(message, "apply_patch"), strings.Contains(message, "file-effects adapter"), strings.Contains(message, "multiply linked"):
		return fileRoute
	case strings.Contains(message, "Git"), strings.Contains(message, "wrapper"), strings.Contains(message, "environment assignments"), strings.Contains(message, "environment overrides"):
		return "use an allowed command directly with literal arguments in the recorded working directory, without environment, configuration or execution-context overrides."
	default:
		return holdRoute
	}
}

func errorRefusal(message string) string {
	return "org hook fails closed: " + message + "\n" + routeScope + "\nInstead: " + errorRoute(message)
}

func eventErrorRefusal(message string, event map[string]any) string {
	tool, _ := event["tool_name"].(string)
	tool = strings.TrimPrefix(tool, "functions.")
	data, _ := event["tool_input"].(map[string]any)
	if raw, ok := event["tool_input"].(string); ok {
		data, _ = parseJSON([]byte(raw), "tool_input")
	}
	if contains([]string{"Bash", "exec_command", "shell", "shell_command"}, tool) {
		for _, key := range []string{"command", "cmd", "argv"} {
			if script, ok := data[key].(string); ok && shellWriteIntent(script) &&
				(patchWord(firstShellWord(script)) || strings.Contains(message, "broken quoting") || strings.Contains(message, "shell quoting")) {
				return "org hook fails closed: " + message + "\n" + routeScope + "\nInstead: " + patchWriteRoute
			}
		}
	}
	return errorRefusal(message)
}
