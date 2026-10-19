package ledger

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

const usage = "usage: laneboss ledger --config NAME [--instance ID | --lane NAME] [--since TIME] [--format text|json]"

func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	values := map[string]string{}
	selection := Selection{}
	for i := 0; i < len(args); i++ {
		if args[i] == "--help" || args[i] == "-h" {
			_, err := fmt.Fprintln(stdout, usage+"\nRead existing employee records without writing ledger state.")
			if err != nil {
				return 70
			}
			return 0
		}
		option := args[i]
		if option != "--config" && option != "--instance" && option != "--lane" && option != "--since" && option != "--format" || i+1 == len(args) || values[option] != "" {
			fmt.Fprintln(stderr, usage)
			return 2
		}
		i++
		values[option] = args[i]
	}
	selection.Instance, selection.Lane, selection.Since = values["--instance"], values["--lane"], values["--since"]
	format := values["--format"]
	if format == "" {
		format = "text"
	}
	if values["--config"] == "" || format != "text" && format != "json" {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	if _, err := selection.Validate(); err != nil {
		fmt.Fprintln(stderr, "refused: invalid ledger selection")
		return 2
	}
	value, err := Read(values["--config"], selection)
	if err != nil {
		fmt.Fprintln(stderr, "ledger records could not be read; check the configuration and stores with the CLI")
		return 3
	}
	if format == "json" {
		if err = json.NewEncoder(stdout).Encode(value); err != nil {
			return 70
		}
		return 0
	}
	if _, err = io.WriteString(stdout, FormatText(value)); err != nil {
		return 70
	}
	return 0
}
func shown(v any) string {
	if v == nil {
		return "no data"
	}
	return fmt.Sprint(v)
}
func FormatText(value object) string {
	var out strings.Builder
	s := obj(value["summary"])
	employee := obj(value["employee"])
	fmt.Fprintf(&out, "Employee %s (%s): done %s; failed %s; running %s; success rate %s; median duration %s s; tokens in/out/cached %s/%s/%s; refusals %s; resumes %s\n", shown(employee["id"]), shown(employee["kind"]), shown(s["tasks_done"]), shown(s["tasks_failed"]), shown(s["tasks_running"]), shown(s["success_rate"]), shown(s["median_duration_seconds"]), shown(s["input_tokens"]), shown(s["output_tokens"]), shown(s["cached_tokens"]), shown(s["refusals"]), shown(s["resumes"]))
	if value["available"] != true {
		out.WriteString("No records.\n")
		return out.String()
	}
	for _, item := range value["rows"].([]any) {
		row := obj(item)
		fmt.Fprintf(&out, "%s  %-8s %s", shown(row["time"]), shown(row["kind"]), shown(row["lane"]))
		for _, field := range []string{"run", "brief_title", "brief_sha256", "outcome", "exit_code", "duration_seconds", "reason", "action", "externally_appended", "rule_id", "model", "account", "cost_usd", "decision_ids", "from", "to"} {
			if row[field] != nil {
				fmt.Fprintf(&out, "  %s=%s", field, strings.ReplaceAll(shown(row[field]), "\n", " "))
			}
		}
		fmt.Fprintf(&out, "  %s\n", shown(row["source"]))
	}
	return out.String()
}
