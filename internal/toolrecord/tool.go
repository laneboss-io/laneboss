// Package toolrecord records visibility metadata, never permission grants.
package toolrecord

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/eventstore"
	"laneboss.io/laneboss/internal/protocol"
)

func Rows(events []eventstore.Object) []map[string]any {
	rows := []map[string]any{}
	for _, e := range events {
		if e["kind"] == "tool.submitted" {
			p, ok := eventstore.ScreenValue(e["payload"]).(map[string]any)
			if !ok {
				continue
			}
			p["id"], p["event"], p["time"] = e["id"], e["seq"], e["recorded_at"]
			rows = append(rows, p)
		}
	}
	return rows
}
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	usage := "usage: laneboss tool submit --config NAME [--instance ID | --lane NAME] --file FILE --purpose TEXT"
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprintln(stdout, usage)
		return 0
	}
	if len(args) == 0 || args[0] != "submit" {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	values := map[string]string{}
	for i := 1; i < len(args); i++ {
		key := args[i]
		if key != "--config" && key != "--instance" && key != "--lane" && key != "--file" && key != "--purpose" || i+1 == len(args) || values[key] != "" {
			fmt.Fprintln(stderr, usage)
			return 2
		}
		i++
		values[key] = args[i]
	}
	if values["--config"] == "" || values["--file"] == "" || (values["--instance"] == "") == (values["--lane"] == "") || strings.TrimSpace(values["--purpose"]) == "" || utf8.RuneCountInString(values["--purpose"]) > 1000 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	identity := values["--instance"]
	if identity == "" {
		identity = values["--lane"]
	}
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`).MatchString(identity) {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	if eventstore.ScreenValue(values["--purpose"]) != values["--purpose"] {
		fmt.Fprintln(stderr, "refused: the purpose contains a credential-shaped value")
		return 2
	}
	c, err := eventstore.Bind(values["--config"])
	if err != nil {
		return eventstore.Failure(err, stderr)
	}
	data, err := c.ReadExternal(values["--file"], 128*1024)
	if err != nil {
		return eventstore.Failure(err, stderr)
	}
	if !utf8.Valid(data) {
		fmt.Fprintln(stderr, "refused: the submission must be UTF-8 text")
		return 2
	}
	preview := eventstore.ScreenValue(string(data)).(string)
	r := []rune(preview)
	if len(r) > 1000 {
		preview = string(r[:999]) + "…"
	}
	path, err := filepath.Abs(values["--file"])
	if err != nil {
		return 2
	}
	_, version, err := protocol.Load()
	if err != nil {
		return 3
	}
	d, err := c.OpenDirectory(true)
	if err != nil {
		return eventstore.Failure(err, stderr)
	}
	defer d.Close()
	store, err := eventstore.Open(d, true)
	if err != nil {
		return eventstore.Failure(err, stderr)
	}
	defer store.Close()
	receipt, err := store.Append(eventstore.Object{"kind": "tool.submitted", "actor": "employee (cli)", "protocol_version": version, "payload": map[string]any{"instance": values["--instance"], "lane": values["--lane"], "path": eventstore.ScreenValue(path), "sha256": fmt.Sprintf("%x", sha256.Sum256(data)), "purpose": values["--purpose"], "preview": preview, "policy_changed": false}})
	if err != nil {
		return eventstore.Failure(err, stderr)
	}
	if err = json.NewEncoder(stdout).Encode(eventstore.ScreenValue(receipt)); err != nil {
		return 70
	}
	return 0
}
