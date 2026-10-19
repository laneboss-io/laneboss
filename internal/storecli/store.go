// Package storecli exposes the configuration's append-only history records.
package storecli

import (
	"fmt"
	"io"
	"strings"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/eventstore"
	"laneboss.io/laneboss/internal/protocol"
	"laneboss.io/laneboss/internal/report"
)

const usage = "usage: laneboss store search --config NAME QUERY [--kind K] [--lane L]\n       laneboss store record --config NAME --kind K --file FILE [--lane L] [--private]"

func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	for _, arg := range args {
		if arg == "--help" || arg == "-h" {
			fmt.Fprintln(stdout, usage)
			return 0
		}
	}
	if len(args) == 0 || args[0] != "search" && args[0] != "record" {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	values, query, private := map[string]string{}, "", false
	for i := 1; i < len(args); i++ {
		key := args[i]
		if key == "--private" && args[0] == "record" && !private {
			private = true
			continue
		}
		if !strings.HasPrefix(key, "--") && args[0] == "search" && query == "" {
			query = key
			continue
		}
		if key != "--config" && key != "--kind" && key != "--lane" && !(key == "--file" && args[0] == "record") || i+1 == len(args) || values[key] != "" {
			fmt.Fprintln(stderr, usage)
			return 2
		}
		i++
		values[key] = args[i]
	}
	c, err := eventstore.Bind(values["--config"])
	if err != nil {
		return eventstore.Failure(err, stderr)
	}
	principal, err := report.Resolve(c.Name)
	if err != nil {
		return eventstore.Failure(eventstore.Refuse("%s", err), stderr)
	}
	lane := values["--lane"]
	if strings.HasPrefix(principal.ID, "lane:") {
		own := strings.TrimPrefix(principal.ID, "lane:")
		if lane != "" && lane != own {
			return eventstore.Failure(eventstore.Refuse("a lane may access store records only for itself"), stderr)
		}
		lane = own
	}
	var result any
	if args[0] == "search" {
		_, events, readErr := eventstore.ReadDisplay(c)
		err = readErr
		if err == nil {
			result, err = eventstore.SearchRecords(events, query, values["--kind"], lane)
		}
	} else {
		if err = caller.RequireIdentity(principal); err != nil {
			return eventstore.Failure(eventstore.Refuse("%s", err), stderr)
		}
		var data []byte
		data, err = c.ReadExternal(values["--file"], 512*1024)
		if err == nil {
			var payload eventstore.Object
			payload, err = eventstore.RecordPayload(values["--kind"], values["--file"], data, private)
			if err == nil {
				result, err = appendRecord(c, principal.ID, lane, payload)
			}
		}
	}
	if err != nil {
		return eventstore.Failure(err, stderr)
	}
	if err = eventstore.Output(result, stdout); err != nil {
		return eventstore.Failure(err, stderr)
	}
	return 0
}

func appendRecord(c *eventstore.Configuration, actor, lane string, payload eventstore.Object) (eventstore.Object, error) {
	d, err := c.OpenDirectory(true)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	s, err := eventstore.Open(d, true)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	var target any
	if lane != "" {
		target = lane
	}
	return s.Append(eventstore.Object{"kind": "store.record", "lane": target, "actor": actor, "protocol_version": protocol.Version, "payload": payload})
}
