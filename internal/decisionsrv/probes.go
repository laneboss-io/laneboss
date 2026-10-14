//go:build laneboss_faults

package decisionsrv

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/decisions/jsonout"
)

// TryProbe is present as a dispatch hook in both builds. Only this tagged
// implementation recognises the private command or reads its input.
func TryProbe(args []string, stdin io.Reader, stdout, stderr io.Writer) (int, bool) {
	if len(args) == 0 || args[0] != "probe" {
		return 0, false
	}
	if len(args) > 1 {
		o, err := parseOptions(args[1:], "file", "")
		if err == nil {
			err = requireOptions(o, "file")
		}
		if err != nil {
			fmt.Fprintln(stderr, err.Error())
			return errorCode(err), true
		}
		text, err := readRegular(o.get("file"), maxTextBytes)
		if err != nil {
			fmt.Fprintln(stderr, err.Error())
			return errorCode(err), true
		}
		stdin = strings.NewReader(text)
	}
	return Probe(stdin, stdout, stderr), true
}

// Probe is a JSON bridge to the same private functions used by the service. It
// lets the acceptance harness exercise arithmetic and byte bounds without a
// language-specific import or a second implementation of the product logic.
func Probe(input io.Reader, output, errors io.Writer) int {
	reader := bufio.NewScanner(input)
	reader.Buffer(make([]byte, 65536), maxTextBytes)
	var cache *lruCache
	for reader.Scan() {
		value, err := parseJSON(reader.Bytes())
		request := obj(value)
		if err == nil && request == nil {
			err = invalid("probe request must be an object")
		}
		var result any
		if err == nil {
			switch str(request["action"]) {
			case "dot":
				left, e := probeVector(request["left"], false)
				if e != nil {
					err = e
					break
				}
				right, e := probeVector(request["right"], false)
				if e != nil {
					err = e
					break
				}
				result = object{"dot": exactDot(left, right), "norm": vectorNorm(left)}
			case "rank":
				query, e := probeVector(request["query"], true)
				if e != nil {
					err = e
					break
				}
				groups := obj(request["groups"])
				if groups == nil {
					err = invalid("probe groups must be an object")
					break
				}
				entries := []vectorEntry{}
				for id, raw := range groups {
					if !idPattern.MatchString(id) {
						err = invalid("invalid probe record id")
						break
					}
					values, ok := raw.([]any)
					if !ok {
						err = invalid("probe entries must be a list")
						break
					}
					for _, value := range values {
						entry := obj(value)
						if entry == nil {
							err = invalid("probe entry must be an object")
							break
						}
						vector, e := probeVector(entry["vector"], true)
						if e != nil {
							err = e
							break
						}
						if len(vector) != len(query) || (entry["side"] != "q_text" && entry["side"] != "d_text") {
							err = invalid("invalid probe vector dimension or side")
							break
						}
						entries = append(entries, vectorEntry{id, str(entry["side"]), vector, vectorNorm(vector)})
					}
					if err != nil {
						break
					}
				}
				if err != nil {
					break
				}
				model := str(request["model"])
				if !idPattern.MatchString(model) || credentialsInText(model) {
					err = invalid("invalid probe model")
					break
				}
				ranking := rankVectorEntries(model, entries, query)
				if raw := request["depth"]; raw != nil {
					depth, ok := integer(raw)
					if !ok || depth < 1 {
						err = invalid("probe depth must be a positive integer")
						break
					}
					if depth < int64(len(ranking.order)) {
						ranking.order = ranking.order[:int(depth)]
					}
				}
				matches := object{}
				for id, entries := range ranking.evidence {
					values := []object{}
					for _, entry := range entries {
						value := entry.json()
						value["id"] = id
						values = append(values, value)
					}
					matches[id] = values
				}
				scores := object{}
				for id, score := range ranking.scores {
					scores[id] = score
				}
				result = object{"ranking": ranking.order, "matches": matches, "scores": scores}
			case "cache-init":
				cache = newAnswerCache()
				result = object{"entries": len(cache.items), "bytes": cache.bytes, "max_entries": cache.maxEntries, "max_bytes": cache.maxBytes}
			case "cache-put":
				if cache == nil {
					err = invalid("cache probe is not initialized")
					break
				}
				key, ok := request["key"].(string)
				if !ok {
					err = invalid("cache key must be text")
					break
				}
				body, ok := request["body"].(string)
				if !ok {
					err = invalid("cache body must be text")
					break
				}
				cache.put(key, []byte(body), len(body))
				keys := []string{}
				for element := cache.order.Front(); element != nil; element = element.Next() {
					keys = append(keys, element.Value.(cacheItem).key)
				}
				result = object{"keys": keys, "bytes": cache.bytes}
			case "serve-options":
				given := options{}
				if raw, exists := request["idle_exit"]; exists {
					given["idle-exit"] = []string{str(raw)}
				}
				minutes, e := idleMinutes(given)
				err = e
				result = object{"idle_exit": minutes}
			case "lane-end":
				result = LaneEnd(str(request["configuration_name"]), str(request["lane"]), str(request["org_dir"]), str(request["instance"]), str(request["db"]), str(request["directory"]))
				if obj(result)["ok"] == false {
					body, e := jsonout.Line(result)
					if e != nil {
						err = invalid(e.Error())
						break
					}
					if _, e = output.Write(body); e != nil {
						fmt.Fprintln(errors, "cannot write probe result")
						return 2
					}
					return 2
				}
			case "store":
				seconds, ok := number(request["timeout"])
				if !ok || seconds <= 0 {
					err = invalid("store timeout must be positive")
					break
				}
				db, e := openStore(str(request["path"]), request["readonly"] == true, time.Duration(seconds*float64(time.Second)))
				if e != nil {
					err = e
					break
				}
				rows, e := readRows(context.Background(), db, "SELECT count(*) AS records FROM records")
				db.Close()
				err = e
				if e == nil {
					result = rows[0]
				}
			case "log":
				value := obj(request["value"])
				if value == nil || credentialsInValue(value) {
					err = invalid("log probe contains invalid data or a credential")
					break
				}
				if _, err = io.WriteString(output, "ready\n"); err != nil {
					break
				}
				err = appendLog(str(request["path"]), value)
				result = object{"logged": value}
			default:
				err = invalid("unknown probe action")
			}
		}
		if err != nil {
			fmt.Fprintln(errors, err.Error())
			return errorCode(err)
		}
		body, err := jsonout.Line(result)
		if err != nil {
			err = invalid(err.Error())
			fmt.Fprintln(errors, err.Error())
			return errorCode(err)
		}
		if _, err = output.Write(body); err != nil {
			fmt.Fprintln(errors, "cannot write probe result")
			return 2
		}
	}
	if reader.Err() != nil {
		fmt.Fprintln(errors, "invalid input: probe input is unreadable or too large")
		return 2
	}
	return 0
}

func probeVector(value any, nonzero bool) ([]float64, error) {
	values, ok := value.([]any)
	if !ok || len(values) == 0 || len(values) > 4096 {
		return nil, invalid("invalid probe vector")
	}
	vector := make([]float64, len(values))
	for i, value := range values {
		n, ok := number(value)
		if !ok {
			return nil, invalid("probe vector must contain finite numbers")
		}
		vector[i] = n
	}
	if nonzero && vectorNorm(vector) == 0 {
		return nil, invalid("probe vector must be nonzero")
	}
	return vector, nil
}
