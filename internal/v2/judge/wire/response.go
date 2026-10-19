package wire

import (
	"encoding/json"
	"errors"
	"strings"

	"laneboss.io/laneboss/internal/typesafe"
	"laneboss.io/laneboss/internal/v2/api"
)

var errResponse = errors.New("invalid complete judge response")

type responseData struct {
	model      string
	input      int64
	output     int64
	usageKnown bool
	partial    bool
	answers    map[api.ID]float64
}

func fields(m map[string]any, names string) bool {
	for key := range m {
		found := false
		for _, name := range strings.Fields(names) {
			if key == name {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

const flags = "partial truncated input_truncated withheld finish_reason"

func incomplete(m map[string]any) bool {
	for _, key := range strings.Fields("partial truncated input_truncated withheld") {
		if value, exists := m[key]; exists && value != false {
			return true
		}
	}
	if value, exists := m["finish_reason"]; exists && value != "stop" {
		return true
	}
	return false
}

func usageCount(value any) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok || strings.ContainsAny(number.String(), ".eE") {
		return 0, false
	}
	n, err := number.Int64()
	return n, err == nil && n >= 0 && n <= maxInteger
}

// The retained wire validator rejects duplicates, invalid UTF-8/surrogates,
// trailing JSON and decimal values outside [0,1] before binary64 rounding.
// This layer narrows it to the frozen v2 Noul contract and checks all metadata.
func decodeResponse(raw []byte, ids []api.ID, model string) (responseData, error) {
	var result responseData
	root, err := typesafe.Decode(raw)
	if err != nil {
		return result, errResponse
	}
	reported, _ := root["model"].(string)
	if modelName.MatchString(reported) {
		result.model = reported
	}
	usage, ok := root["usage"].(map[string]any)
	if ok {
		var inputOK, outputOK bool
		result.input, inputOK = usageCount(usage["input_tokens"])
		result.output, outputOK = usageCount(usage["output_tokens"])
		result.usageKnown = inputOK && outputOK
	}
	if result.model != model || !result.usageKnown ||
		!fields(root, "model answers usage request metadata "+flags) ||
		!fields(usage, "input_tokens output_tokens "+flags) {
		return result, errResponse
	}
	if request, exists := root["request"]; exists {
		id, ok := request.(string)
		if !ok || !ValidID(api.ID(id)) {
			return result, errResponse
		}
	}
	result.partial = incomplete(root) || incomplete(usage)
	if metadata, exists := root["metadata"]; exists {
		m, ok := metadata.(map[string]any)
		if !ok || !fields(m, flags) {
			return result, errResponse
		}
		result.partial = result.partial || incomplete(m)
	}
	answers, ok := root["answers"].(map[string]any)
	if !ok || len(answers) != len(ids) {
		return result, errResponse
	}
	result.answers = make(map[api.ID]float64, len(ids))
	for _, id := range ids {
		a, ok := answers[string(id)].(map[string]any)
		if !ok || a["type"] != "noul" || !fields(a, "type noul metadata "+flags) {
			return result, errResponse
		}
		if metadata, exists := a["metadata"]; exists {
			m, ok := metadata.(map[string]any)
			if !ok || !fields(m, flags) {
				return result, errResponse
			}
			result.partial = result.partial || incomplete(m)
		}
		result.partial = result.partial || incomplete(a)
		p, ok := typesafe.Number(a["noul"], 1)
		if !ok {
			return result, errResponse
		}
		result.answers[id] = p
	}
	return result, nil
}
