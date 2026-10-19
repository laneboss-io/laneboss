// Package typesafe validates the documented System One HTTP wire contract.
// It has no network or credential access; policy and retries belong to callers.
package typesafe

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"math/big"
	"strconv"
	"strings"
	"unicode/utf8"
)

var ErrWire = errors.New("not the documented TypeSafe response")

// ProbabilitySumTolerance budgets half a 4-decimal-place rounding unit per
// option. api.md:255 and primitives_choice.md:346 require a sum of one but
// specify no precision. This application tolerance is not a service guarantee.
func ProbabilitySumTolerance(options int) float64 {
	return math.Max(1e-6, float64(options)*5e-5)
}

// Decode rejects duplicate members, invalid Unicode and trailing JSON.
func Decode(raw []byte) (map[string]any, error) {
	if !utf8.Valid(raw) || !validUnicode(raw) {
		return nil, ErrWire
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, err := readValue(d, 0)
	if err != nil {
		return nil, ErrWire
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, ErrWire
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, ErrWire
	}
	return m, nil
}

func readValue(d *json.Decoder, depth int) (any, error) {
	if depth > 128 {
		return nil, ErrWire
	}
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := t.(json.Delim); ok {
		switch delim {
		case '{':
			m := map[string]any{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return nil, err
				}
				name, ok := key.(string)
				if !ok {
					return nil, ErrWire
				}
				if _, exists := m[name]; exists {
					return nil, ErrWire
				}
				v, err := readValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				m[name] = v
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return nil, ErrWire
			}
			return m, nil
		case '[':
			a := []any{}
			for d.More() {
				v, err := readValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return nil, ErrWire
			}
			return a, nil
		default:
			return nil, ErrWire
		}
	}
	return t, nil
}

func validUnicode(raw []byte) bool {
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) || raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		n, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}

// Number checks exact decimal bounds before allowing binary64 rounding.
func Number(value any, top float64) (float64, bool) {
	n, ok := value.(json.Number)
	if !ok || len(n.String()) > 1024 {
		return 0, false
	}
	raw := n.String()
	mantissa := raw
	if at := strings.IndexAny(mantissa, "eE"); at >= 0 {
		mantissa = mantissa[:at]
	}
	if strings.Trim(strings.TrimPrefix(mantissa, "-"), "0.") == "" {
		return 0, true
	}
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > top {
		return 0, false
	}
	// Large negative exponents underflow, but negative nonzero decimals must
	// still fail. Never allocate a power of ten for an unbounded exponent.
	if at := strings.IndexAny(raw, "eE"); at >= 0 {
		exp, err := strconv.Atoi(raw[at+1:])
		if err != nil || exp < -400 {
			if strings.HasPrefix(raw[at+1:], "-") && !strings.HasPrefix(raw, "-") {
				return 0, true
			}
			return 0, false
		}
		if exp > 400 {
			return 0, false
		}
	}
	exact, ok := new(big.Rat).SetString(raw)
	if !ok || exact.Sign() < 0 || exact.Cmp(new(big.Rat).SetFloat64(top)) > 0 {
		return 0, false
	}
	return f, true
}

func description(v any) bool {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x) != ""
	case map[string]any:
		return len(x) > 0
	case []any:
		return len(x) > 0
	}
	return false
}

// Questions validates decoded question objects, not model-specific ID meaning.
func Questions(questions map[string]any) bool {
	if len(questions) == 0 {
		return false
	}
	for id, value := range questions {
		q, ok := value.(map[string]any)
		if id == "" || !ok || !description(q["instructions"]) {
			return false
		}
		switch q["type"] {
		case "noul":
			if c, exists := q["criteria"]; exists {
				criteria, ok := c.(map[string]any)
				if !ok {
					return false
				}
				for key, v := range criteria {
					if (key != "true" && key != "false") || !description(v) {
						return false
					}
				}
			}
		case "choice":
			criteria, ok := q["criteria"].(map[string]any)
			if !ok || len(criteria) < 1 || len(criteria) > 255 {
				return false
			}
			for key, v := range criteria {
				if key == "" || (v != nil && !description(v)) {
					return false
				}
			}
		case "score":
			criteria, ok := q["criteria"].([]any)
			if !ok || len(criteria) < 2 || len(criteria) > 10 {
				return false
			}
			for _, v := range criteria {
				if !description(v) {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

func count(v any) bool {
	n, ok := v.(json.Number)
	if !ok || strings.ContainsAny(n.String(), ".eE") {
		return false
	}
	i, err := strconv.ParseInt(n.String(), 10, 64)
	return err == nil && i >= 0
}

// Response validates a whole envelope atomically. A missing, extra or malformed
// answer invalidates the batch; callers never infer a low score from absence.
func Response(raw []byte, questions map[string]any) (map[string]any, error) {
	root, err := Decode(raw)
	if err != nil || !Questions(questions) {
		return nil, ErrWire
	}
	model, ok := root["model"].(string)
	usage, usageOK := root["usage"].(map[string]any)
	answers, answersOK := root["answers"].(map[string]any)
	if !ok || strings.TrimSpace(model) == "" || !usageOK || !answersOK || len(answers) != len(questions) {
		return nil, ErrWire
	}
	for _, field := range []string{"input_tokens", "output_tokens"} {
		if value, present := usage[field]; present && !count(value) {
			return nil, ErrWire
		}
	}
	for id, value := range questions {
		q := value.(map[string]any)
		a, ok := answers[id].(map[string]any)
		if !ok || a["type"] != q["type"] {
			return nil, ErrWire
		}
		if q["type"] == "noul" {
			if _, ok := Number(a["noul"], 1); !ok {
				return nil, ErrWire
			}
			continue
		}
		if _, ok := Number(a["confidence"], 1); !ok {
			return nil, ErrWire
		}
		keys := map[string]any{}
		if q["type"] == "choice" {
			keys = q["criteria"].(map[string]any)
		} else {
			for i, level := range q["criteria"].([]any) {
				keys[strconv.Itoa(i)] = level
			}
		}
		dist, ok := a["probabilities"].(map[string]any)
		if !ok || len(dist) != len(keys) {
			return nil, ErrWire
		}
		sum, peak, weighted := 0.0, 0.0, 0.0
		for key := range keys {
			p, ok := Number(dist[key], 1)
			if !ok {
				return nil, ErrWire
			}
			sum += p
			peak = math.Max(peak, p)
			if q["type"] == "score" {
				i, _ := strconv.Atoi(key)
				weighted += float64(i) * p
			}
		}
		if math.Abs(sum-1) > ProbabilitySumTolerance(len(keys)) {
			return nil, ErrWire
		}
		if q["type"] == "choice" {
			choice, ok := a["choice"].(string)
			p, known := Number(dist[choice], 1)
			if !ok || !known || p < peak {
				return nil, ErrWire
			}
		} else {
			score, ok := Number(a["score"], float64(len(keys)-1))
			legend, legendOK := a["legend"].(map[string]any)
			if !ok || !legendOK || len(legend) != len(keys) || math.Abs(score-weighted) > 1e-6 {
				return nil, ErrWire
			}
			for key, level := range keys {
				want, _ := json.Marshal(level)
				got, _ := json.Marshal(legend[key])
				if !bytes.Equal(want, got) {
					return nil, ErrWire
				}
			}
		}
	}
	// Keep the documented fields; arbitrary provider extras must not become
	// adapter output. The optional launcher request id survives a round trip.
	cleanUsage := map[string]any{}
	for _, field := range []string{"input_tokens", "output_tokens"} {
		if value, present := usage[field]; present {
			cleanUsage[field] = value
		}
	}
	clean := map[string]any{"model": model, "usage": cleanUsage, "answers": map[string]any{}}
	if id, exists := root["request"]; exists {
		clean["request"] = id
	}
	for id, value := range answers {
		a := value.(map[string]any)
		fields := "type noul"
		if a["type"] == "choice" {
			fields = "type choice probabilities confidence"
		} else if a["type"] == "score" {
			fields = "type score legend probabilities confidence"
		}
		entry := map[string]any{}
		for _, key := range strings.Fields(fields) {
			entry[key] = a[key]
		}
		clean["answers"].(map[string]any)[id] = entry
	}
	return clean, nil
}
