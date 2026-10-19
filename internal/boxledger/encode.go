package boxledger

import (
	"bytes"
	"encoding/json"
	"math"
	"strconv"
	"strings"
)

func encodeLine(row map[string]any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(row); err != nil {
		return nil, err
	}
	data := bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'})
	line := make([]byte, 0, len(data)+1)
	inString := false
	for i := 0; i < len(data); {
		c := data[i]
		if inString && c == '\\' {
			// JSON's JavaScript escapes differ from Python's UTF-8 output.
			if bytes.HasPrefix(data[i:], []byte(`\u2028`)) {
				line = append(line, []byte("\u2028")...)
				i += 6
				continue
			}
			if bytes.HasPrefix(data[i:], []byte(`\u2029`)) {
				line = append(line, []byte("\u2029")...)
				i += 6
				continue
			}
			line = append(line, data[i:i+2]...)
			i += 2
			continue
		}
		if c == '"' {
			inString = !inString
		}
		if !inString && (c == '-' || c >= '0' && c <= '9') {
			end := i + 1
			for end < len(data) && strings.ContainsRune("0123456789.eE+-", rune(data[end])) {
				end++
			}
			number, err := pythonNumber(string(data[i:end]))
			if err != nil {
				return nil, err
			}
			line = append(line, number...)
			i = end
			continue
		}
		line = append(line, c)
		i++
	}
	return append(line, '\n'), nil
}

func pythonNumber(text string) (string, error) {
	if text == "-0" {
		return "0", nil
	}
	if !strings.ContainsAny(text, ".eE") {
		return text, nil
	}
	n, err := strconv.ParseFloat(text, 64)
	if err != nil {
		return "", err
	}
	// Python switches small fractions to scientific notation and pads exponents.
	if n != 0 && math.Abs(n) < 0.0001 || strings.ContainsAny(text, "eE") && math.Abs(n) >= 1e16 {
		return strconv.FormatFloat(n, 'e', -1, 64), nil
	}
	if strings.ContainsAny(text, "eE") {
		return strconv.FormatFloat(n, 'f', -1, 64), nil
	}
	return text, nil
}
