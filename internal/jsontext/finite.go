package jsontext

import "strings"

// Python's stream reader accepted JSON's nonstandard non-finite constants.
// Normalize only unquoted tokens to null so costs remain unknown; preserve text.
func FiniteJSON(line string) string {
	var result strings.Builder
	quoted, escaped := false, false
	for i := 0; i < len(line); {
		c := line[i]
		if quoted {
			result.WriteByte(c)
			i++
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				quoted = false
			}
			continue
		}
		if c == '"' {
			quoted = true
			result.WriteByte(c)
			i++
			continue
		}
		matched := false
		for _, token := range []string{"NaN", "Infinity", "-Infinity"} {
			end := i + len(token)
			left := i == 0 || strings.ContainsRune("[:,{ \t\r\n", rune(line[i-1]))
			right := end == len(line) || end < len(line) && strings.ContainsRune(",]} \t\r\n", rune(line[end]))
			if left && right && strings.HasPrefix(line[i:], token) {
				result.WriteString("null")
				i = end
				matched = true
				break
			}
		}
		if !matched {
			result.WriteByte(c)
			i++
		}
	}
	return result.String()
}
