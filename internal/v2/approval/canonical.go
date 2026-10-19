package approval

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"sort"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/v2/api"
)

// ManifestDigest covers the entire source/derived delta and renderer artifact.
// Lists are copied before sorting. Caller order never changes the meaning of a
// manifest, and no caller-owned slice or BlobRef is modified.
func ManifestDigest(change api.ChangeRequest) (api.Digest, error) {
	if !validID(change.OrgID) || !validGeneration(change.BaseGeneration) {
		return "", invalid("invalid org or base generation")
	}
	files, err := normalizedFiles(change.Files, false)
	if err != nil {
		return "", err
	}
	derived, err := normalizedFiles(change.Derived, true)
	if err != nil {
		return "", err
	}
	if err = disjointFiles(files, derived); err != nil {
		return "", err
	}
	if err = validRenderer(change.Renderer); err != nil {
		return "", err
	}
	return canonicalDigest(map[string]any{
		"org_id": change.OrgID, "base_generation": change.BaseGeneration,
		"files": files, "derived": derived, "renderer": change.Renderer,
	})
}

func canonicalDigest(value any) (api.Digest, error) {
	data, err := canonical(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return api.Digest(hex.EncodeToString(sum[:])), nil
}

func canonical(value any) ([]byte, error) {
	if err := inputStrings(reflect.ValueOf(value), 0); err != nil {
		return nil, err
	}
	var serialized bytes.Buffer
	encoder := json.NewEncoder(&serialized)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, invalid("approval object cannot be encoded")
	}
	decoder := json.NewDecoder(&serialized)
	decoder.UseNumber()
	parsed, err := readValue(decoder, 0)
	if err != nil {
		return nil, err
	}
	var output bytes.Buffer
	if err = writeCanonical(&output, parsed); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func inputStrings(value reflect.Value, depth int) error {
	if depth > 32 {
		return invalid("approval object exceeds its nesting bound")
	}
	if !value.IsValid() {
		return nil
	}
	switch value.Kind() {
	case reflect.Interface, reflect.Pointer:
		if !value.IsNil() {
			return inputStrings(value.Elem(), depth+1)
		}
	case reflect.String:
		if !utf8.ValidString(value.String()) {
			return invalid("approval string must be UTF-8")
		}
	case reflect.Map:
		for _, key := range value.MapKeys() {
			if err := inputStrings(key, depth+1); err != nil {
				return err
			}
			if err := inputStrings(value.MapIndex(key), depth+1); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < value.Len(); i++ {
			if err := inputStrings(value.Index(i), depth+1); err != nil {
				return err
			}
		}
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			if err := inputStrings(value.Field(i), depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeCanonical(output *bytes.Buffer, value any) error {
	switch v := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		output.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				output.WriteByte(',')
			}
			if err := writeString(output, key); err != nil {
				return err
			}
			output.WriteByte(':')
			if err := writeCanonical(output, v[key]); err != nil {
				return err
			}
		}
		output.WriteByte('}')
	case []any:
		output.WriteByte('[')
		for i, child := range v {
			if i > 0 {
				output.WriteByte(',')
			}
			if err := writeCanonical(output, child); err != nil {
				return err
			}
		}
		output.WriteByte(']')
	case string:
		return writeString(output, v)
	case json.Number:
		number, err := strconv.ParseUint(string(v), 10, 64)
		if err != nil || number > maxInteger {
			return invalid("approval numbers must be exact nonnegative integers")
		}
		output.WriteString(strconv.FormatUint(number, 10))
	case bool:
		output.WriteString(strconv.FormatBool(v))
	default:
		return invalid("approval object has an unsupported JSON value")
	}
	return nil
}

func writeString(output *bytes.Buffer, value string) error {
	if !utf8.ValidString(value) {
		return invalid("approval string must be UTF-8")
	}
	const hexDigits = "0123456789abcdef"
	output.WriteByte('"')
	for _, char := range value {
		switch char {
		case '"', '\\':
			output.WriteByte('\\')
			output.WriteRune(char)
		case '\b':
			output.WriteString(`\b`)
		case '\t':
			output.WriteString(`\t`)
		case '\n':
			output.WriteString(`\n`)
		case '\f':
			output.WriteString(`\f`)
		case '\r':
			output.WriteString(`\r`)
		default:
			if char < 0x20 {
				output.WriteString(`\u00`)
				output.WriteByte(hexDigits[char>>4])
				output.WriteByte(hexDigits[char&15])
			} else {
				output.WriteRune(char)
			}
		}
	}
	output.WriteByte('"')
	return nil
}

func utf16Less(left, right string) bool {
	a, b := utf16.Encode([]rune(left)), utf16.Encode([]rune(right))
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}
