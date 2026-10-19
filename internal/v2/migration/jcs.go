package migration

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/jsontext"
	"laneboss.io/laneboss/internal/v2/api"
)

const (
	SchemaMigrationManifest = "laneboss.migration.v2"
	SchemaObjectManifest    = "laneboss.objects.v2"
	SchemaAdoptionManifest  = "laneboss.adoption.v2"
	SchemaQuiescence        = "laneboss.quiescence.v2"
	SchemaVerification      = "laneboss.verification.v2"
)

var (
	v2IDPattern     = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	v2DigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	v2ConfigPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
)

func ValidID(id api.ID) bool {
	return v2IDPattern.MatchString(string(id))
}

func ValidDigest(d api.Digest) bool {
	return v2DigestPattern.MatchString(string(d))
}

func ValidConfigName(name string) bool {
	return v2ConfigPattern.MatchString(name)
}

func ValidTimestamp(ts api.Timestamp) bool {
	s := string(ts)
	if !strings.HasSuffix(s, "Z") {
		return false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	return err == nil && t.Year() >= 1 && t.Year() <= 9999
}

func ValidBlobClass(c string) bool {
	switch c {
	case "task", "prompt", "report", "artifact", "capture", "transcript",
		"policy", "manifest", "judge_request", "judge_raw", "archive", "record":
		return true
	}
	return false
}

func ValidateBlobRef(ref api.BlobRef, expectedClass string) error {
	if !ValidID(ref.ID) {
		return invalidErr("blob reference id is invalid")
	}
	if !ValidDigest(ref.SHA256) {
		return invalidErr("blob reference sha256 must be 64 lowercase hex digits")
	}
	if ref.Bytes < 0 || ref.Bytes > api.MaxObjectBytes {
		return invalidErr("blob reference bytes out of bounds")
	}
	if !ValidBlobClass(ref.Class) {
		return invalidErr("blob reference class is invalid")
	}
	if expectedClass != "" && ref.Class != expectedClass {
		return invalidErr(fmt.Sprintf("blob reference class must be %s", expectedClass))
	}
	return nil
}

func ValidateObjectManifest(m api.ObjectManifest) error {
	if m.Schema != SchemaObjectManifest {
		return invalidErr("inventory schema must be laneboss.objects.v2")
	}
	if m.Entries == nil {
		return invalidErr("inventory entries must be a non-null array")
	}
	seen := make(map[string]bool, len(m.Entries))
	for i, e := range m.Entries {
		if err := validateRelativePath(e.Path); err != nil {
			return invalidErr(fmt.Sprintf("inventory.entries[%d].path: %v", i, err))
		}
		if seen[e.Path] {
			return invalidErr(fmt.Sprintf("duplicate inventory path: %s", e.Path))
		}
		seen[e.Path] = true
		if e.Mode&0o7000 != 0 {
			return invalidErr(fmt.Sprintf("inventory.entries[%d].mode: setuid/setgid/sticky bits are forbidden", i))
		}
		switch e.Kind {
		case "file":
			if (e.Content == nil) == (e.Assembly == nil) {
				return invalidErr(fmt.Sprintf("inventory.entries[%d]: file requires exactly one of content or assembly", i))
			}
			if e.LinkTarget != "" {
				return invalidErr(fmt.Sprintf("inventory.entries[%d]: file cannot have link_target", i))
			}
			if e.Content != nil {
				if err := ValidateBlobRef(*e.Content, ""); err != nil {
					return invalidErr(fmt.Sprintf("inventory.entries[%d].content: %v", i, err))
				}
			}
			if e.Assembly != nil {
				if !ValidDigest(e.Assembly.SHA256) || e.Assembly.Bytes <= 0 || len(e.Assembly.Parts) == 0 {
					return invalidErr(fmt.Sprintf("inventory.entries[%d].assembly: invalid assembly metadata", i))
				}
				var sumBytes int64
				for pIdx, part := range e.Assembly.Parts {
					if err := ValidateBlobRef(part, ""); err != nil {
						return invalidErr(fmt.Sprintf("inventory.entries[%d].assembly.parts[%d]: %v", i, pIdx, err))
					}
					sumBytes += part.Bytes
				}
				if sumBytes != e.Assembly.Bytes {
					return invalidErr(fmt.Sprintf("inventory.entries[%d].assembly: parts byte sum does not match assembly bytes", i))
				}
			}
		case "directory":
			if e.Content != nil || e.Assembly != nil || e.LinkTarget != "" {
				return invalidErr(fmt.Sprintf("inventory.entries[%d]: directory cannot have content, assembly or link_target", i))
			}
		case "symlink":
			if e.Content != nil || e.Assembly != nil {
				return invalidErr(fmt.Sprintf("inventory.entries[%d]: symlink cannot have content or assembly", i))
			}
			if err := validateInternalSymlink(e.Path, e.LinkTarget); err != nil {
				return invalidErr(fmt.Sprintf("inventory.entries[%d].link_target: %v", i, err))
			}
		default:
			return invalidErr(fmt.Sprintf("inventory.entries[%d].kind: unsupported kind %q", i, e.Kind))
		}
	}
	return nil
}

func validateRelativePath(p string) error {
	if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, "\\") || strings.ContainsRune(p, 0) {
		return fmt.Errorf("must be a safe relative path")
	}
	parts := strings.Split(p, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("path traversal or empty segment is forbidden")
		}
	}
	if path.Clean(p) != p {
		return fmt.Errorf("path is not canonical")
	}
	return nil
}

func validateInternalSymlink(entryPath, target string) error {
	if target == "" || strings.HasPrefix(target, "/") || strings.Contains(target, "\\") || strings.ContainsRune(target, 0) {
		return fmt.Errorf("symlink target must be a relative internal path")
	}
	joined := path.Clean(path.Join(path.Dir(entryPath), target))
	if joined == "." || joined == ".." || strings.HasPrefix(joined, "../") || strings.HasPrefix(joined, "/") {
		return fmt.Errorf("symlink target escapes inventory root")
	}
	return nil
}

func DigestBytes(data []byte) api.Digest {
	sum := sha256.Sum256(data)
	return api.Digest(hex.EncodeToString(sum[:]))
}

func NewOpaqueID(prefix string) (api.ID, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return api.ID(prefix + hex.EncodeToString(b[:])), nil
}

func DeterministicID(prefix string, parts ...string) api.ID {
	h := sha256.New()
	for i, p := range parts {
		if i > 0 {
			h.Write([]byte{0})
		}
		h.Write([]byte(p))
	}
	sum := h.Sum(nil)
	return api.ID(prefix + hex.EncodeToString(sum[:12]))
}

func sanitizeRecordID(prefix, raw string) api.ID {
	if raw != "" {
		candidate := api.ID(prefix + raw)
		if ValidID(candidate) {
			return candidate
		}
	}
	return DeterministicID(prefix, raw)
}

// DecodeStrictJSON decodes raw JSON bytes into dst while rejecting invalid UTF-8,
// unpaired UTF-16 surrogates, duplicate object keys, non-finite numbers, unknown
// struct fields, and trailing bytes.
func DecodeStrictJSON(raw []byte, dst any) error {
	if len(raw) == 0 || len(raw) > api.MaxObjectBytes {
		return invalidErr("JSON payload is empty or exceeds bound")
	}
	if !jsontext.ValidUnicode(raw) {
		return invalidErr("JSON payload contains invalid UTF-8 or unpaired surrogates")
	}
	if _, err := parseNoDupTree(raw); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return invalidErr("invalid JSON request shape: " + err.Error())
	}
	if _, err := dec.Token(); err != io.EOF {
		return invalidErr("trailing JSON content is forbidden")
	}
	return nil
}

func parseNoDupTree(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, err := decodeNoDupNode(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, invalidErr("trailing JSON tokens are forbidden")
	}
	return v, nil
}

func decodeNoDupNode(dec *json.Decoder, depth int) (any, error) {
	if depth > 256 {
		return nil, invalidErr("JSON nesting exceeds limit")
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, invalidErr("malformed JSON")
	}
	switch x := tok.(type) {
	case json.Delim:
		if x == '{' {
			m := make(map[string]any)
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, invalidErr("malformed JSON key")
				}
				k, ok := kt.(string)
				if !ok {
					return nil, invalidErr("JSON key must be string")
				}
				if _, dup := m[k]; dup {
					return nil, invalidErr("duplicate JSON key: " + k)
				}
				val, err := decodeNoDupNode(dec, depth+1)
				if err != nil {
					return nil, err
				}
				m[k] = val
			}
			end, err := dec.Token()
			if err != nil || end != json.Delim('}') {
				return nil, invalidErr("unclosed JSON object")
			}
			return m, nil
		}
		if x == '[' {
			arr := []any{}
			for dec.More() {
				val, err := decodeNoDupNode(dec, depth+1)
				if err != nil {
					return nil, err
				}
				arr = append(arr, val)
			}
			end, err := dec.Token()
			if err != nil || end != json.Delim(']') {
				return nil, invalidErr("unclosed JSON array")
			}
			return arr, nil
		}
		return nil, invalidErr("unexpected JSON delimiter")
	case json.Number:
		s := string(x)
		if !strings.ContainsAny(s, ".eE") {
			if n, err := strconv.ParseInt(s, 10, 64); err == nil {
				return n, nil
			}
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return nil, invalidErr("non-finite JSON number")
		}
		return f, nil
	default:
		return tok, nil
	}
}

// CanonicalJCS serializes v into RFC 8785 JCS canonical UTF-8 JSON bytes.
func CanonicalJCS(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return api.CanonicalJSON(raw)
}

func writeJCS(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		writeJCSString(buf, x)
	case int:
		buf.WriteString(strconv.Itoa(x))
	case int64:
		buf.WriteString(strconv.FormatInt(x, 10))
	case uint64:
		buf.WriteString(strconv.FormatUint(x, 10))
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return invalidErr("non-finite float in JCS")
		}
		if x == 0 {
			buf.WriteString("0")
		} else {
			buf.WriteString(strconv.FormatFloat(x, 'g', -1, 64))
		}
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeJCSString(buf, k)
			buf.WriteByte(':')
			if err := writeJCS(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeJCS(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	default:
		return fmt.Errorf("unsupported JCS value type %T", v)
	}
	return nil
}

func writeJCSString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

// RequestDigest computes SHA256(RFC8785-JCS({protocol,schema,config,method,params})).
func RequestDigest(config string, method api.Method, params any) (api.Digest, error) {
	envelope := map[string]any{
		"protocol": api.Protocol,
		"schema":   api.SchemaVersion,
		"config":   config,
		"method":   string(method),
		"params":   params,
	}
	jcs, err := CanonicalJCS(envelope)
	if err != nil {
		return "", err
	}
	return DigestBytes(jcs), nil
}

func invalidErr(msg string) *api.Error {
	return &api.Error{
		Code:    api.CodeInvalid,
		Message: msg,
		Instead: "Correct the migration request or manifest file and retry.",
		Owner:   "lb-v2-migration",
	}
}

func integrityErr(msg string) *api.Error {
	return &api.Error{
		Code:    api.CodeIntegrity,
		Message: msg,
		Instead: "Preserve the frozen source state and evidence without modifying it, and inspect the integrity failure.",
		Owner:   "lb-v2-migration",
	}
}

func conflictErr(msg string) *api.Error {
	return &api.Error{
		Code:    api.CodeConflict,
		Message: msg,
		Instead: "Quiesce all legacy writers and use a separate service-owned destination store.",
		Owner:   "lb-v2-migration",
	}
}

func forbiddenErr(msg string) *api.Error {
	return &api.Error{
		Code:    api.CodeForbidden,
		Message: msg,
		Instead: "Authenticate through the human endpoint with an operation-bound human confirmation proof.",
		Owner:   "lb-v2-migration",
	}
}
