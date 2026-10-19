// Package wire validates the bounded, value-free secret protocol metadata.
package wire

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"path"
	"reflect"
	"strings"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/v2/api"
)

const MaxMaterial = 64 * 1024

func Error(code api.ErrorCode, message string) *api.Error {
	instead := "Correct the bounded request file without including secret values."
	switch code {
	case api.CodeIntegrity:
		instead = "Stop dependent work and retain encrypted records and operation evidence for investigation."
	case api.CodeForbidden, api.CodeUnauthenticated:
		instead = "Use the verified human endpoint or an exact current delegated source grant."
	case api.CodePrerequisite, api.CodeUnavailable, api.CodeUnsupported:
		instead = "Repair the named prerequisite through the installed service before launching."
	case api.CodeConflict:
		instead = "Inspect the original operation and source version before retrying the same intent."
	case api.CodeDeadline, api.CodeContainmentUnknown:
		instead = "Inspect the exact run and retain runtime slots until quiescence is verified."
	case api.CodeCancelled:
		instead = "Inspect the original operation receipt before retrying."
	}
	return &api.Error{Code: code, Message: message, Instead: instead, Owner: "lb-v2-secrets"}
}

func Context(ctx context.Context) error {
	switch ctx.Err() {
	case nil:
		return nil
	case context.DeadlineExceeded:
		return Error(api.CodeDeadline, "secret operation exceeded its deadline")
	default:
		return Error(api.CodeCancelled, "secret operation was cancelled")
	}
}

func ID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, c := range []byte(value) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
			c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func Name(value string) bool {
	if len(value) == 0 || len(value) > 128 || value == "." || value == ".." {
		return false
	}
	for i, c := range []byte(value) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
			c >= '0' && c <= '9' || i > 0 && (c == '-' || c == '_' || c == '.')) {
			return false
		}
	}
	return true
}

func RandomID() (api.ID, error) {
	var data [24]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", Error(api.CodeUnavailable, "secure randomness is unavailable")
	}
	return api.ID(hex.EncodeToString(data[:])), nil
}

func Digest(value api.Digest) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range []byte(value) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// EnvTarget uses a blacklist of control/loader/vendor namespaces. It does not
// restrict the programs a lane may execute. Host environment values are never read.
func EnvTarget(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for i, c := range []byte(value) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' ||
			i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	upper := strings.ToUpper(value)
	for _, prefix := range []string{
		"LANEBOSS", "LD_", "DYLD_", "CLAUDE", "CLAUDOCK", "CODEX",
		"XDG_", "BASH", "ZSH", "ENV", "SHELLOPTS", "PYTHON", "PERL",
		"RUBY", "JAVA_", "JDK_", "NODE_", "GIT_", "SSH_", "TMUX", "SYSTEMD_", "LISTEN_",
		"BWRAP", "DBUS_", "OPENAI_", "ANTHROPIC_",
		"MALLOC_",
	} {
		if strings.HasPrefix(upper, prefix) {
			return false
		}
	}
	switch upper {
	case "HOME", "PATH", "TMPDIR", "TMP", "TEMP", "USER", "LOGNAME",
		"SHELL", "PWD", "OLDPWD", "IFS", "CDPATH", "SHLVL", "_",
		"SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE", "GCONV_PATH",
		"LOCPATH", "NLSPATH", "HOSTALIASES", "RES_OPTIONS", "LOCALDOMAIN", "GETCONF_DIR", "NIS_PATH", "RESOLV_HOST_CONF", "PS4", "GOFLAGS":
		return false
	case "GLIBC_TUNABLES", "ZDOTDIR", "FPATH", "PROMPT_COMMAND", "TZDIR",
		"JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS":
		return false
	}
	return true
}

func FileTarget(value string) bool {
	if len(value) == 0 || len(value) > 240 || path.IsAbs(value) ||
		path.Clean(value) != value || strings.Contains(value, "\\") {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." || len(part) > 128 {
			return false
		}
		for _, c := range []byte(part) {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
				c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
				return false
			}
		}
	}
	return true
}

// Decode rejects duplicate/unknown/missing keys, nulls, invalid UTF-8 and trailing
// data, including when the dispatcher is replaced by a focused test registrar.
// Secrets requests contain no floating-point or arbitrary JSON fields.
func Decode(data []byte, target any, max int) error {
	if len(data) == 0 || len(data) > max || !utf8.Valid(data) {
		return Error(api.CodeInvalid, "invalid secret request size or encoding")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := tokens(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return Error(api.CodeInvalid, "trailing secret request data")
	}
	t := reflect.TypeOf(target)
	if t == nil || t.Kind() != reflect.Pointer || t.Elem().Kind() != reflect.Struct {
		return Error(api.CodeIntegrity, "invalid secret decoder target")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		return Error(api.CodeInvalid, "secret request must be an object")
	}
	if err := required(data, t.Elem()); err != nil {
		return err
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return Error(api.CodeInvalid, "invalid secret request shape")
	}
	return nil
}

func tokens(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return Error(api.CodeInvalid, "secret request nesting exceeds its bound")
	}
	token, err := decoder.Token()
	if err != nil || token == nil {
		return Error(api.CodeInvalid, "invalid or null secret request data")
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]bool)
		for decoder.More() {
			key, err := decoder.Token()
			name, valid := key.(string)
			if err != nil || !valid || seen[name] {
				return Error(api.CodeInvalid, "duplicate or invalid secret request key")
			}
			seen[name] = true
			if err := tokens(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := tokens(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return Error(api.CodeInvalid, "invalid secret request delimiter")
	}
	if _, err := decoder.Token(); err != nil {
		return Error(api.CodeInvalid, "incomplete secret request")
	}
	return nil
}

func required(data []byte, t reflect.Type) error {
	if t.Kind() == reflect.Pointer {
		return required(data, t.Elem())
	}
	switch t.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
			return Error(api.CodeInvalid, "secret object has invalid fields")
		}
		// encoding/json matches struct fields without regard to case. The
		// frozen wire grammar requires exact keys, including at nested levels.
		known := make(map[string]bool)
		for i := 0; i < t.NumField(); i++ {
			name := strings.Split(t.Field(i).Tag.Get("json"), ",")[0]
			if name != "" && name != "-" {
				known[name] = true
			}
		}
		for name := range fields {
			if !known[name] {
				return Error(api.CodeInvalid, "unknown secret request field")
			}
		}
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			parts := strings.Split(field.Tag.Get("json"), ",")
			if parts[0] == "-" || parts[0] == "" {
				continue
			}
			raw, ok := fields[parts[0]]
			if !ok {
				if len(parts) > 1 && parts[1] == "omitempty" {
					continue
				}
				return Error(api.CodeInvalid, "missing secret request field")
			}
			if err := required(raw, field.Type); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			return nil // encoding/json validates base64 for []byte.
		}
		var entries []json.RawMessage
		if err := json.Unmarshal(data, &entries); err != nil || entries == nil {
			return Error(api.CodeInvalid, "secret result requires an array")
		}
		for _, raw := range entries {
			if err := required(raw, t.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}

func Nil(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}
