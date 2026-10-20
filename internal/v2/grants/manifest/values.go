package manifest

import (
	"path"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/v2/api"
)

var configName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

func Config(value string) bool { return configName.MatchString(value) }

func ValidID(id api.ID) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for _, c := range id {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func ValidDigest(value api.Digest) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Selection strings include vendor names such as machine families with dots
// and fully qualified image names. They are exact data values, never patterns.
func selection(value string) bool {
	if value == "" || len(value) > 1024 || !utf8.ValidString(value) || strings.ContainsAny(value, "*?\\[]") {
		return false
	}
	for _, c := range value {
		if c < 33 || c == 127 {
			return false
		}
	}
	return true
}

func Time(value api.Timestamp) (time.Time, error) {
	if !strings.HasSuffix(string(value), "Z") {
		return time.Time{}, Invalid("timestamp must use UTC Z")
	}
	parsed, err := time.Parse(time.RFC3339Nano, string(value))
	if err != nil || parsed.Format(time.RFC3339Nano) != string(value) {
		return time.Time{}, Invalid("timestamp must be canonical RFC3339Nano")
	}
	return parsed, nil
}

func Expiry(value api.Timestamp, now time.Time) (time.Time, error) {
	parsed, err := Time(value)
	if err != nil {
		return time.Time{}, err
	}
	if !parsed.After(now) {
		return time.Time{}, &api.Error{Code: api.CodeForbidden,
			Message: "grant has expired", Instead: "Obtain a current explicit grant.",
			Owner: "lb-v2-grants"}
	}
	return parsed, nil
}

// Relative accepts a single unambiguous spelling; it never repairs traversal.
func Relative(value string) error {
	return relativeName(value, false)
}

// ArchivePath preserves Git administration names as inert retained data.
// Consumers must apply their own Git materialization policy before writing.
func ArchivePath(value string) error {
	return relativeName(value, true)
}

func relativeName(value string, archived bool) error {
	if value == "" || len(value) > 4096 || !utf8.ValidString(value) ||
		strings.HasPrefix(value, "/") || path.Clean(value) != value ||
		strings.ContainsAny(value, "\\\x00\r\n") {
		return Invalid("path must be an unambiguous beneath-root relative path")
	}
	for _, component := range strings.Split(value, "/") {
		if component == ".." || component == "" || !archived && strings.EqualFold(component, ".git") {
			return Invalid("path contains traversal or Git administration")
		}
		for _, c := range component {
			if c < 32 || c == 127 {
				return Invalid("path contains control characters")
			}
		}
	}
	return nil
}

func Beneath(root, candidate string) bool {
	return root == "." || candidate == root || strings.HasPrefix(candidate, root+"/")
}

func Destination(value string) error {
	parts := strings.Split(value, "/")
	if len(parts) != 3 || parts[0] != "" ||
		(parts[1] != "work" && parts[1] != "data") || !ValidID(api.ID(parts[2])) {
		return Invalid("destination must be /work/ID or /data/ID")
	}
	return nil
}

func Blob(ref api.BlobRef) error {
	if !ValidID(ref.ID) || !ValidDigest(ref.SHA256) || ref.Bytes < 0 ||
		ref.Bytes > api.MaxObjectBytes {
		return Invalid("invalid bounded object reference")
	}
	switch ref.Class {
	case "task", "prompt", "report", "artifact", "capture", "transcript", "policy",
		"manifest", "judge_request", "judge_raw", "archive", "record", "launch_request", "launch_spec",
		"diff", "check", "message", "channel_input", "channel_payload", "channel_receipt":
		return nil
	case "materialize_input", "archive_input", "worker_result":
		return nil
	default:
		return Invalid("unknown object class")
	}
}

func Budget(value api.Budget) error {
	if value.WallMS <= 0 || uint64(value.WallMS) > MaxInteger ||
		value.CPUSeconds > MaxInteger ||
		value.MemoryBytes == 0 || value.MemoryBytes > MaxInteger ||
		value.Processes == 0 || value.DiskBytes == 0 || value.DiskBytes > MaxInteger ||
		value.SpendMicros < 0 || uint64(value.SpendMicros) > MaxInteger ||
		len(value.Currency) != 3 {
		return Invalid("budget needs finite ceilings and positive wall, memory, process and disk limits")
	}
	for _, c := range value.Currency {
		if c < 'A' || c > 'Z' {
			return Invalid("budget currency must use three uppercase letters")
		}
	}
	return nil
}

// SecretTarget is a blacklist of authority-bearing process controls. It is
// independent of the environment and does not restrict ordinary commands.
func SecretTarget(delivery, target string) error {
	if delivery == "file" {
		if err := Relative(target); err != nil {
			return err
		}
		if target == "." {
			return Invalid("secret file needs a relative filename")
		}
		return nil
	}
	if delivery != "env" || target == "" || len(target) > 128 {
		return Invalid("secret delivery must be env or file with an explicit target")
	}
	for i, c := range target {
		if !(c >= 'A' && c <= 'Z') && !(c >= 'a' && c <= 'z') && c != '_' &&
			!(i > 0 && c >= '0' && c <= '9') {
			return Invalid("invalid secret environment target")
		}
	}
	upper := strings.ToUpper(target)
	for _, prefix := range []string{"LD_", "DYLD_", "LANEBOSS_", "CLAUDE", "CLAUDOCK", "CODEX", "XDG_", "GIT_"} {
		if strings.HasPrefix(upper, prefix) {
			return Invalid("secret target is a reserved process control")
		}
	}
	switch upper {
	case "HOME", "PATH", "TMPDIR", "TMP", "TEMP", "USER", "LOGNAME", "SHELL",
		"PWD", "OLDPWD", "CDPATH", "IFS", "ENV", "BASH_ENV", "BASHOPTS", "SHELLOPTS",
		"PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONUSERBASE", "NODE_OPTIONS",
		"NODE_PATH", "RUBYOPT", "RUBYLIB", "PERL5OPT", "PERL5LIB", "ZDOTDIR",
		"GCONV_PATH", "LOCPATH", "GLIBC_TUNABLES", "PROMPT_COMMAND", "PS4",
		"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL",
		"OPENAI_API_KEY", "OPENAI_BASE_URL", "OPENAI_ORG_ID", "OPENAI_PROJECT_ID",
		"SSH_AUTH_SOCK", "DBUS_SESSION_BUS_ADDRESS", "DBUS_SYSTEM_BUS_ADDRESS", "TMUX":
		return Invalid("secret target is a reserved process control")
	}
	return nil
}
