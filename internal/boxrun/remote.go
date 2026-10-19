package boxrun

import (
	"errors"
	"fmt"
	"path"
	"strings"

	"laneboss.io/laneboss/internal/boxcore"
)

const (
	remoteSource  = "/tmp/lb-box-src.tar"
	remoteSuite   = "/tmp/lb-box-suite.sh"
	remoteWrapper = "/tmp/lb-box-wrapper.sh"
)

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func remotePath(value string) error {
	if !path.IsAbs(value) || strings.HasPrefix(value, "-") ||
		strings.ContainsAny(value, "\x00\n\r") {
		return fmt.Errorf("boxrun: invalid remote path %q", value)
	}
	return nil
}

func validateGuest(cfg boxcore.GuestConfig) error {
	if len(cfg.DoneFiles) == 0 || len(cfg.BusyFiles) == 0 {
		return errors.New("boxrun: done and busy files are required")
	}
	if err := remotePath(cfg.OutDir); err != nil {
		return err
	}
	for _, files := range [][]string{cfg.DoneFiles, cfg.BusyFiles} {
		for _, file := range files {
			if err := remotePath(file); err != nil {
				return err
			}
		}
	}
	return nil
}

func doneCommand(files []string) (string, error) {
	if len(files) == 0 {
		return "", errors.New("boxrun: no done marker configured")
	}
	var commands []string
	for _, file := range files {
		if err := remotePath(file); err != nil {
			return "", err
		}
		commands = append(commands, "mkdir -p "+shellQuote(path.Dir(file))+" && touch "+shellQuote(file))
	}
	return strings.Join(commands, " && "), nil
}

func uploadCommand(remote string) (string, error) {
	if err := remotePath(remote); err != nil {
		return "", err
	}
	quoted := shellQuote(remote)
	return "mkdir -p \"$(dirname " + quoted + ")\" && cat > " + quoted, nil
}

func readyCommand() string {
	return "true"
}

func startCommand(out string) string {
	return "mkdir -p " + shellQuote(out) + " && { setsid bash " + shellQuote(remoteWrapper) +
		" < /dev/null > /dev/null 2>&1 & printf '%s\\n' started; }"
}

func pollCommand(out string) string {
	return "if [ -f " + shellQuote(path.Join(out, ".complete")) + " ]; then cat " +
		shellQuote(path.Join(out, "suite.exit")) + " 2>/dev/null || echo -1; else echo running; fi"
}

func killCommand(out string) string {
	body := "pid=$(cat " + shellQuote(path.Join(out, ".wrapper.pid")) + ") || exit 2\n" +
		"case \"$pid\" in ''|*[!0-9]*) exit 2;; esac\n" +
		"[ \"$pid\" -gt 1 ] || exit 2\nkill -TERM -- -\"$pid\""
	// Bash's kill supports -- consistently, unlike some /bin/sh builtins.
	return "bash -c " + shellQuote(body)
}

func harvestCommand(out string) string {
	return "tar -C " + shellQuote(out) + " -cf - ."
}

func suiteScript(suite string, source bool) string {
	text := "#!/bin/bash\n"
	if source {
		// The brief explicitly permits this fallback for an archive without src.
		text += "cd \"$HOME/src\" 2>/dev/null || true\n"
	}
	return text + suite + "\n"
}

func wrapperScript(cfg boxcore.GuestConfig, runID string) (string, error) {
	if err := validateGuest(cfg); err != nil {
		return "", err
	}
	return "#!/bin/bash\nset -u\nset -o pipefail\nexport LC_ALL=C\nOUT=" + shellQuote(cfg.OutDir) +
		"\nBUSY=" + shellQuote(cfg.BusyFiles[0]) + "\n" + `mkdir -p "$OUT" || exit 98
printf '%s\n' "$$" > "$OUT/.wrapper.pid" || exit 98
: > "$OUT/suite.log" || exit 98
rc=143
finished=0
wrapper_pid=$$
heartbeat=
stop_heartbeat() {
    if [ -n "$heartbeat" ]; then
        if kill -0 "$heartbeat" 2>/dev/null; then
            if ! kill -TERM "$heartbeat" 2>/dev/null; then
                printf '%s\n' 'heartbeat stop failed' >&2
            fi
        fi
        if wait "$heartbeat"; then :; else
            printf '%s\n' 'heartbeat stopped' >&2
        fi
    fi
}
finish() {
    if [ "$finished" -eq 1 ]; then return; fi
    finished=1
    if [ ! -f "$OUT/suite.exit" ]; then
        printf '%s\n' "$rc" > "$OUT/suite.exit" || { stop_heartbeat; return 98; }
    fi
    if ! (
        cd "$OUT" &&
        find . -type f ! -path './manifest.sha256' ! -path './.complete' -print0 |
        sort -z | xargs -0 -r sha256sum -- > manifest.sha256
    ); then
        printf '%s\n' 'manifest failed' >&2
        stop_heartbeat
        return 98
    fi
    touch "$OUT/.complete" || { stop_heartbeat; return 98; }
    stop_heartbeat
}
on_signal() {
    rc=143
    finish
    exit "$rc"
}
trap on_signal TERM INT HUP
(
    beat_sleep=
    beat_stop() {
        if [ -n "$beat_sleep" ]; then
            if kill -0 "$beat_sleep" 2>/dev/null; then
                if ! kill -TERM "$beat_sleep" 2>/dev/null; then
                    printf '%s\n' 'heartbeat timer stop failed' >&2
                fi
            fi
            if wait "$beat_sleep"; then :; else
                beat_rc=$?
                case "$beat_rc" in
                    129|130|143) :;;
                    *) printf 'heartbeat timer exit %s\n' "$beat_rc" >&2; exit 98;;
                esac
            fi
        fi
        exit 0
    }
    trap beat_stop TERM INT HUP
    mkdir -p "$(dirname "$BUSY")" || exit 98
    while kill -0 "$wrapper_pid" 2>/dev/null; do
        touch "$BUSY" || exit 98
        sleep 60 &
        beat_sleep=$!
        wait "$beat_sleep"
    done
) &
heartbeat=$!
` + "if [ -f " + shellQuote(remoteSource) + " ]; then\n" +
		"    if ! { mkdir -p \"$HOME/src\" && tar -xf " + shellQuote(remoteSource) +
		" -C \"$HOME/src\"; }; then\n        rc=98\n        finish\n        exit 98\n    fi\nfi\n" +
		"export LB_BOX_OUT=\"$OUT\" LB_BOX_RUN_ID=" + shellQuote(runID) + "\n" +
		"bash " + shellQuote(remoteSuite) + ` >> "$OUT/suite.log" 2>&1
rc=$?
printf 'suite exit %s\n' "$rc" >> "$OUT/suite.log"
printf '%s\n' "$rc" > "$OUT/suite.exit" || { rc=98; finish; exit 98; }
finish
`, nil
}
