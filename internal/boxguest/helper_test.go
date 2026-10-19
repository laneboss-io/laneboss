package boxguest

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/boxcore"
)

const testNow int64 = 2000000000

type guardHarness struct {
	t        *testing.T
	root     string
	bin      string
	guard    string
	run      string
	load     string
	shutdown string
	calls    string
	log      string
	spec     boxcore.GuestSpec
	env      map[string]string
}

func newGuard(t *testing.T, spec boxcore.GuestSpec) *guardHarness {
	t.Helper()
	root := t.TempDir()
	if spec.OutDir == "" {
		spec.OutDir = filepath.Join(root, "out")
	}
	if len(spec.DoneFiles) == 0 {
		spec.DoneFiles = []string{filepath.Join(root, "done")}
	}
	if len(spec.BusyFiles) == 0 {
		spec.BusyFiles = []string{filepath.Join(root, "busy")}
	}
	h := &guardHarness{
		t: t, root: root, bin: filepath.Join(root, "bin"),
		guard: filepath.Join(root, "guard"),
		run:   filepath.Join(root, "run"), load: filepath.Join(root, "load"),
		shutdown: filepath.Join(root, "shutdown.log"),
		calls:    filepath.Join(root, "curl"), log: filepath.Join(root, "logger.log"),
		spec: spec, env: make(map[string]string),
	}
	for _, path := range []string{h.bin, h.run, h.calls, spec.OutDir} {
		if err := os.MkdirAll(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	h.write(h.guard, GuardScript(spec), 0755)
	h.write(h.load, "0.00 0.00 0.00 1/1 1\n", 0644)
	h.fake("shutdown", `printf '%s\n' "$*" >> "$FAKE_SHUTDOWN_LOG"
`)
	h.fake("logger", `printf '%s\n' "$*" >> "$FAKE_LOGGER_LOG"
`)
	h.fake("docker", `if [ "$*" != 'ps -q' ]; then exit 64; fi
printf '%s' "${FAKE_DOCKER_ID:-}"
`)
	h.fake("curl", fakeCurl)
	touch, err := exec.LookPath("touch")
	if err != nil {
		t.Fatal(err)
	}
	touch, err = filepath.Abs(touch)
	if err != nil {
		t.Fatal(err)
	}
	// Marker creation uses the guard's fixed clock.
	h.fake("touch", `stamp=$LB_GUARD_NOW
if [ -f "$FAKE_TOUCH_CLOCK" ]; then
    stamp=$(cat "$FAKE_TOUCH_CLOCK")
fi
exec `+testQuote(touch)+" -d \"@$stamp\" \"$@\"\n")
	h.fake("date", `case "$*" in
    '-u +%Y-%m-%dT%H:%M:%SZ') printf '%s\n' '2033-05-18T03:33:20Z' ;;
    '+%s') printf '%s\n' "$LB_GUARD_NOW" ;;
    *) exit 64 ;;
esac
`)
	return h
}

func testQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func (h *guardHarness) write(path, body string, mode os.FileMode) {
	h.t.Helper()
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		h.t.Fatal(err)
	}
}

func (h *guardHarness) fake(name, body string) {
	h.t.Helper()
	h.write(filepath.Join(h.bin, name), "#!/bin/bash\nset -u\n"+body, 0755)
}

func (h *guardHarness) execute(now int64, mode string, wantCode int) string {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	args := []string{h.guard}
	if mode != "" {
		args = append(args, mode)
	}
	cmd := exec.CommandContext(ctx, "bash", args...)
	// A small explicit environment keeps credentials and host tools out.
	cmd.Env = []string{
		"PATH=" + h.bin + ":/usr/bin:/bin",
		"LC_ALL=C", "TZ=UTC",
		"LB_GUARD_RUN_DIR=" + h.run, "LB_GUARD_LOADAVG=" + h.load,
		"LB_GUARD_SHUTDOWN=" + filepath.Join(h.bin, "shutdown"),
		"LB_GUARD_NOW=" + strconv.FormatInt(now, 10),
		"FAKE_SHUTDOWN_LOG=" + h.shutdown, "FAKE_LOGGER_LOG=" + h.log,
		"FAKE_CURL_DIR=" + h.calls,
		"FAKE_TOUCH_CLOCK=" + filepath.Join(h.root, "touch-clock"),
	}
	keys := make([]string, 0, len(h.env))
	for key := range h.env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		cmd.Env = append(cmd.Env, key+"="+h.env[key])
	}
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		h.t.Fatalf("guard exceeded its test deadline: %v\n%s", ctx.Err(), output)
	}
	code := 0
	if err != nil {
		exit, ok := err.(*exec.ExitError)
		if !ok {
			h.t.Fatalf("cannot execute guard: %v", err)
		}
		code = exit.ExitCode()
	}
	if code != wantCode {
		h.t.Fatalf("guard exit %d, want %d: %v\n%s", code, wantCode, err, output)
	}
	return string(output)
}

func (h *guardHarness) setTime(path string, seconds int64) {
	h.t.Helper()
	at := time.Unix(seconds, 0)
	if err := os.Chtimes(path, at, at); err != nil {
		h.t.Fatal(err)
	}
}

func (h *guardHarness) out(name, body string, seconds int64) string {
	h.t.Helper()
	path := filepath.Join(h.spec.OutDir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		h.t.Fatal(err)
	}
	h.write(path, body, 0644)
	h.setTime(path, seconds)
	return path
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func absent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("want missing %s, got %v", path, err)
	}
}

func (h *guardHarness) shutdowns(want int) {
	h.t.Helper()
	body, err := os.ReadFile(h.shutdown)
	if os.IsNotExist(err) && want == 0 {
		return
	}
	if err != nil {
		h.t.Fatal(err)
	}
	if string(body) != strings.Repeat("-h now\n", want) {
		h.t.Fatalf("shutdown arguments %q, want %d calls of -h now", body, want)
	}
}

type curlCall struct {
	args []string
	body string
	url  string
}

func (h *guardHarness) curlCalls() []curlCall {
	h.t.Helper()
	count := 0
	if body, err := os.ReadFile(filepath.Join(h.calls, "count")); err == nil {
		var parseErr error
		count, parseErr = strconv.Atoi(strings.TrimSpace(string(body)))
		if parseErr != nil {
			h.t.Fatal(parseErr)
		}
	} else if !os.IsNotExist(err) {
		h.t.Fatal(err)
	}
	var calls []curlCall
	for i := 1; i <= count; i++ {
		record := filepath.Join(h.calls, strconv.Itoa(i))
		n, err := strconv.Atoi(strings.TrimSpace(readFile(h.t, filepath.Join(record, "argc"))))
		if err != nil {
			h.t.Fatal(err)
		}
		call := curlCall{}
		for j := 1; j <= n; j++ {
			arg := readFile(h.t, filepath.Join(record, "arg-"+strconv.Itoa(j)))
			call.args = append(call.args, arg)
			if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
				call.url = arg
			}
		}
		if body, err := os.ReadFile(filepath.Join(record, "body")); err == nil {
			call.body = string(body)
		} else if !os.IsNotExist(err) {
			h.t.Fatal(err)
		}
		calls = append(calls, call)
	}
	return calls
}

func (h *guardHarness) uploadsSince(start int) []curlCall {
	h.t.Helper()
	all := h.curlCalls()
	if start > len(all) {
		h.t.Fatal("curl log shrank")
	}
	var uploads []curlCall
	for _, call := range all[start:] {
		if strings.HasPrefix(call.url, "https://storage.googleapis.com/") {
			uploads = append(uploads, call)
		}
	}
	return uploads
}

func hasArg(args []string, value string) bool {
	for _, arg := range args {
		if arg == value {
			return true
		}
	}
	return false
}

func hasPair(args []string, flag, value string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == value {
			return true
		}
	}
	return false
}

func checkUpload(t *testing.T, call curlCall, bucket, object, path, body string) {
	t.Helper()
	want := "https://storage.googleapis.com/" +
		"upload/storage/v1/b/" + bucket + "/o?uploadType=media&name=" +
		strings.ReplaceAll(object, "/", "%2F")
	if call.url != want || call.body != body {
		t.Fatalf("upload URL/body %q/%q, want %q/%q", call.url, call.body, want, body)
	}
	checkRequest(t, call, path)
}

func checkRequest(t *testing.T, call curlCall, path string) {
	t.Helper()
	for _, pair := range [][2]string{
		{"--max-time", "20"}, {"-X", "POST"},
		{"-H", "Authorization: Bearer sprout-token"},
		{"-H", "Content-Type: application/octet-stream"},
		{"--data-binary", "@" + path},
	} {
		if !hasPair(call.args, pair[0], pair[1]) {
			t.Fatalf("missing curl pair %q in %q", pair, call.args)
		}
	}
	if !hasArg(call.args, "-fsS") {
		t.Fatalf("missing curl failure reporting in %q", call.args)
	}
}

const fakeCurl = `count=0
if [ -f "$FAKE_CURL_DIR/count" ]; then
    count=$(cat "$FAKE_CURL_DIR/count")
fi
count=$((count + 1))
printf '%s\n' "$count" > "$FAKE_CURL_DIR/count"
record="$FAKE_CURL_DIR/$count"
mkdir -p "$record" || exit 1
printf '%s\n' "$#" > "$record/argc"
printf '%s\n' "$@" > "$record/args"
index=0
for arg in "$@"; do
    index=$((index + 1))
    printf '%s' "$arg" > "$record/arg-$index"
done
url=''
data=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        --max-time|-H|-X) shift ;;
        --data-binary) shift; data=${1:-} ;;
        -fsS) ;;
        http://*|https://*) url=$1 ;;
        *) exit 64 ;;
    esac
    shift
done
case "$url" in
    */token)
        case "${FAKE_TOKEN_MODE:-ok}" in
            fail) exit 22 ;;
            empty) printf '%s\n' '{"access_token":""}'; exit 0 ;;
            missing) printf '%s\n' '{"other":"value"}'; exit 0 ;;
            ok) printf '%s\n' '{"access_token":"sprout-token"}'; exit 0 ;;
            *) exit 64 ;;
        esac
        ;;
    */preempted)
        if [ "${FAKE_PREEMPT_FAIL:-0}" -eq 1 ]; then exit 22; fi
        printf '%s\n' "${FAKE_PREEMPT_VALUE:-TRUE}"
        exit 0
        ;;
    https://storage.googleapis.com/*)
        case "$data" in
            @*) cat -- "${data#@}" > "$record/body" || exit 1 ;;
            *) printf '%s' "$data" > "$record/body" ;;
        esac
        if [ -n "${FAKE_CHANGE_FILE:-}" ]; then
            LB_GUARD_NOW=$((LB_GUARD_NOW + 1)) touch "$FAKE_CHANGE_FILE" || exit 1
            printf '%s\n' "$((LB_GUARD_NOW + 2))" > "$FAKE_TOUCH_CLOCK"
        fi
        if [ -n "${FAKE_FAIL_OBJECT:-}" ]; then
            case "$url" in
                *"name=$FAKE_FAIL_OBJECT") exit 22 ;;
            esac
        fi
        exit 0
        ;;
    *) exit 64 ;;
esac
`

func markerTime(t *testing.T, path string) time.Time {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.ModTime()
}

func idleSince(h *guardHarness, want int64) {
	h.t.Helper()
	value := readFile(h.t, filepath.Join(h.run, "idle-since"))
	if value != fmt.Sprintf("%d\n", want) {
		h.t.Fatalf("idle-since %q, want %d", value, want)
	}
}
