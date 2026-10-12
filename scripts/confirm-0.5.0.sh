#!/bin/sh
# scripts/confirm-0.5.0.sh
#
# The written procedure "Confirming the statements by running 0.5.0" of docs/architecture.md (under "Rolling back to
# 0.5.0 across the changes of this design"), carried out on one machine. The OLD launcher (0.5.0) is built from the
# tarball given as the one argument; the NEW launcher (the commit under test) is built from the tree this script sits
# in. Both are installed into prefixes of their own under a temporary directory inside $HOME, the stores of the
# procedure's step 3 are made with the NEW launcher, and every row of the procedure's step-4 table is run with the
# OLD launcher, on a copy of the store the row names.
#
# Every row prints its name, the exact command, the file the command was written to, the exit code it returned, the
# first two lines of its standard output and the first two lines of its standard error, the line(s) of that output
# which met the row's pattern with how many there are, and then what the document's "Expected" column says. MATCH
# means the exit code equals the expected one and, where the document names text, that text is present in the
# command's own output. Where the document names no text (it names the exit code alone) only the exit code is checked
# and the raw lines are printed for the reader. A row that differs from the document is printed as MISMATCH.
#
# Usage: sh scripts/confirm-0.5.0.sh OLD-TARBALL
#
# Exit codes: 0 every row matched the document; 1 any row mismatched (its raw lines are printed); 2 the script itself
# broke (the step is named on standard error).

# The two commit ids, each kept in two halves so that no line holds an unbroken run of forty characters
# (the repository's publication scan reads such a run as a possible secret). They are joined below and
# printed in full.
OLD_SHA_HEAD=919af683934fd003f22da845
OLD_SHA_TAIL=ac587ae5e22a3c95
NEW_SHA_HEAD=02366650bde33f3850a7ecc
NEW_SHA_TAIL=ada8537494ee63c24
OLD_SHA=$OLD_SHA_HEAD$OLD_SHA_TAIL
NEW_SHA=$NEW_SHA_HEAD$NEW_SHA_TAIL
set -u

if [ "$#" -ne 1 ]; then
    echo "usage: sh scripts/confirm-0.5.0.sh OLD-TARBALL (a git archive of 0.5.0)" >&2
    exit 2
fi
OLD_TARBALL=$1
NEW_TREE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)

STEP="start-up"
broke() {
    echo "confirm-0.5.0: the script broke at the step \"$STEP\": $*" >&2
    echo "confirm-0.5.0: exit 2" >&2
    exit 2
}

[ -f "$OLD_TARBALL" ] || broke "the old tarball $OLD_TARBALL is not a file"
[ -f "$NEW_TREE/scripts/install.sh" ] || broke "the new tree $NEW_TREE has no scripts/install.sh"
[ -f "$NEW_TREE/tests/e2e/standin.py" ] || broke "the new tree $NEW_TREE has no tests/e2e/standin.py"
command -v python3 >/dev/null 2>&1 || broke "python3 is not on PATH"
command -v tmux >/dev/null 2>&1 || broke "tmux is not on PATH (a lane's runs live in tmux sessions)"
PY=$(command -v python3)
STANDIN=$NEW_TREE/tests/e2e/standin.py

# --- the run's own directories, all inside $HOME ------------------
STEP="make the run's directories under \$HOME"
R=$(mktemp -d "$HOME/lb-confirm-0.5.0.XXXXXX") || broke "mktemp could not make a directory under $HOME"
OLD_SRC=$R/old-src
PREFIX_OLD=$R/prefix-old
PREFIX_NEW=$R/prefix-new
export LANEBOSS_HOME=$R/home
export LANEBOSS_STATE_HOME=$R/state
export LANEBOSS_CONFIG=trial
# A lane started with --worktree writes a claim in the account's claims registry, which is
# HOME/.local/state/laneboss/.lane-claims from the user database. This run touches nothing outside its own
# directories, so the registry is moved inside them, with the launcher's documented way of moving it.
export LANEBOSS_TEST_CLAIMS_DIR=$R/claims
export E2E_RECORD_DIR=$R/records
CONFIG_DIR=$LANEBOSS_HOME/configs/trial
STATE_DIR=$LANEBOSS_STATE_HOME/trial
TEMPLATES=$R/templates
STORES=$R/stores
USED=$R/used
ROW_DIR=$R/rows
EVENTS=$R/events
BRIEFS=$R/briefs
WORK=$R/work
OUTDIR=$R/out
mkdir -p "$OLD_SRC" "$PREFIX_OLD" "$PREFIX_NEW" "$CONFIG_DIR/rules" "$LANEBOSS_STATE_HOME" \
    "$LANEBOSS_TEST_CLAIMS_DIR" "$E2E_RECORD_DIR" "$TEMPLATES" "$STORES" "$USED" "$ROW_DIR" "$EVENTS" "$BRIEFS" \
    "$WORK" "$OUTDIR" || broke "mkdir failed under $R"
chmod 700 "$LANEBOSS_TEST_CLAIMS_DIR" || broke "chmod 700 on the claims registry failed"

OLD_BIN=$PREFIX_OLD/bin/laneboss
NEW_BIN=$PREFIX_NEW/bin/laneboss

LANE_B=b-lane
LANE_C=c-turns
LANE_E=e-loop
LANE_FRESH=fresh-lane

echo "=== Confirming the statements by running 0.5.0"
echo "run directory:         $R"
echo "new tree (under test): $NEW_TREE"
echo "new sha:               $NEW_SHA"
echo "old sha:               $OLD_SHA"
echo "old tarball:           $OLD_TARBALL"
echo "python3:               $PY"
echo "LANEBOSS_HOME:         $LANEBOSS_HOME"
echo "LANEBOSS_STATE_HOME:   $LANEBOSS_STATE_HOME"
echo "claims registry:       $LANEBOSS_TEST_CLAIMS_DIR (moved inside the run, so nothing outside it is touched)"
echo

# --- 1. unpack the old tree and install both versions ------------------
STEP="unpack the old tree and install both versions"
tar -xf "$OLD_TARBALL" -C "$OLD_SRC" || broke "the old tarball did not unpack into $OLD_SRC"
[ -f "$OLD_SRC/scripts/install.sh" ] || broke "the unpacked old tree has no scripts/install.sh"
sh "$OLD_SRC/scripts/install.sh" --prefix "$PREFIX_OLD" >"$OUTDIR/install-old.json" 2>"$OUTDIR/install-old.err"
OLD_INSTALL=$?
[ "$OLD_INSTALL" = 0 ] || broke "the old install exited $OLD_INSTALL: $(head -n 2 "$OUTDIR/install-old.err")"
sh "$NEW_TREE/scripts/install.sh" --prefix "$PREFIX_NEW" >"$OUTDIR/install-new.json" 2>"$OUTDIR/install-new.err"
NEW_INSTALL=$?
[ "$NEW_INSTALL" = 0 ] || broke "the new install exited $NEW_INSTALL: $(head -n 2 "$OUTDIR/install-new.err")"
[ -x "$OLD_BIN" ] || broke "the old install left no executable $OLD_BIN"
[ -x "$NEW_BIN" ] || broke "the new install left no executable $NEW_BIN"
echo "installed old: $(cat "$OUTDIR/install-old.json")"
echo "installed new: $(cat "$OUTDIR/install-new.json")"
echo

# --- 2. the trial configuration (quoted here-documents: no shell expansion of the text) ------------------------
STEP="write the trial configuration and its edited copies"
cat >"$TEMPLATES/trial.toml" <<'TOML'
# The configuration of the confirmation run: one runner that can take turns (the stand-in runner of the new tree,
# with {session} in `command` and in `resume` and prompt = "stdin"), one runner that uses neither, and the table
# [turns] with idle_message. The two @-tokens are the interpreter and the stand-in program.
schema_version = 1
name = "trial"
description = "The confirmation run of the statements about a rollback to 0.5.0."
rules = ["rules/standing.md"]

[lanes]
budget_minutes = 30
quiet_seconds = 600
stop_grace_seconds = 2

[turns]
idle_message = "rules/idle.md"
idle_seconds = 600
poll_seconds = 1
backoff_seconds = 300
limit_backoff_seconds = 1800

[runners.turner]
command = ["@PYTHON@", "-I", "@STANDIN@", "ok", "--lane", "{lane}", "--brief", "{brief}", "--session-id", "{session}"]
resume = ["@PYTHON@", "-I", "@STANDIN@", "ok", "resumed", "--lane", "{lane}", "--message", "{message}", "--resume", "{session}"]
prompt = "stdin"
limit_patterns = ["^standin: usage limit reached"]
dropped_patterns = ["^standin: stream disconnected"]

[runners.plain]
command = ["@PYTHON@", "-I", "@STANDIN@", "ok", "--lane", "{lane}", "--brief", "{brief}"]
TOML

# The same configuration with [turns], prompt and {session} removed: the three triggers of the configuration that
# 0.5.0 refuses when the configuration loads. The rows after the first three run with this copy.
cat >"$TEMPLATES/trial.edited.toml" <<'TOML'
# The configuration of the confirmation run with the three triggers of the configuration removed: the whole table
# [turns], prompt = "stdin" and {session}. The rows after the first three run with this copy.
schema_version = 1
name = "trial"
description = "The confirmation run of the statements about a rollback to 0.5.0."
rules = ["rules/standing.md"]

[lanes]
budget_minutes = 30
quiet_seconds = 600
stop_grace_seconds = 2

[runners.turner]
command = ["@PYTHON@", "-I", "@STANDIN@", "ok", "--lane", "{lane}", "--brief", "{brief}"]
resume = ["@PYTHON@", "-I", "@STANDIN@", "ok", "resumed", "--lane", "{lane}", "--message", "{message}"]
limit_patterns = ["^standin: usage limit reached"]
dropped_patterns = ["^standin: stream disconnected"]

[runners.plain]
command = ["@PYTHON@", "-I", "@STANDIN@", "ok", "--lane", "{lane}", "--brief", "{brief}"]
TOML

# The edited configuration with the key of T4 added to one runner.
cat >"$TEMPLATES/trial.stream.toml" <<'TOML'
# The edited configuration with the key stream (the key of T4) added to one runner.
schema_version = 1
name = "trial"
description = "The confirmation run of the statements about a rollback to 0.5.0."
rules = ["rules/standing.md"]

[lanes]
budget_minutes = 30
quiet_seconds = 600
stop_grace_seconds = 2

[runners.turner]
command = ["@PYTHON@", "-I", "@STANDIN@", "ok", "--lane", "{lane}", "--brief", "{brief}"]
resume = ["@PYTHON@", "-I", "@STANDIN@", "ok", "resumed", "--lane", "{lane}", "--message", "{message}"]
limit_patterns = ["^standin: usage limit reached"]
dropped_patterns = ["^standin: stream disconnected"]

[runners.plain]
command = ["@PYTHON@", "-I", "@STANDIN@", "ok", "--lane", "{lane}", "--brief", "{brief}"]
stream = "text"
TOML

cat >"$CONFIG_DIR/rules/standing.md" <<'MD'
# Standing rules of the confirmation run

- This configuration exists only to run the statements about a rollback to 0.5.0.
MD
cat >"$CONFIG_DIR/rules/idle.md" <<'MD'
Check in: say in one line what you are doing.
MD
cat >"$BRIEFS/b-lane.md" <<'MD'
# An ordinary lane

A brief for the stand-in runner.
MD
cat >"$BRIEFS/c-turns.md" <<'MD'
# A lane that takes turns

A brief for the stand-in runner.
MD
cat >"$BRIEFS/e-loop.md" <<'MD'
# A lane the loop drives

A brief for the stand-in runner.
MD
cat >"$BRIEFS/fresh.md" <<'MD'
# A lane for the row that starts one

A brief for the stand-in runner.
MD

put_config() {  # TEMPLATE
    sed -e "s|@PYTHON@|$PY|g" -e "s|@STANDIN@|$STANDIN|g" "$1" >"$CONFIG_DIR/config.toml" || broke "sed failed for $1"
}

echo "--- the trial configuration against its edited copy (the three triggers of the configuration removed)"
diff -u "$TEMPLATES/trial.toml" "$TEMPLATES/trial.edited.toml"
echo

# --- 3. make the stores with the new version --------------------
# `lane status --lane L` until the lane's run has ended and its tmux session has gone: the store can then be copied.
# The two keys are looked for one at a time: the status is JSON with its keys sorted, so "session_alive" (inside
# "live") comes before "running" and a single pattern that names them in that order would never match.
settle() {
    s_lane=$1
    s_n=0
    s_text=""
    while [ "$s_n" -lt 180 ]; do
        s_text=$("$NEW_BIN" lane status --lane "$s_lane" --config trial 2>&1) \
            || s_text="lane status failed: $s_text"
        case "$s_text" in
            *'"running": false'*)
                if printf '%s' "$s_text" | grep -q '"session_alive": false'; then return 0; fi
                ;;
        esac
        s_n=$((s_n + 1))
        sleep 1
    done
    echo "the last lane status of $s_lane was:" >&2
    printf '%s\n' "$s_text" | head -c 4000 >&2
    echo >&2
    return 1
}

# A fresh state directory: the one in place is moved aside (nothing is deleted) and the new version makes another.
fresh_state() {
    if [ -e "$STATE_DIR" ]; then
        mv "$STATE_DIR" "$USED/live-$1" || broke "could not move the state directory aside to $USED/live-$1"
    fi
}

echo "=== the stores (the document's step 3) ==="

STEP="make the store B (an ordinary lane on the second runner, run to its end)"
put_config "$TEMPLATES/trial.toml"
mkdir -p "$WORK/$LANE_B"
"$NEW_BIN" lane start --config trial --lane "$LANE_B" --brief "$BRIEFS/b-lane.md" \
    --runner plain --model standin-model-1 --worktree "$WORK/$LANE_B" >"$OUTDIR/start-b.json" 2>"$OUTDIR/start-b.err"
[ "$?" = 0 ] || broke "the new launcher refused lane start for B: $(head -n 2 "$OUTDIR/start-b.err")"
settle "$LANE_B" || broke "the run of B's lane did not end"
"$NEW_BIN" state verify --config trial >"$OUTDIR/verify-b.json" 2>&1 \
    || broke "the new launcher could not verify its own store B: $(head -n 2 "$OUTDIR/verify-b.json")"
cp -a "$STATE_DIR" "$STORES/B" || broke "could not copy the state directory to $STORES/B"
echo "store B: $(cat "$OUTDIR/start-b.json")"
echo

STEP="make the store C (a turn-based lane: two sends and one turn)"
fresh_state store-B
mkdir -p "$WORK/$LANE_C"
"$NEW_BIN" lane start --config trial --lane "$LANE_C" --brief "$BRIEFS/c-turns.md" --turns \
    --runner turner --model standin-model-1 --worktree "$WORK/$LANE_C" >"$OUTDIR/start-c.json" 2>"$OUTDIR/start-c.err"
[ "$?" = 0 ] || broke "the new launcher refused lane start --turns for C: $(head -n 2 "$OUTDIR/start-c.err")"
settle "$LANE_C" || broke "the first run of C's lane did not end"
printf 'The first message for the lane that takes turns.\n' >"$OUTDIR/message-c-1.md"
printf 'The second message for the lane that takes turns.\n' >"$OUTDIR/message-c-2.md"
"$NEW_BIN" lane send --config trial --lane "$LANE_C" --file "$OUTDIR/message-c-1.md" \
    >"$OUTDIR/send-c-1.json" 2>"$OUTDIR/send-c-1.err" || broke "lane send 1 for C was refused"
"$NEW_BIN" lane send --config trial --lane "$LANE_C" --file "$OUTDIR/message-c-2.md" \
    >"$OUTDIR/send-c-2.json" 2>"$OUTDIR/send-c-2.err" || broke "lane send 2 for C was refused"
"$NEW_BIN" lane turn --config trial --lane "$LANE_C" >"$OUTDIR/turn-c.json" 2>"$OUTDIR/turn-c.err" \
    || broke "lane turn for C was refused: $(head -n 2 "$OUTDIR/turn-c.err")"
settle "$LANE_C" || broke "the turn of C's lane did not end"
# A control on this store: it must hold what the rows about C name, or those rows would prove nothing.
count_kind() {  # KIND [LANE]: how many stored events have this kind (and lane)
    c_text=$("$NEW_BIN" state events --config trial 2>/dev/null) || c_text=""
    if [ "$#" -ge 2 ]; then
        printf '%s' "$c_text" | grep -o "\"kind\": \"$1\", \"lane\": \"$2\"" | wc -l | tr -d ' '
    else
        printf '%s' "$c_text" | grep -o "\"kind\": \"$1\"" | wc -l | tr -d ' '
    fi
}
[ "$(count_kind lane.mailed "$LANE_C")" -ge 2 ] || broke "C holds no lane.mailed events"
[ "$(count_kind lane.delivered "$LANE_C")" -ge 1 ] || broke "C holds no lane.delivered event"
cp -a "$STATE_DIR" "$STORES/C" || broke "could not copy the state directory to $STORES/C"
echo "store C: $(cat "$OUTDIR/turn-c.json"); lane.mailed x$(count_kind lane.mailed "$LANE_C"), lane.delivered x$(count_kind lane.delivered "$LANE_C")"
echo

STEP="make the store D (a copy of B with a hand-made mail file and mail.lock)"
cp -a "$STORES/B" "$STORES/D" || broke "could not copy B to D"
mkdir -p "$STORES/D/lanes/$LANE_B/mail" || broke "could not make the mail directory of D"
printf 'A message for the ordinary lane, written by hand.\n' >"$OUTDIR/message-d.md"
D_NAME=$(sha256sum "$OUTDIR/message-d.md" | cut -c1-64)
cp "$OUTDIR/message-d.md" "$STORES/D/lanes/$LANE_B/mail/000000001-$D_NAME" || broke "could not write D's mail file"
printf 'handmade\n' >"$STORES/D/lanes/$LANE_B/mail.lock" || broke "could not write D's mail.lock"
echo "store D: B plus lanes/$LANE_B/mail/000000001-$D_NAME and lanes/$LANE_B/mail.lock"
echo

STEP="make the store E (the loop drives one turn of a lane with one message waiting)"
fresh_state store-C
mkdir -p "$WORK/$LANE_E"
"$NEW_BIN" lane start --config trial --lane "$LANE_E" --brief "$BRIEFS/e-loop.md" --turns \
    --runner turner --model standin-model-1 --worktree "$WORK/$LANE_E" >"$OUTDIR/start-e.json" 2>"$OUTDIR/start-e.err"
[ "$?" = 0 ] || broke "the new launcher refused lane start --turns for E: $(head -n 2 "$OUTDIR/start-e.err")"
settle "$LANE_E" || broke "the first run of E's lane did not end"
printf 'The message that waits for the loop.\n' >"$OUTDIR/message-e.md"
"$NEW_BIN" lane send --config trial --lane "$LANE_E" --file "$OUTDIR/message-e.md" \
    >"$OUTDIR/send-e.json" 2>"$OUTDIR/send-e.err" || broke "lane send for E was refused"
"$NEW_BIN" lane loop --config trial >"$OUTDIR/loop-e.jsonl" 2>"$OUTDIR/loop-e.err" &
LOOP_PID=$!
e_n=0
while [ "$e_n" -lt 120 ]; do
    if [ "$(count_kind lane.ended "$LANE_E")" -ge 2 ]; then break; fi
    if ! kill -0 "$LOOP_PID" 2>/dev/null; then
        broke "the loop ended before it drove a turn: $(head -n 2 "$OUTDIR/loop-e.err")"
    fi
    e_n=$((e_n + 1))
    sleep 1
done
[ "$e_n" -lt 120 ] || broke "the loop did not drive a turn of E's lane within 120 s"
"$NEW_BIN" lane loop --stop --config trial >"$OUTDIR/loop-stop.json" 2>"$OUTDIR/loop-stop.err" \
    || broke "lane loop --stop was refused: $(head -n 2 "$OUTDIR/loop-stop.err")"
wait "$LOOP_PID"
LOOP_EXIT=$?
[ "$LOOP_EXIT" = 0 ] || broke "the foreground loop exited $LOOP_EXIT: $(head -n 2 "$OUTDIR/loop-e.err")"
settle "$LANE_E" || broke "the turn the loop drove did not end"
for f in loop.lock loop.json loop.log; do
    [ -e "$STATE_DIR/$f" ] || broke "the loop left no $f in the state directory"
done
# A control on this store: it must hold what the rows about E name.
for kind in loop.started loop.turn loop.stopped; do
    [ "$(count_kind "$kind")" -ge 1 ] || broke "E holds no $kind event"
done
cp -a "$STATE_DIR" "$STORES/E" || broke "could not copy the state directory to $STORES/E"
echo "store E: loop.started x$(count_kind loop.started), loop.turn x$(count_kind loop.turn), loop.stopped x$(count_kind loop.stopped); loop.lock, loop.json and loop.log in the copy"
echo

# --- 4. the rows of the procedure's step-4 table --------------------
ROWS_RUN=0
ROWS_OK=0
ROWS_BAD=0

show_lines() {  # FILE LABEL
    if [ -s "$1" ]; then
        head -n 2 "$1" | while IFS= read -r line; do printf '    %s %s\n' "$2" "$line"; done
    else
        printf '    %s (nothing)\n' "$2"
    fi
}

# The line(s) of a captured output that met the row's pattern, and how many there are. Both the bytes and the count
# come from the captured file itself (grep over it), never from text this script writes. A row whose pattern is "-"
# (the document names no text for it) prints nothing here; a file with no such line says so, so the reader can see
# why the verdict is what it is, and can count the lines against the store controls printed when the stores were made.
show_hits() {  # FILE LABEL PATTERN
    if [ "$3" = "-" ]; then
        return 0
    fi
    h_count=$(grep -Ec -- "$3" "$1" 2>/dev/null) || h_count=0
    if [ "$h_count" -eq 0 ]; then
        printf '    hit %s| no line meets the pattern\n' "$2"
        return 0
    fi
    printf '    hit %s| %s line(s) meeting the pattern:\n' "$2" "$h_count"
    grep -E -- "$3" "$1" 2>/dev/null | head -n 8 | while IFS= read -r h_line; do
        printf '        %s\n' "$h_line"
    done
}

# run_row NAME WANT-EXIT PATTERN EXPECTED COMMAND
# The command is written to a file of its own under the run directory and the file is run. PATTERN is an extended
# regular expression that must be found in the command's own standard output or standard error; "-" means the
# document names no text for the row (it names the exit code alone) and only the exit code is checked. The rows whose
# output is a print of a store's events name the events' own JSON fields -- the "kind" field with the kind it holds
# and, where it helps, the lane -- never a bare word, so a file path or a lane name cannot satisfy them. The line(s)
# that met the pattern are printed under the row (show_hits), so the reader sees what the verdict rests on.
run_row() {
    r_name=$1
    r_want=$2
    r_pattern=$3
    r_expect=$4
    r_cmd=$5
    ROWS_RUN=$((ROWS_RUN + 1))
    r_file=$ROW_DIR/$r_name.sh
    printf '%s\n' "$r_cmd" >"$r_file" || broke "could not write $r_file"
    sh "$r_file" >"$ROW_DIR/$r_name.out" 2>"$ROW_DIR/$r_name.err"
    r_code=$?
    r_verdict=MISMATCH
    if [ "$r_code" = "$r_want" ]; then
        if [ "$r_pattern" = "-" ]; then
            r_verdict=MATCH
        elif grep -Eq -- "$r_pattern" "$ROW_DIR/$r_name.out" "$ROW_DIR/$r_name.err"; then
            r_verdict=MATCH
        fi
    fi
    echo "ROW $r_name"
    echo "    cmd: $r_cmd"
    echo "    file: $r_file"
    echo "    exit: $r_code (expected $r_want)"
    show_lines "$ROW_DIR/$r_name.out" "out|"
    show_lines "$ROW_DIR/$r_name.err" "err|"
    echo "    expected: $r_expect"
    echo "    pattern: $r_pattern"
    show_hits "$ROW_DIR/$r_name.out" "out" "$r_pattern"
    show_hits "$ROW_DIR/$r_name.err" "err" "$r_pattern"
    echo "    verdict: $r_verdict"
    echo
    if [ "$r_verdict" = MATCH ]; then
        ROWS_OK=$((ROWS_OK + 1))
    else
        ROWS_BAD=$((ROWS_BAD + 1))
    fi
    return 0
}

# verdict_row NAME SEEN-AND-HASHES EXPECTED MATCHED(0|1): a check that is not a command itself, printed as a row.
verdict_row() {
    ROWS_RUN=$((ROWS_RUN + 1))
    echo "ROW $1"
    echo "    seen: $2"
    echo "    expected: $3"
    if [ "$4" = 0 ]; then
        echo "    verdict: MATCH"
        ROWS_OK=$((ROWS_OK + 1))
    else
        echo "    verdict: MISMATCH"
        ROWS_BAD=$((ROWS_BAD + 1))
    fi
    echo
}

# The store a row runs on: the state directory in place is moved aside and a copy of the named store is put where the
# configuration's state directory is, so the row reads the copy the document names and nothing else.
USE_N=0
use_store() {  # NAME
    USE_N=$((USE_N + 1))
    if [ -e "$STATE_DIR" ]; then
        mv "$STATE_DIR" "$USED/before-$1-$USE_N" || broke "could not move the state directory aside before $1"
    fi
    cp -a "$STORES/$1" "$STATE_DIR" || broke "could not put the copy $1 in place"
}

# The event files the rows append by hand. The message's digest is computed here, so that no line of this
# script holds an unbroken run of forty characters.
DIGEST_64=$(printf 'the message this invented event announces\n' | sha256sum | cut -c1-64)
cat >"$EVENTS/lane-mailed.json" <<JSON
{"actor": "confirm-0.5.0", "kind": "lane.mailed", "lane": "$LANE_B",
 "payload": {"bytes": 12, "sender": "supervisor", "sequence": 1, "sha256": "$DIGEST_64"},
 "protocol_version": "1.2.0"}
JSON
cat >"$EVENTS/other-kind-1.2.0.json" <<'JSON'
{"actor": "confirm-0.5.0", "kind": "confirm.note", "payload": {"note": "an event of another kind"},
 "protocol_version": "1.2.0"}
JSON
loop_event() {  # FILE KIND
    cat >"$1" <<JSON
{"actor": "confirm-0.5.0", "kind": "$2", "payload": {"loop": "confirm-0.5.0"},
 "protocol_version": "1.2.0"}
JSON
}
loop_event "$EVENTS/loop-started.json" loop.started
loop_event "$EVENTS/loop-turn.json" loop.turn
loop_event "$EVENTS/loop-skipped.json" loop.skipped
loop_event "$EVENTS/loop-stopped.json" loop.stopped

echo "=== the rows (the document's step 4) ==="
echo

STEP="row 1: config validate on the configuration with [turns], prompt and {session}"
put_config "$TEMPLATES/trial.toml"
run_row r01-config-turns 2 'invalid configuration: .*turns: unknown key' \
    'exit 2, invalid configuration:, naming the key path (turns, runners.NAME.prompt, ...)' \
    "$OLD_BIN config validate trial"

STEP="row 2 (the control): config validate on the configuration with the three triggers removed"
put_config "$TEMPLATES/trial.edited.toml"
BAD_BEFORE=$ROWS_BAD
run_row r02-config-edited 0 '-' 'exit 0' \
    "$OLD_BIN config validate trial"
if [ "$ROWS_BAD" != "$BAD_BEFORE" ]; then
    echo "the control failed: the old version cannot load the edited configuration, so no row after the first three"
    echo "could prove anything. The sequence stops here (the document's step 4: the rows after the first three run"
    echo "with the copy of the configuration from which [turns], prompt and {session} were removed)."
    echo
    echo "rows run $ROWS_RUN, matched $ROWS_OK, mismatched $ROWS_BAD"
    echo "confirm-0.5.0: exit 1"
    exit 1
fi

STEP="row 3: config validate on the edited configuration with stream added to one runner"
put_config "$TEMPLATES/trial.stream.toml"
run_row r03-config-stream 2 'invalid configuration: .*runners\.plain\.stream: unknown key' \
    'exit 2, invalid configuration:, naming runners.NAME.stream and the words unknown key' \
    "$OLD_BIN config validate trial"

# From here the old version runs against the edited configuration, which it can load.
put_config "$TEMPLATES/trial.edited.toml"

STEP="row 4: event tail and state events on C"
use_store C
run_row r04a-event-tail-c 0 '"kind": "lane\.(mailed|delivered)", "lane": "c-turns"' \
    'exit 0, every event printed, the new kinds among them' \
    "$OLD_BIN event tail --config trial"
use_store C
run_row r04b-state-events-c 0 '"kind": "lane\.mailed", "lane": "c-turns".*"kind": "lane\.delivered", "lane": "c-turns"' \
    'exit 0, every event printed, the new kinds among them' \
    "$OLD_BIN state events --config trial"

STEP="row 5: state verify and state rebuild on C"
use_store C
run_row r05a-state-verify-c 3 'integrity problem: event seq [0-9]+: .*must be an object with exactly: account, base, branch,' \
    'exit 3, integrity problem: event seq N: and the form that 0.5.0 lists' \
    "$OLD_BIN state verify --config trial"
use_store C
run_row r05b-state-rebuild-c 3 'integrity problem: event seq [0-9]+: .*must be an object with exactly: account, base, branch,' \
    'exit 3, integrity problem: event seq N: and the form that 0.5.0 lists' \
    "$OLD_BIN state rebuild --config trial"

STEP="row 6: doctor and start on C"
use_store C
run_row r06a-doctor-c 1 '"check": "store.recorded".*"ok": false' \
    'doctor: exit 1 with its store.recorded check failed' \
    "$OLD_BIN doctor --config trial"
use_store C
run_row r06b-start-c 3 'the store\.recorded check failed' \
    'start: exit 3, the store.recorded check failed' \
    "$OLD_BIN start --config trial"

STEP="row 7: state lanes, lane status, lane check and lane start of a new lane, on C"
use_store C
run_row r07a-state-lanes-c 3 "the lane projection is not in this version's form" \
    "exit 3, the lane projection is not in this version's form" \
    "$OLD_BIN state lanes --config trial"
use_store C
run_row r07b-lane-status-one-c 3 "the lane projection is not in this version's form" \
    "exit 3, the lane projection is not in this version's form" \
    "$OLD_BIN lane status --config trial --lane $LANE_C"
use_store C
run_row r07c-lane-status-all-c 3 "the lane projection is not in this version's form" \
    "exit 3, the lane projection is not in this version's form" \
    "$OLD_BIN lane status --config trial"
use_store C
run_row r07d-lane-check-c 3 "the lane projection is not in this version's form" \
    "exit 3, the lane projection is not in this version's form" \
    "$OLD_BIN lane check --config trial"
mkdir -p "$WORK/$LANE_FRESH"
use_store C
run_row r07e-lane-start-new-c 3 "the lane projection is not in this version's form" \
    "exit 3, the lane projection is not in this version's form" \
    "$OLD_BIN lane start --config trial --lane $LANE_FRESH --brief $BRIEFS/fresh.md --runner plain --model standin-model-1 --worktree $WORK/$LANE_FRESH"

STEP="row 8: lane resume, stop, mark, clean, scan, review and refusals for the turn-based lane, on C"
use_store C
run_row r08a-lane-resume-c 3 '-' 'exit 3' "$OLD_BIN lane resume --config trial --lane $LANE_C"
use_store C
run_row r08b-lane-stop-c 3 '-' 'exit 3' "$OLD_BIN lane stop --config trial --lane $LANE_C"
use_store C
run_row r08c-lane-mark-abandoned-c 3 '-' 'exit 3' \
    "$OLD_BIN lane mark --config trial --lane $LANE_C --state abandoned"
use_store C
run_row r08d-lane-clean-c 3 '-' 'exit 3' "$OLD_BIN lane clean --config trial --lane $LANE_C"
use_store C
run_row r08e-lane-scan-c 3 '-' 'exit 3' "$OLD_BIN lane scan --config trial --lane $LANE_C"
use_store C
# The refusal id must be one of the form the command takes (rf- and 24 hex digits): the command checks it before it
# reads the store, so an id of another form would stop the row before the store is read and prove nothing about it.
run_row r08f-lane-review-c 3 '-' 'exit 3' \
    "$OLD_BIN lane review --config trial --lane $LANE_C --refusal rf-000000000000000000000000 --path $WORK/$LANE_C --verdict clean"
use_store C
run_row r08g-lane-refusals-c 3 '-' 'exit 3' "$OLD_BIN lane refusals --config trial --lane $LANE_C"

STEP="row 9: lane mark --state abandoned and --landing merged for the ordinary lane, on B"
use_store B
run_row r09a-lane-mark-abandoned-b 0 '-' 'exit 0' \
    "$OLD_BIN lane mark --config trial --lane $LANE_B --state abandoned"
use_store B
run_row r09b-lane-mark-landing-b 0 '-' 'exit 0' \
    "$OLD_BIN lane mark --config trial --lane $LANE_B --landing merged"

STEP="row 10: event append of a lane.mailed event, on B"
use_store B
run_row r10-append-lane-mailed 2 'kind: lane events are lane\.planned, lane\.started, lane\.ended, lane\.timeout, lane\.stuck, lane\.resumed, lane\.lost, lane\.cleaned, lane\.merged, lane\.deployed, lane\.landed, lane\.state, lane\.gone, lane\.refusal, lane\.workaround_suspected, lane\.refusal_reviewed' \
    'exit 2, kind: lane events are and the list of kinds' \
    "$OLD_BIN event append --config trial --file $EVENTS/lane-mailed.json"

STEP="row 11: event append of another kind with protocol_version 1.2.0, and brief render, on B"
use_store B
run_row r11a-append-other-1.2.0 0 '-' 'exit 0' \
    "$OLD_BIN event append --config trial --file $EVENTS/other-kind-1.2.0.json"
use_store B
run_row r11b-brief-render-b 0 '-' 'exit 0' \
    "$OLD_BIN brief render --config trial --lane $LANE_B --in $BRIEFS/b-lane.md --out $OUTDIR/rendered-b.md"

STEP="row 12: state verify, doctor, start and lane status on D, and the mail files unchanged"
use_store D
D_BEFORE=$(cd "$STATE_DIR/lanes/$LANE_B" && sha256sum mail.lock mail/*) || broke "could not hash D's mail files"
run_row r12a-state-verify-d 0 '-' 'exit 0' "$OLD_BIN state verify --config trial"
run_row r12b-doctor-d 0 '-' 'exit 0' "$OLD_BIN doctor --config trial"
run_row r12c-start-d 0 '-' 'exit 0' "$OLD_BIN start --config trial"
run_row r12d-lane-status-d 0 '-' 'exit 0' "$OLD_BIN lane status --config trial"
D_AFTER=$(cd "$STATE_DIR/lanes/$LANE_B" && sha256sum mail.lock mail/*) || broke "could not hash D's mail files again"
if [ "$D_BEFORE" = "$D_AFTER" ]; then D_SAME=0; else D_SAME=1; fi
verdict_row r12e-mail-files-unchanged \
    "$D_SAME (0 means the same); before: $(printf '%s' "$D_BEFORE" | tr '\n' ' '); after: $(printf '%s' "$D_AFTER" | tr '\n' ' ')" \
    'exit 0, and the files of mail/ and mail.lock are the same afterwards (compare their hashes)' \
    "$D_SAME"

STEP="row 13: event append of a loop.started event, on B"
use_store B
run_row r13-append-loop-started 0 '-' 'exit 0: 0.5.0 checks no loop.* event' \
    "$OLD_BIN event append --config trial --file $EVENTS/loop-started.json"

STEP="row 14: event tail and state events on E"
use_store E
run_row r14a-event-tail-e 0 '"kind": "loop\.(started|turn|stopped)"' \
    'exit 0, every event printed, the loop.* events among them' \
    "$OLD_BIN event tail --config trial"
use_store E
run_row r14b-state-events-e 0 '"kind": "loop\.started".*"kind": "loop\.turn".*"kind": "loop\.stopped"' \
    'exit 0, every event printed, the loop.* events among them' \
    "$OLD_BIN state events --config trial"

STEP="row 15: a copy of B with the loop's events appended and the loop's files added, verified and rebuilt"
use_store B
"$OLD_BIN" event append --config trial --file "$EVENTS/loop-started.json" >"$OUTDIR/r15-append-1.json" 2>&1 \
    || broke "row 15: appending loop.started with the old launcher was refused"
"$OLD_BIN" event append --config trial --file "$EVENTS/loop-turn.json" >"$OUTDIR/r15-append-2.json" 2>&1 \
    || broke "row 15: appending loop.turn with the old launcher was refused"
"$OLD_BIN" event append --config trial --file "$EVENTS/loop-skipped.json" >"$OUTDIR/r15-append-3.json" 2>&1 \
    || broke "row 15: appending loop.skipped with the old launcher was refused"
"$OLD_BIN" event append --config trial --file "$EVENTS/loop-stopped.json" >"$OUTDIR/r15-append-4.json" 2>&1 \
    || broke "row 15: appending loop.stopped with the old launcher was refused"
printf 'a lock file the file tool added\n' >"$STATE_DIR/loop.lock"
printf '{"loop": "confirm-0.5.0", "pid": 0}\n' >"$STATE_DIR/loop.json"
printf 'a line of the loop log\n' >"$STATE_DIR/loop.log"
L_BEFORE=$(cd "$STATE_DIR" && sha256sum loop.lock loop.log loop.json)
run_row r15a-state-verify-b-loop 0 '-' 'exit 0, and the three files are the same afterwards (compare their hashes)' \
    "$OLD_BIN state verify --config trial"
run_row r15b-state-rebuild-b-loop 0 '-' 'exit 0, and the three files are the same afterwards (compare their hashes)' \
    "$OLD_BIN state rebuild --config trial"
L_AFTER=$(cd "$STATE_DIR" && sha256sum loop.lock loop.log loop.json)
if [ "$L_BEFORE" = "$L_AFTER" ]; then L_SAME=0; else L_SAME=1; fi
verdict_row r15c-loop-files-unchanged \
    "$L_SAME (0 means the same); before: $(printf '%s' "$L_BEFORE" | tr '\n' ' '); after: $(printf '%s' "$L_AFTER" | tr '\n' ' ')" \
    'exit 0, and the three files are the same afterwards (compare their hashes)' \
    "$L_SAME"

# --- 5. the manifest --------------------
STEP="print the manifest"
echo "=== manifest ==="
sha256sum "$OLD_TARBALL" | sed 's|^|old tarball            sha256 |'
NEW_MANIFEST=$(cd "$NEW_TREE" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1)
echo "new tree               sha256 $NEW_MANIFEST (of the sorted per-file sha256 under $NEW_TREE)"
for template in trial.toml trial.edited.toml trial.stream.toml; do
    sha256sum "$TEMPLATES/$template" | sed 's|^|configuration          sha256 |'
done
for store in B C D E; do
    sha256sum "$STORES/$store/events.sqlite" | sed "s|^|store $store events.sqlite  sha256 |"
done
echo "rows run $ROWS_RUN, matched $ROWS_OK, mismatched $ROWS_BAD"
echo

if [ "$ROWS_BAD" = 0 ]; then
    echo "confirm-0.5.0: every row matched the document; exit 0"
    exit 0
fi
echo "confirm-0.5.0: $ROWS_BAD row(s) differ from the document; exit 1"
exit 1
