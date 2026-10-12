#!/bin/sh
# The shell program of the /laneboss command. Usage: start.sh [CONFIGURATION [ROLE]]. SKILL.md runs it with no
# argument in its one shell block and tells the session to run it with the plain names the person typed; typed text
# never enters a shell block, and this program reads nothing from standard input.
#
# It accepts no argument, one name or two names, a name being a letter or digit and then letters, digits, dots,
# underscores and hyphens, and refuses anything else. The program is laneboss on PATH, then $HOME/.local/bin/laneboss,
# and nowhere else; it runs "laneboss start", "laneboss start --config NAME" or "laneboss start --config NAME
# --role ROLE".
#
# It always exits 0 and always prints something on standard output, because the agent program gives the session
# nothing, not even an error, for a command that exits non-zero. When it cannot hand the session a list or a
# briefing its output is the marker line and then the reason, and it never repeats an argument:
#   - one of its own refusals, or laneboss not found: one sentence;
#   - a "laneboss start" that exits non-zero: the line "laneboss start exited with status N." and then what the
#     launcher printed on standard output and then on standard error, unchanged.
# When "laneboss start" exits 0 its output goes through unchanged, each stream on its own, with no marker.
unset IFS
marker="laneboss plugin: NOT STARTED"

not_started() {
  printf '%s\n' "$marker"
  printf '%s\n' "$1"
  exit 0
}

if [ "$#" -gt 2 ]; then
  not_started "laneboss plugin: give at most two arguments, a configuration name and optionally a role."
fi
for word in "$@"; do
  if [ -z "$word" ] || ! ( LC_ALL=C; case $word in [!a-zA-Z0-9]* | *[!a-zA-Z0-9._-]*) exit 1 ;; esac ); then
    not_started "laneboss plugin: a configuration name and a role start with a letter or digit and hold only letters, digits, dots, underscores and hyphens."
  fi
done
program=laneboss
if ! command -v laneboss >/dev/null 2>&1; then
  program=$HOME/.local/bin/laneboss
  if [ ! -f "$program" ] || [ ! -x "$program" ]; then
    not_started "laneboss was not found on PATH or at $HOME/.local/bin/laneboss; install it by running sh scripts/install.sh from the laneboss checkout."
  fi
fi
scratch=$(mktemp -d "${TMPDIR:-/tmp}/laneboss-plugin.XXXXXX" 2>/dev/null) ||
  not_started "laneboss plugin: a temporary directory could not be made, so laneboss start was not run."
trap 'rm -r "$scratch"' EXIT
trap 'exit 1' HUP INT TERM
config=${1-}
role=${2-}
set -- start
[ -z "$config" ] || set -- "$@" --config "$config"
[ -z "$role" ] || set -- "$@" --role "$role"
"$program" "$@" > "$scratch/out" 2> "$scratch/err" < /dev/null
exit_code=$?
if [ "$exit_code" -eq 0 ]; then
  cat "$scratch/out"
  cat "$scratch/err" >&2
else
  printf '%s\n' "$marker"
  printf '%s\n' "laneboss start exited with status $exit_code."
  cat "$scratch/out" "$scratch/err"
fi
exit 0
