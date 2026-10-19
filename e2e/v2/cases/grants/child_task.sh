#!/bin/sh
set -eu
test "$#" -eq 1
test -r input.txt
task_work=$(mktemp -d "${TMPDIR:-/tmp}/lb-grants.XXXXXX")
cp child_probe.c pre-commit.sh input.txt "$task_work/"
cd "$task_work"
if command -v cc >/dev/null 2>&1; then
    task_cc=cc
elif command -v gcc >/dev/null 2>&1; then
    task_cc=gcc
else
    printf '%s\n' 'missing: cc' 'missing: gcc' 'prep package: gcc and libc6-dev' >&2
    exit 127
fi
"$task_cc" -Wall -Werror child_probe.c -o child-probe
build_exit=$?
./child-probe "$1"
input_sha256=$(sha256sum input.txt)
input_sha256=${input_sha256%% *}
printf '{"input_sha256":"%s"}\n' "$input_sha256"
git init --quiet .
test -d .git
test ! -f .git/objects/info/alternates
test ! -f .git/commondir
test -z "$(git for-each-ref --format='%(refname)')"
printf '%s\n' "$1" > probe-target
cp pre-commit.sh .git/hooks/pre-commit
chmod 700 .git/hooks/pre-commit
# The disposable repository's actual Git commit invokes the child-written hook.
# Git sends hook output to stderr; keep the real hook record in the worker's
# primary stdout stream along with the direct probe. Preserve Git's exit.
git -c user.name=Boundary -c user.email=boundary commit --allow-empty --quiet -m 'Boundary probe' 2>&1
git_exit=$?
printf '{"build_exit":%s,"git_exit":%s}\n' "$build_exit" "$git_exit"
