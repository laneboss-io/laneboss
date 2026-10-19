#!/bin/sh
# Authorized disposable Ubuntu box only. No installed serve run is launched here.
set -eu
umask 077

judge_source=$(CDPATH='' cd -- "$(dirname -- "$0")/../../../.." && pwd -P)
cd "$judge_source"
test "$(uname -s)" = Linux
judge_go=$(command -v go)
judge_output=$(mktemp -d /tmp/lb-v2-case-judge.XXXXXX)
export GOFLAGS=-trimpath
rc=0

judge_check() {
    judge_name=$1
    shift
    if "$@" > "$judge_output/$judge_name.log" 2>&1; then
        printf '%s\n' "$judge_name: exit 0"
    else
        rc=$?
        cat "$judge_output/$judge_name.log"
        printf '%s\n' "$judge_name: failed"
        return "$rc"
    fi
}

if judge_check packages "$judge_go" test -count=1 \
    ./internal/v2/api ./internal/v2/admin ./internal/v2/identity \
    ./internal/v2/client/... ./internal/v2/store ./internal/v2/service \
    ./internal/v2/judge/... ./internal/v2/assembly ./internal/v2/cli \
    ./internal/v2/policy ./internal/v2/guidance ./internal/v2/templates \
    ./e2e/v2/cases/judge ./scripts/v2-serve/bundle; then
    if judge_check native sudo "$judge_go" test -count=1 \
        -tags laneboss_root_canary -run '^TestJudgeGateNative$' ./internal/v2/admin; then
        if judge_check red "$judge_go" test -count=1 -v \
            -tags laneboss_judge_red -run '^TestJudgeNativeRed$' ./e2e/v2/cases/judge; then
            if judge_check python python3 -B -m unittest discover \
                -s e2e/v2/cases/judge -p 'test_*.py'; then
                if judge_check vet "$judge_go" vet ./internal/v2/api \
                    ./internal/v2/admin ./internal/v2/identity ./internal/v2/client/... \
                    ./internal/v2/store ./internal/v2/service ./internal/v2/judge/... \
                    ./internal/v2/assembly ./e2e/v2/cases/judge; then
                    printf '%s\n' 'judge checks completed'
                else rc=$?; fi
            else rc=$?; fi
        else rc=$?; fi
    else rc=$?; fi
else rc=$?; fi
printf '%s\n' "retained judge check logs: $judge_output"
(exit "$rc")
