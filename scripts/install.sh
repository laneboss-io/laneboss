#!/bin/sh
# Build with the pinned Go toolchain and install one immutable version with its plugins.
set -eu
usage="usage: install.sh [--prefix DIR]   (default prefix: ~/.local)"
prefix=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --prefix)
            if [ "$#" -lt 2 ] || [ -z "$2" ]; then
                echo "install: --prefix needs a directory; $usage" >&2
                exit 2
            fi
            prefix=$2
            shift 2
            ;;
        --prefix=?*) prefix=${1#--prefix=}; shift ;;
        -h|--help) echo "$usage"; exit 0 ;;
        *) echo "install: unknown argument; $usage" >&2; exit 2 ;;
    esac
done
if [ -z "$prefix" ]; then
    if [ -z "${HOME:-}" ]; then
        echo "install: HOME is not set; pass --prefix DIR" >&2
        exit 2
    fi
    prefix=$HOME/.local
fi
case "$prefix" in
    '~'|'~'/*) ;;
    /*) ;;
    *) prefix=$PWD/$prefix ;;
esac
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
if [ ! -f "$root/go.mod" ] || [ ! -f "$root/cmd/laneboss/main.go" ]; then
    echo "install: no Go launcher source beside this installer" >&2
    exit 2
fi
go_command=${LANEBOSS_GO:-go}
if ! go_command=$(command -v "$go_command" 2>/dev/null) || [ ! -f "$go_command" ] || [ ! -x "$go_command" ]; then
    echo "install: Go is required on PATH, or set LANEBOSS_GO to a Go executable" >&2
    exit 2
fi
# Relative executable paths must survive changing to the source root.
case "$go_command" in
    /*) ;;
    *) go_command=$PWD/$go_command ;;
esac
temporary_base=${TMPDIR:-/tmp}
case "$temporary_base" in
    /*) ;;
    *) temporary_base=$PWD/$temporary_base ;;
esac
TMPDIR=$temporary_base
export TMPDIR
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/laneboss-install-build.XXXXXX")
case "$build_dir" in
    /*) ;;
    *) build_dir=$PWD/$build_dir ;;
esac
trap 'status=$?; trap - EXIT; if ! rm -r -- "$build_dir"; then echo "install: could not remove temporary build directory" >&2; exit 2; fi; exit "$status"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 131' QUIT
trap 'exit 141' PIPE
trap 'exit 143' TERM
cd "$root"
# Fixed toolchain and build settings make the installed manifest reproducible
# across source locations. The Go command fetches missing toolchains/modules.
GOTOOLCHAIN=go1.26.0 GOWORK=off CGO_ENABLED=0 GOENV=off GOFLAGS= "$go_command" build -tags= -trimpath -buildvcs=false -o "$build_dir/laneboss" ./cmd/laneboss
GOTOOLCHAIN=go1.26.0 GOWORK=off CGO_ENABLED=0 GOENV=off GOFLAGS= "$go_command" build -tags= -trimpath -buildvcs=false -o "$build_dir/install" ./scripts/install
"$build_dir/install" "$root" "$prefix" "$build_dir/laneboss"
