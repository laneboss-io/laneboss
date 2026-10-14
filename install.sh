#!/bin/sh
# Install Laneboss for one user with one command; this file is made to be piped:
#
#     curl -fsSL https://raw.githubusercontent.com/laneboss-io/laneboss/main/install.sh | sh
#
# It is a bootstrap and holds no installer of its own: it gets the source of one version and runs that version's own
# scripts/install.sh, which does the installing (docs/install.md). What it fetches runs with your rights, and nothing
# checks it. It never uses sudo and refuses to run as root. It writes only under the prefix (default ~/.local) and a
# temporary directory that it removes on the exits it catches: a normal end, a failure, and the signals HUP, INT, QUIT,
# PIPE and TERM. When it is piped, options go after `sh -s --`, for example: sh -s -- --prefix DIR
#
#   LANEBOSS_SOURCE   a directory, or a .tar, .tar.gz or .tgz file, on this machine; it is used first
#   LANEBOSS_REPO     the repository's address; default: the REPO line below. It is cloned with git (a private
#                     repository works with your own git credentials), else its tarball is fetched with curl
#   LANEBOSS_VERSION  a tag or a branch of the repository; default: main
#   LANEBOSS_GO       the Go executable; default: go (the source installer pins the toolchain)
#
# Every command of this file after this header is inside one brace group, and the closing brace is the last line of
# the file. A shell reads a whole group before it runs any of it, so a download that stops inside the commands is a
# syntax error and runs nothing, and one that stops inside this header is only comments.
{
set -eu

# The repository's public address, used when neither LANEBOSS_SOURCE nor LANEBOSS_REPO names a source.
REPO=https://github.com/laneboss-io/laneboss.git

laneboss_bootstrap() {
    usage="usage: install.sh [--prefix DIR]   (default prefix: ~/.local)"
    tmp=""
    trap 'status=$?; if [ -n "$tmp" ]; then chmod -R u+rwX -- "$tmp" 2>/dev/null || true; rm -rf -- "$tmp" || true; fi; exit "$status"' EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 131' QUIT
    trap 'exit 141' PIPE
    trap 'exit 143' TERM

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
            --prefix=?*)
                prefix=${1#--prefix=}
                shift
                ;;
            -h|--help)
                echo "$usage"
                echo "Gets the source of one version of Laneboss and runs that version's own scripts/install.sh."
                echo "Variables: LANEBOSS_SOURCE (a directory, .tar or .tar.gz on this machine), LANEBOSS_REPO (the"
                echo "repository's address), LANEBOSS_VERSION (a tag or branch; default main), LANEBOSS_GO."
                exit 0
                ;;
            *)
                echo "install: unknown argument; $usage" >&2
                exit 2
                ;;
        esac
    done

    # Who runs it, and on what: never root (a missing or odd answer of id is a refusal too), only macOS and Linux.
    uid=$(id -u 2>/dev/null) || uid=""
    case "$uid" in
        ''|*[!0-9]*)
            echo "install: cannot tell which user this is (id -u did not print a number); refusing to run" >&2
            exit 2
            ;;
    esac
    if [ "$uid" -eq 0 ]; then
        echo "install: refusing to run as root: Laneboss installs for one user under their home directory and" \
            "never needs sudo; run this as your own user" >&2
        exit 2
    fi
    system=$(uname -s 2>/dev/null) || system=""
    case "$system" in
        Darwin|Linux) ;;
        '')
            echo "install: cannot tell which system this is (uname -s printed nothing); Laneboss installs on macOS" \
                "and Linux" >&2
            exit 2
            ;;
        *)
            echo "install: unsupported system $system: Laneboss installs on macOS and Linux" >&2
            exit 2
            ;;
    esac

    case "$prefix" in
        ''|'~'|'~'/*)
            if [ -z "${HOME:-}" ]; then
                echo "install: HOME is not set; pass --prefix DIR" >&2
                exit 2
            fi
            ;;
    esac
    case "$prefix" in
        '') prefix=$HOME/.local ;;
        '~') prefix=$HOME ;;
        '~'/*) prefix=$HOME/${prefix#'~'/} ;;
        /*) ;;
        *) prefix=$PWD/$prefix ;;
    esac

    # Where the source comes from: LANEBOSS_SOURCE, else the repository.
    source=${LANEBOSS_SOURCE:-}
    repo=${LANEBOSS_REPO:-$REPO}
    wanted=${LANEBOSS_VERSION:-main}
    kind=""
    if [ -n "$source" ]; then
        case "$source" in
            /*) ;;
            *) source=$PWD/$source ;;
        esac
        if [ -d "$source" ]; then
            kind=directory
        elif [ -f "$source" ]; then
            case "$source" in
                *.tar|*.tar.gz|*.tgz) kind=archive ;;
            esac
        fi
        if [ -z "$kind" ]; then
            printf 'install: LANEBOSS_SOURCE is not a directory or a .tar, .tar.gz or .tgz file: %s\n' "$source" >&2
            exit 2
        fi
    else
        allowed=0
        case "$repo" in
            -*)
                echo "install: the repository address must not start with a dash" >&2
                exit 2
                ;;
            *::*)
                echo "install: the repository address must not contain :: (git runs a helper program for an" \
                    "address of the form name::address)" >&2
                exit 2
                ;;
            https://*|ssh://*|file://*|/*)
                allowed=1
                ;;
            *://*)
                ;;
            *@*:*)
                allowed=1
                ;;
            *)
                if [ -z "${LANEBOSS_REPO:-}" ]; then
                    echo "install: this copy of install.sh has no repository address yet (its REPO line is still a" \
                        "placeholder); set LANEBOSS_SOURCE to a directory or a .tar or .tar.gz file on this" \
                        "machine, or LANEBOSS_REPO to the repository's address" >&2
                    exit 2
                fi
                ;;
        esac
        if [ "$allowed" != 1 ]; then
            echo "install: refusing the repository address: the source is run after it is fetched, so it must come" \
                "over https://, over ssh:// (or as user@host:path), from file:// or from an absolute path on this" \
                "machine" >&2
            exit 2
        fi
        case "$wanted" in
            -*|*..*|*[!A-Za-z0-9._/+-]*)
                echo "install: LANEBOSS_VERSION must be a tag or branch name made of letters, digits and . _ / + -" >&2
                exit 2
                ;;
        esac
        # What is printed never carries what the address holds before its last @: a user name, a password.
        address=$repo
        case "$repo" in
            *@*)
                case "$repo" in
                    *://*) address=${repo%%://*}://${repo##*@} ;;
                    *) address=${repo##*@} ;;
                esac
                ;;
        esac
    fi

    # The source's own installer pins the Go version and builds the launcher.
    go_command=${LANEBOSS_GO:-go}
    if ! go_command=$(command -v "$go_command" 2>/dev/null) || [ ! -f "$go_command" ] || [ ! -x "$go_command" ]; then
        echo "install: Go is required on PATH, or set LANEBOSS_GO to a Go executable" >&2
        exit 2
    fi
    # Keep the selected executable and temporary base valid when the source
    # installer changes directories. A colon in a relative base is just a path.
    case "$go_command" in
        /*) ;;
        *) go_command=$PWD/$go_command ;;
    esac
    LANEBOSS_GO=$go_command
    export LANEBOSS_GO
    temporary_base=${TMPDIR:-/tmp}
    case "$temporary_base" in
        /*) ;;
        *) temporary_base=$PWD/$temporary_base ;;
    esac
    TMPDIR=$temporary_base
    export TMPDIR
    fetch=""
    if [ -z "$source" ]; then
        if command -v git >/dev/null 2>&1; then
            fetch=git
        elif command -v curl >/dev/null 2>&1; then
            fetch=curl
            case "$repo" in
                https://*|file://*) ;;
                *)
                    echo "install: without git, the repository address must be an https:// or file:// address, so" \
                        "that its tarball can be fetched" >&2
                    exit 2
                    ;;
            esac
        else
            echo "install: neither git nor curl is on PATH; one of them is needed to fetch the source (or set" \
                "LANEBOSS_SOURCE to a directory or an archive on this machine)" >&2
            exit 2
        fi
    fi
    if [ "$kind" = archive ] || [ "$fetch" = curl ]; then
        if ! command -v tar >/dev/null 2>&1; then
            echo "install: tar is not on PATH; it is needed to unpack the source" >&2
            exit 2
        fi
        gzipped=0
        case "$source" in
            *.tar.gz|*.tgz) gzipped=1 ;;
        esac
        if [ "$fetch" = curl ]; then
            gzipped=1
        fi
        if [ "$gzipped" = 1 ] && ! command -v gzip >/dev/null 2>&1; then
            echo "install: gzip is not on PATH; it is needed to unpack a .tar.gz archive" >&2
            exit 2
        fi
    fi

    # Get the source into a temporary directory when it is not a directory already.
    archive=""
    root=""
    if [ -n "$fetch" ] || [ "$kind" = archive ]; then
        if ! tmp=$(mktemp -d "${TMPDIR:-/tmp}/laneboss-install.XXXXXX" 2>/dev/null); then
            tmp=""
            printf 'install: cannot make a temporary directory under %s\n' "${TMPDIR:-/tmp}" >&2
            exit 2
        fi
        case "$tmp" in
            /*) ;;
            *) tmp=$PWD/$tmp ;;
        esac
    fi
    case "$fetch" in
        git)
            printf 'install: fetching version %s of %s with git\n' "$wanted" "$address"
            # git itself refuses every other protocol, a redirect to http and every name::address helper included.
            if ! GIT_ALLOW_PROTOCOL=file:https:ssh git clone -q -c advice.detachedHead=false --depth 1 \
                --branch "$wanted" -- "$repo" "$tmp/source" </dev/null; then
                printf 'install: git could not fetch version %s of %s; check LANEBOSS_REPO and LANEBOSS_VERSION\n' \
                    "$wanted" "$address" >&2
                exit 2
            fi
            root=$tmp/source
            ;;
        curl)
            base=${repo%/}
            base=${base%.git}
            where=${address%/}
            where=${where%.git}
            printf 'install: fetching version %s of %s with curl\n' "$wanted" "$where"
            archive=$tmp/source.tar.gz
            if ! curl -fsSL -g --proto =https,file --proto-redir =https -o "$archive" \
                "$base/archive/$wanted.tar.gz" </dev/null; then
                printf 'install: curl could not fetch %s/archive/%s.tar.gz; check LANEBOSS_REPO and LANEBOSS_VERSION\n' \
                    "$where" "$wanted" >&2
                exit 2
            fi
            kind=archive
            ;;
    esac
    if [ "$kind" = directory ]; then
        root=$source
    elif [ "$kind" = archive ]; then
        if [ -z "$archive" ]; then
            archive=$source
        fi
        case "$archive" in
            *.tar) unpack=-xf ;;
            *) unpack=-xzf ;;
        esac
        mkdir "$tmp/unpacked"
        if ! tar "$unpack" "$archive" -C "$tmp/unpacked" </dev/null; then
            printf 'install: tar could not unpack %s\n' "$archive" >&2
            exit 2
        fi
        if [ -f "$tmp/unpacked/scripts/install.sh" ]; then
            root=$tmp/unpacked
        else
            for entry in "$tmp/unpacked"/*; do
                if [ -z "$root" ] && [ -f "$entry/scripts/install.sh" ]; then
                    root=$entry
                fi
            done
        fi
    fi
    if [ -z "$root" ] || [ ! -f "$root/scripts/install.sh" ]; then
        printf 'install: there is no scripts/install.sh in %s\n' "${source:-the fetched source}" >&2
        exit 2
    fi

    # Run that version's own installer with its pinned Go toolchain. What the link at PREFIX/bin/laneboss points
    # at tells "already installed" from an upgrade; the program there is read, never started.
    command=$prefix/bin/laneboss
    before=""
    if [ -L "$command" ]; then
        target=$(readlink "$command" 2>/dev/null) || target=""
        case "$target" in
            */versions/*/bin/laneboss)
                before=${target%/bin/laneboss}
                before=${before##*/}
                ;;
        esac
    fi
    echo "install: running scripts/install.sh of that source with your rights; nothing checks the source (docs/install.md)"
    sh "$root/scripts/install.sh" --prefix "$prefix" </dev/null >/dev/null || exit $?
    if ! shown=$("$command" --version </dev/null); then
        printf 'install: the installed command did not run: %s --version\n' "$command" >&2
        exit 2
    fi
    installed=$(readlink "$command")
    case "$installed" in
        */versions/*/bin/laneboss)
            installed=${installed%/bin/laneboss}
            installed=${installed##*/}
            ;;
        *)
            echo "install: the installed command has no version-directory link" >&2
            exit 2
            ;;
    esac

    if [ "$before" = "$installed" ]; then
        printf 'install: laneboss %s is already installed\n' "$installed"
    elif [ -n "$before" ]; then
        printf 'install: installed laneboss %s in %s; version %s stays in the same place for a rollback\n' \
            "$installed" "$prefix" "$before"
    else
        printf 'install: installed laneboss %s in %s\n' "$installed" "$prefix"
    fi
    printf '%s\n' "$shown"
    case ":${PATH:-}:" in
        *":$prefix/bin:"*) ;;
        *)
            printf 'install: %s/bin is not on your PATH; add this line to your shell startup file to use laneboss:\n' \
                "$prefix"
            printf 'export PATH="%s/bin:$PATH"\n' "$prefix"
            ;;
    esac
    echo "install: next, check the environment with: laneboss doctor --config NAME   (the README's Quick start"
    echo "makes a configuration)"
    if ! command -v tmux >/dev/null 2>&1; then
        echo "install: warning: tmux is not on PATH; lanes run in tmux sessions, so install tmux before you start" \
            "a lane (laneboss doctor reports it)" >&2
    fi
}

laneboss_bootstrap "$@"
}
