#!/bin/sh
# Install Laneboss for one user with one command; this file is made to be piped:
#
#     curl -fsSL https://raw.githubusercontent.com/laneboss-io/laneboss/main/install.sh | sh
#
# By default it installs released Laneboss and claudock-cli binaries, verifying each archive against SHA256SUMS.
# --without-claudock skips the companion. --from-source keeps the Laneboss source build path.
# It never uses sudo and refuses to run as root. It writes only under the prefix (default ~/.local) and a
# temporary directory that it removes on the exits it catches: a normal end, a failure, and the signals HUP, INT, QUIT,
# PIPE and TERM. When it is piped, options go after `sh -s --`, for example: sh -s -- --prefix DIR
#
#   LANEBOSS_VERSION  release version (optional v prefix); default: GitHub's latest release redirect
#   LANEBOSS_RELEASE_BASE_URL  explicit test asset directory for both programs; requires a Laneboss release version
#   With --from-source:
#   LANEBOSS_SOURCE   a directory, or a .tar, .tar.gz or .tgz file, on this machine; it is used first
#   LANEBOSS_REPO     the repository's address; default: the REPO line below. It is cloned with git (a private
#                     repository works with your own git credentials), else its tarball is fetched with curl
#   LANEBOSS_VERSION  a tag or a branch of the source repository; default: main
#   LANEBOSS_GO       the Go executable; default: go (the source installer pins the toolchain)
#
# Every command of this file after this header is inside one brace group, and the closing brace is the last line of
# the file. A shell reads a whole group before it runs any of it, so a download that stops inside the commands is a
# syntax error and runs nothing, and one that stops inside this header is only comments.
{
set -eu

# The repository's public address, used when neither LANEBOSS_SOURCE nor LANEBOSS_REPO names a source.
REPO=https://github.com/laneboss-io/laneboss.git
RELEASES=https://github.com/laneboss-io/laneboss/releases
CLAUDOCK_RELEASES=https://github.com/laneboss-io/claudock-cli/releases
CLAUDOCK_VERSION=0.1.0

release_requirements() {
    for release_tool in curl tar gzip awk; do
        if ! command -v "$release_tool" >/dev/null 2>&1; then
            echo "install: missing release prerequisite: $release_tool" >&2
            exit 2
        fi
    done
    if command -v sha256sum >/dev/null 2>&1; then
        checksum_tool=sha256sum
    elif command -v shasum >/dev/null 2>&1; then
        checksum_tool=shasum
    else
        echo "install: sha256sum or shasum is required; refusing an unverified download" >&2
        exit 2
    fi
    case "$system" in
        Linux) release_os=linux ;;
        Darwin) release_os=darwin ;;
    esac
    machine=$(uname -m)
    case "$machine" in
        x86_64|amd64) release_arch=amd64 ;;
        arm64|aarch64) release_arch=arm64 ;;
        *) echo "install: unsupported architecture; releases support amd64 and arm64" >&2; exit 2 ;;
    esac
}

release_location() {
    release_base=${LANEBOSS_RELEASE_BASE_URL:-}
    release_protocols=https
    if [ -n "$release_base" ]; then
        # HTTP is allowed only for an explicitly selected loopback test server.
        case "$release_base" in
            https://*) ;;
            http://*)
                if ! LC_ALL=C awk -v base="$release_base" 'BEGIN {
                    exit !(base ~ /^http:\/\/(127\.0\.0\.1|localhost):[0-9]+(\/[^@?#]*)?$/)
                }'; then
                    echo "install: HTTP release testing requires a loopback server with a port" >&2
                    exit 2
                fi
                release_protocols=http,https
                ;;
            *) echo "install: release base must use HTTPS or a loopback HTTP test server" >&2; exit 2 ;;
        esac
    fi
}

release_temporary_dir() {
    if [ -z "$tmp" ]; then
        tmp=$(mktemp -d "${TMPDIR:-/tmp}/laneboss-install.XXXXXX")
        case "$tmp" in
            /*) ;;
            *) tmp=$PWD/$tmp ;;
        esac
    fi
}

fetch_verified_release() {
    verified_program=$1
    verified_version=$2
    verified_default_base=$3
    release_requirements
    release_location
    if [ -z "$release_base" ]; then
        release_base=$verified_default_base
    fi
    release_base=${release_base%/}
    release_temporary_dir
    verified_dir=$tmp/$verified_program-download
    mkdir "$verified_dir"
    asset=${verified_program}_${verified_version}_${release_os}_${release_arch}.tar.gz
    printf 'install: downloading %s %s for %s/%s\n' \
        "$verified_program" "$verified_version" "$release_os" "$release_arch"
    if ! curl -fsSL --proto "=$release_protocols" --proto-redir "=$release_protocols" \
        -o "$verified_dir/$asset" "$release_base/$asset" </dev/null; then
        echo "install: $verified_program release archive download failed" >&2
        exit 2
    fi
    if ! curl -fsSL --proto "=$release_protocols" --proto-redir "=$release_protocols" \
        -o "$verified_dir/SHA256SUMS" "$release_base/SHA256SUMS" </dev/null; then
        echo "install: $verified_program checksum download failed" >&2
        exit 2
    fi
    if ! expected=$(LC_ALL=C awk -v asset="$asset" '
        $2 == asset {
            matches++
            if (NF != 2 || length($1) != 64 || $1 ~ /[^0-9a-fA-F]/) bad = 1
            digest = tolower($1)
        }
        END { if (matches != 1 || bad) exit 1; print digest }
    ' "$verified_dir/SHA256SUMS"); then
        echo "install: $verified_program SHA256SUMS must contain exactly one valid checksum for the archive" >&2
        exit 2
    fi
    case "$checksum_tool" in
        sha256sum) actual=$(sha256sum "$verified_dir/$asset") ;;
        shasum) actual=$(shasum -a 256 "$verified_dir/$asset") ;;
    esac
    # Checksum tools escape filenames containing a backslash on some systems.
    actual=${actual#\\}
    actual=${actual%% *}
    if [ "$actual" != "$expected" ]; then
        echo "install: $verified_program SHA-256 mismatch; refusing to unpack or execute the release" >&2
        exit 2
    fi
    printf 'install: %s release archive SHA-256 verified\n' "$verified_program"
    verified_root=$verified_dir/unpacked
    mkdir "$verified_root"
    tar -xzf "$verified_dir/$asset" -C "$verified_root" </dev/null
}

laneboss_release() {
    release_requirements
    release_location
    if [ -n "$release_base" ] && [ -z "$wanted" ]; then
        echo "install: a release base override requires --version or LANEBOSS_VERSION" >&2
        exit 2
    fi
    if [ -z "$wanted" ]; then
        if ! latest=$(curl -fsSL --proto =https --proto-redir =https -o /dev/null \
            -w '%{url_effective}' "$RELEASES/latest" </dev/null); then
            echo "install: could not resolve the latest GitHub release" >&2
            exit 2
        fi
        case "$latest" in
            "$RELEASES"/tag/v*) wanted=${latest##*/} ;;
            *) echo "install: latest release did not redirect to a version tag" >&2; exit 2 ;;
        esac
    fi
    release_version=${wanted#v}
    case "$release_version" in
        ''|*[!0-9A-Za-z.+-]*)
            echo "install: release version contains unsupported characters" >&2
            exit 2
            ;;
    esac
    if ! LC_ALL=C awk -v version="$release_version" 'BEGIN {
        exit !(version ~ /^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?$/ && version !~ /\.\./)
    }'; then
        echo "install: release version must look like 1.2.3 or 1.2.3-label" >&2
        exit 2
    fi
    fetch_verified_release laneboss "$release_version" "$RELEASES/download/v$release_version"
    root=$verified_root
    if [ ! -f "$root/laneboss" ] || [ -L "$root/laneboss" ] || [ ! -x "$root/laneboss" ] \
        || [ ! -d "$root/plugins/claude-code" ]; then
        echo "install: verified archive is missing its executable or plugins" >&2
        exit 2
    fi
    # The compiled identity must equal the release name before any prefix write.
    "$root/laneboss" --install-release "$root" "$prefix" "$release_version" </dev/null
}

read_claudock_version() {
    if ! claudock_version_text=$("$1" version </dev/null 2>/dev/null); then
        return 1
    fi
    if ! claudock_seen=$(printf '%s\n' "$claudock_version_text" | LC_ALL=C awk '
        NR == 1 && tolower($1) == "claudock" {
            version = $2
            if (tolower(version) == "version") version = $3
            sub(/^v/, "", version)
            if (version ~ /^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?$/) {
                print version
                valid = 1
            }
        }
        END { if (NR != 1 || !valid) exit 1 }
    '); then
        return 1
    fi
}

install_claudock() {
    if [ "$with_claudock" = 0 ]; then
        echo "install: claudock skipped (--without-claudock)"
        return
    fi
    claudock_target=$prefix/bin/claudock
    claudock_existing=""
    claudock_location="on PATH"
    if claudock_candidate=$(command -v claudock 2>/dev/null); then
        claudock_existing=$claudock_candidate
    elif [ -e "$claudock_target" ] || [ -L "$claudock_target" ]; then
        claudock_existing=$claudock_target
        claudock_location="in the prefix"
    fi
    if [ -n "$claudock_existing" ]; then
        claudock_seen=""
        if [ -f "$claudock_existing" ] && [ -x "$claudock_existing" ] \
            && read_claudock_version "$claudock_existing" \
            && [ "$claudock_seen" = "$CLAUDOCK_VERSION" ]; then
            printf 'install: claudock %s is already %s; keeping it\n' "$CLAUDOCK_VERSION" "$claudock_location"
            return
        fi
        if [ "$upgrade_claudock" = 0 ]; then
            echo "install: keeping existing claudock $claudock_location (different or unreadable version)."
            echo "install: Laneboss installation is complete; use --upgrade-claudock to install the pinned claudock."
            return
        fi
    fi
    if [ -d "$claudock_target" ]; then
        echo "install: claudock destination is a directory; Laneboss is installed, claudock is not" >&2
        exit 2
    fi
    echo "install: Laneboss installation is complete; installing claudock next (a failure exits nonzero)."
    fetch_verified_release claudock "$CLAUDOCK_VERSION" "$CLAUDOCK_RELEASES/download/v$CLAUDOCK_VERSION"
    claudock_binary=$verified_root/claudock
    if [ ! -f "$claudock_binary" ] || [ -L "$claudock_binary" ] || [ ! -x "$claudock_binary" ] \
        || ! read_claudock_version "$claudock_binary" || [ "$claudock_seen" != "$CLAUDOCK_VERSION" ]; then
        echo "install: verified claudock binary is missing or has the wrong version; Laneboss remains installed" >&2
        exit 2
    fi
    # Copy and rename on the destination filesystem so a failed copy or chmod
    # leaves the previous executable intact. The subshell cleans its staging dir.
    (
        claudock_stage=$(mktemp -d "$prefix/bin/.claudock-install.XXXXXX")
        trap 'rm -r -- "$claudock_stage"' EXIT
        trap 'exit 129' HUP
        trap 'exit 130' INT
        trap 'exit 143' TERM
        cp "$claudock_binary" "$claudock_stage/claudock"
        chmod 755 "$claudock_stage/claudock"
        mv -f "$claudock_stage/claudock" "$claudock_target"
    )
    printf 'install: installed claudock %s beside laneboss\n' "$CLAUDOCK_VERSION"
    case ":${PATH:-}:" in
        *":$prefix/bin:"*) ;;
        *) echo "install: add the selected prefix bin directory to PATH to use both commands" ;;
    esac
}

laneboss_bootstrap() {
    usage="usage: install.sh [--prefix DIR] [--version VERSION] [--from-source] [--without-claudock] [--upgrade-claudock]"
    tmp=""
    trap 'status=$?; if [ -n "$tmp" ]; then chmod -R u+rwX -- "$tmp" 2>/dev/null || true; rm -rf -- "$tmp" || true; fi; exit "$status"' EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 131' QUIT
    trap 'exit 141' PIPE
    trap 'exit 143' TERM

    prefix=""
    from_source=0
    with_claudock=1
    upgrade_claudock=0
    wanted=${LANEBOSS_VERSION:-}
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
            --from-source) from_source=1; shift ;;
            --without-claudock) with_claudock=0; shift ;;
            --upgrade-claudock) upgrade_claudock=1; shift ;;
            --version)
                if [ "$#" -lt 2 ] || [ -z "$2" ]; then
                    echo "install: --version needs a version; $usage" >&2
                    exit 2
                fi
                wanted=$2
                shift 2
                ;;
            --version=?*) wanted=${1#--version=}; shift ;;
            -h|--help)
                echo "$usage"
                echo "Installs Laneboss (latest or --version) and pinned claudock-cli, verifying both archives without Go."
                echo "--without-claudock skips the companion; --upgrade-claudock replaces a different existing version."
                echo "Default prefix: ~/.local. Variables: LANEBOSS_VERSION, LANEBOSS_RELEASE_BASE_URL (explicit test asset directory)."
                echo "--from-source builds instead: LANEBOSS_SOURCE, LANEBOSS_REPO, LANEBOSS_VERSION (default main), LANEBOSS_GO."
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

    if [ "$from_source" = 0 ]; then
        if [ -n "${LANEBOSS_SOURCE:-}" ] || [ -n "${LANEBOSS_REPO:-}" ]; then
            echo "install: LANEBOSS_SOURCE and LANEBOSS_REPO require --from-source" >&2
            exit 2
        fi
        laneboss_release
        "$prefix/bin/laneboss" --version </dev/null
        install_claudock
        case ":${PATH:-}:" in
            *":$prefix/bin:"*) ;;
            *) printf 'install: add %s/bin to PATH to use laneboss\n' "$prefix" ;;
        esac
        echo "install: next, run laneboss doctor --config NAME (see the README's Quick start)"
        if ! command -v tmux >/dev/null 2>&1; then
            echo "install: warning: install tmux before starting a lane" >&2
        fi
        return
    fi

    # Where the source comes from: LANEBOSS_SOURCE, else the repository.
    source=${LANEBOSS_SOURCE:-}
    repo=${LANEBOSS_REPO:-$REPO}
    wanted=${wanted:-main}
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
    install_claudock
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
