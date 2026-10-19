#!/usr/bin/env bash
# Build deterministic release archives from a clean checkout; never publishes.
set -euo pipefail
umask 022
export LC_ALL=C
export COPYFILE_DISABLE=1

fail() {
    echo "release: $1" >&2
    exit 2
}

[[ $# -eq 2 ]] || fail 'usage: scripts/release.sh VERSION OUTDIR'
release_version=$1
if [[ ! $release_version =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?$ ]] \
    || [[ $release_version == *..* ]]; then
    fail 'VERSION must look like 1.2.3 or 1.2.3-label (without v)'
fi
release_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$release_root"
identity_version=$(sed -n 's/^[[:space:]]*Version[[:space:]]*=[[:space:]]*"\([^"]*\)"[[:space:]]*$/\1/p' internal/identity/identity.go)
[[ $release_version == "$identity_version" ]] || fail 'VERSION does not equal identity.Version'
release_status=$(git status --porcelain --untracked-files=all)
[[ -z $release_status ]] || fail 'working tree is dirty; commit the release inputs first'

for release_tool in git gzip sed cp chmod mktemp; do
    command -v "$release_tool" >/dev/null 2>&1 || fail "missing prerequisite: $release_tool"
done
release_go=${LANEBOSS_GO:-go}
release_go=$(command -v "$release_go") || fail 'Go is required to obtain the pinned toolchain'
[[ -f $release_go && -x $release_go ]] || fail 'Go must name an executable file'
case "$release_go" in
    /*) ;;
    *) release_go=$release_root/$release_go ;;
esac
release_tar=tar
release_tar_version=$(tar --version)
if [[ $release_tar_version != *'GNU tar'* ]]; then
    command -v gtar >/dev/null 2>&1 || fail 'GNU tar is required (gtar on macOS)'
    release_tar=gtar
    release_tar_version=$(gtar --version)
    [[ $release_tar_version == *'GNU tar'* ]] || fail 'GNU tar is required'
fi
if command -v sha256sum >/dev/null 2>&1; then
    release_checksum=sha256sum
elif command -v shasum >/dev/null 2>&1; then
    release_checksum=shasum
else
    fail 'sha256sum or shasum is required'
fi

release_out=$2
case "$release_out" in
    /*) ;;
    *) release_out=$release_root/$release_out ;;
esac
mkdir -p -- "$release_out"
release_out=$(CDPATH='' cd -- "$release_out" && pwd -P)
case "$release_out/" in
    "$release_root/"*) fail 'OUTDIR must be outside the checkout' ;;
esac
for release_entry in "$release_out"/* "$release_out"/.[!.]* "$release_out"/..?*; do
    [[ ! -e $release_entry && ! -L $release_entry ]] || fail 'OUTDIR must be empty'
done
release_tmp=$(mktemp -d "${TMPDIR:-/tmp}/lb-release.XXXXXX")
release_cleanup() {
    release_exit=$?
    trap - EXIT
    rm -r -- "$release_tmp"
    exit "$release_exit"
}
trap release_cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir "$release_tmp/package"
cp LICENSE README.md "$release_tmp/package/"
cp -R plugins "$release_tmp/package/"
release_pkg=$release_tmp/package
mkdir -p "$release_pkg/integrations/discord" "$release_pkg/docs"
cp integrations/discord/gateway.mjs "$release_pkg/integrations/discord/"
cp docs/org-discord.md "$release_pkg/docs/"
chmod 644 "$release_tmp/package/LICENSE" "$release_tmp/package/README.md"
release_assets=()
for release_platform in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
    release_os=${release_platform%/*}
    release_arch=${release_platform#*/}
    release_asset=laneboss_${release_version}_${release_os}_${release_arch}.tar.gz
    printf 'release: building %s with Go 1.26.0\n' "$release_platform"
    GOTOOLCHAIN=go1.26.0 GOWORK=off GOENV=off GOFLAGS='' GOEXPERIMENT='' \
        CGO_ENABLED=0 GOOS="$release_os" GOARCH="$release_arch" GOAMD64=v1 GOARM64=v8.0 \
        "$release_go" build -buildmode=exe -tags= -trimpath -buildvcs=false -ldflags=-buildid= \
        -o "$release_tmp/package/laneboss" ./cmd/laneboss
    chmod 755 "$release_tmp/package/laneboss"
    TAR_OPTIONS='' "$release_tar" --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
        --mode='a=rX,u+w' --format=ustar -cf - -C "$release_tmp/package" LICENSE README.md laneboss plugins integrations docs \
        | GZIP='' gzip -n -9 > "$release_out/$release_asset"
    release_assets+=("$release_asset")
done
# A tree changed during the builds is not a release candidate.
release_status=$(git status --porcelain --untracked-files=all)
[[ -z $release_status ]] || fail 'working tree changed during the builds; do not publish the output'
(
    cd "$release_out"
    case "$release_checksum" in
        sha256sum) sha256sum "${release_assets[@]}" ;;
        shasum) shasum -a 256 "${release_assets[@]}" ;;
    esac
) > "$release_out/SHA256SUMS"
printf 'release: assets in %s\n' "$release_out"
printf '%s\n' "${release_assets[@]}" SHA256SUMS
