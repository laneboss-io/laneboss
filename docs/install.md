# Installing Laneboss

Install Laneboss and claudock-cli on Linux or macOS, for amd64 or arm64:

```sh
curl -fsSL https://raw.githubusercontent.com/laneboss-io/laneboss/main/install.sh | sh
```

No Go toolchain or language interpreter is needed for a release install. The bootstrap requires a POSIX
shell, curl, tar, gzip, awk and either `sha256sum` or `shasum`. Git and tmux are needed to run lanes,
and `laneboss doctor --config NAME` checks them. The installer refuses root and unsupported systems.

The bootstrap resolves GitHub's `releases/latest` redirect to a version tag without an API token.
It downloads `laneboss_VERSION_OS_ARCH.tar.gz` and `SHA256SUMS` from
`https://github.com/laneboss-io/laneboss` at `/releases/download/vVERSION/`.
The archive contains `laneboss`, `LICENSE`, `README.md`, `plugins/`, the Discord
gateway at `integrations/discord/gateway.mjs` and its guide at `docs/org-discord.md`.
Exactly one valid checksum entry must name that archive. The bootstrap compares the downloaded
archive's SHA-256 before extraction or execution. A failed download, missing checksum tool, missing
or duplicate checksum entry, malformed digest or mismatch stops installation. It never falls back
to a source build. The verified binary checks its compiled version against the selected release
name before publishing any installed files.

After Laneboss finishes installing, the bootstrap downloads claudock-cli `0.1.0` for the same OS
and architecture. It fetches `claudock_0.1.0_OS_ARCH.tar.gz` and `SHA256SUMS` from
`https://github.com/laneboss-io/claudock-cli` at `/releases/download/v0.1.0/`.
That archive contains `claudock`, LICENSE and README. Both programs use the same archive verifier,
including the mandatory SHA-256 comparison before extraction or execution.
The verified claudock binary must report the pinned version through `claudock version` before it is
copied, made executable and atomically renamed into `PREFIX/bin/claudock`.
This follows a completed Laneboss install. A claudock download, checksum, version or publication
failure exits nonzero and leaves Laneboss fully installed; it does not claim the combined install succeeded.

Codex-only users can skip the entire companion step, including its version check and downloads:

```sh
curl -fsSL https://raw.githubusercontent.com/laneboss-io/laneboss/main/install.sh | sh -s -- --without-claudock
```

If claudock on PATH already reports the pinned version, the bootstrap says so and keeps it.
It also recognizes a matching executable already in the selected prefix when it is absent from PATH.
A different or unreadable existing version is kept by default, with a clear message and exit 0 for
the completed Laneboss part. Pass `--upgrade-claudock` to install the pinned version in the selected
prefix. Put that prefix's `bin` first on PATH when an older copy is installed elsewhere.
The installer creates no profiles and performs no authentication. For Claude, the recommended setup
is [claudock profiles and the claudock runner](getting-started.md#use-claudock-cli-for-a-real-agent);
the guide also documents direct `claude` and `codex` runners.

To choose a version or a different prefix:

```sh
curl -fsSL https://raw.githubusercontent.com/laneboss-io/laneboss/main/install.sh | sh -s -- --version 0.7.0
curl -fsSL https://raw.githubusercontent.com/laneboss-io/laneboss/main/install.sh | sh -s -- --prefix "$HOME/tools"
```

`LANEBOSS_VERSION` also selects a release version (with or without a leading `v`).
`--version` takes precedence over that variable. Without either, the latest released version is used.

The bootstrap script itself comes from the moving `main` branch over HTTPS and runs with your rights.
Review it before executing it when you need to audit that input. The archive and checksums come from
the same release over HTTPS: they detect corruption or a mismatched asset, but they are not a
signature or independent proof of publisher identity. A compromised release publisher could replace
both. The installer never uses sudo and never changes agent settings automatically.

## Build from source

Keep the source route explicit:

```sh
curl -fsSL https://raw.githubusercontent.com/laneboss-io/laneboss/main/install.sh | sh -s -- --from-source
```

From a checkout or unpacked source archive:

```sh
LANEBOSS_SOURCE=. sh ./install.sh --from-source
export PATH="$HOME/.local/bin:$PATH"
laneboss --version
laneboss plugin path
```

These routes need Go on PATH. The source installer selects **Go 1.26.0** with `GOTOOLCHAIN`.
Go downloads that toolchain and the modules pinned in `go.mod` and `go.sum` if they are not cached.
It builds `cmd/laneboss` with `-buildmode=exe -tags= -trimpath -buildvcs=false -ldflags=-buildid=`,
CGO disabled, and saved Go settings, flags and experiments disabled. These are also the release
binary's build settings. A temporary Go helper publishes the result using the same installer
implementation as the released binary; the helper is not installed.

With `--from-source`, `LANEBOSS_SOURCE` selects a local directory or a `.tar`, `.tar.gz` or `.tgz`
source archive. Otherwise `LANEBOSS_REPO` selects the repository and `LANEBOSS_VERSION` (or
`--version`) selects a tag or branch, defaulting to `main`. The bootstrap clones with Git, or
downloads a tarball with curl when Git is unavailable, and runs that source's `scripts/install.sh`.
It does not verify the fetched source against release checksums. Use a reviewed tag or commit checkout
when an exact input is required. Source selection variables require `--from-source`.
`LANEBOSS_GO` selects the Go executable used to obtain the pinned toolchain.
The lower-level `sh scripts/install.sh` installs only Laneboss and can run offline when the toolchain
and modules are cached. The root bootstrap also installs released claudock-cli with `--from-source`,
unless `--without-claudock` is passed or a matching executable is already present.

Both the bootstrap and `scripts/install.sh` accept `--prefix DIR`.

## Installed files

```text
PREFIX/
  bin/laneboss -> a relative link into share/laneboss/versions/VERSION, file bin/laneboss
  bin/claudock (verified companion binary, unless skipped or already available on PATH)
  share/laneboss/versions/VERSION/
    bin/laneboss
    plugins/claude-code/
    integrations/discord/gateway.mjs
    docs/org-discord.md
    MANIFEST
```

The default prefix is `~/.local`. `laneboss plugin path` resolves the executable's version directory
and prints the plugin directory as one JSON string. Executable plugin scripts have mode 755;
other plugin files have no executable bit. See [plugin.md](plugin.md) to add the plugin to an agent.

A version directory is immutable. The manifest records the version and SHA-256 of every installed file.
Before switching the command link, both installation routes require the manifest to match, verify all
hashes and plugin modes, and refuse missing files, extra files, symlinks or nonregular files.
They also refuse to replace a regular file at `PREFIX/bin/laneboss`.
A failed verification leaves that link unchanged.

Installing another version keeps the old directory. To roll back, select an installed version:

```sh
old=VERSION
ln -s "../share/laneboss/versions/$old/bin/laneboss" "$HOME/.local/bin/.laneboss.new"
mv "$HOME/.local/bin/.laneboss.new" "$HOME/.local/bin/laneboss"
```

The old binary must understand the configuration and database formats currently in use.
Installing or switching a version does not migrate configuration or state.

## Build release assets

From a clean checkout, with the intended version already committed:

```sh
scripts/release.sh 0.7.0 /tmp/out
```

Usage is `scripts/release.sh VERSION OUTDIR`. VERSION must exactly equal `identity.Version`,
without a `v` prefix. OUTDIR must be empty and outside the checkout. The script refuses a dirty
tree, including untracked files, and rechecks it after building.
It needs Go, Bash, GNU tar (`gtar` on macOS), gzip and a SHA-256 tool.
It cross-compiles Linux and macOS binaries for amd64 and arm64 using Go 1.26.0 with CGO disabled,
trimmed paths, no VCS metadata and an empty build ID. Archive entries are sorted with fixed timestamps,
ownership and modes; gzip omits its timestamp and original filename.

The output is four `laneboss_VERSION_OS_ARCH.tar.gz` archives and `SHA256SUMS`, which names those
four assets. The script prints the filenames; it creates no Git tag, GitHub release or upload.
Publishing those files under the matching `vVERSION` release is a separate maintainer operation.

## Verify a release on a disposable box

Copy the built `/tmp/out` directory and this revision's reviewed `install.sh` to an unprivileged
fresh box. For the default combined install, place the claudock `0.1.0` release archives in the
same `/tmp/out` directory. Append claudock's official SHA256SUMS entries to Laneboss's SHA256SUMS
once, preserving the supplied checksums; every asset must have exactly one entry in the combined file.
Start with neither claudock on PATH nor either test prefix below already present.
Start a loopback file server in one terminal (Python is needed only for this test server):

```sh
python3 -m http.server 8000 --bind 127.0.0.1 --directory /tmp/out
```

In another terminal, from the directory containing the reviewed bootstrap:

```sh
LANEBOSS_RELEASE_BASE_URL=http://127.0.0.1:8000 sh ./install.sh --version 0.7.0 --prefix "$HOME/laneboss-both"
"$HOME/laneboss-both/bin/laneboss" --version
"$HOME/laneboss-both/bin/laneboss" plugin path
"$HOME/laneboss-both/bin/claudock" version
```

Check the Codex-only route with a second unused prefix:

```sh
LANEBOSS_RELEASE_BASE_URL=http://127.0.0.1:8000 sh ./install.sh --version 0.7.0 --without-claudock --prefix "$HOME/laneboss-only"
"$HOME/laneboss-only/bin/laneboss" --version
test ! -e "$HOME/laneboss-only/bin/claudock"
test ! -L "$HOME/laneboss-only/bin/claudock"
```

`LANEBOSS_RELEASE_BASE_URL` is honored only when explicitly set and requires an explicit release
version for a Laneboss release install. It is the exact directory containing both projects' archives
and the combined `SHA256SUMS`, with no version path
appended. HTTPS is accepted; HTTP is limited to an explicit loopback server with a port.
It changes the download location for both programs and retains all checksum and version checks.
With `--from-source`, it applies only to the released claudock companion. Expect Laneboss version
`0.7.0`, protocol `1.3.0`, a plugin path inside the selected version directory, and claudock version
`0.1.0` for the combined install. Repeat installation to check Laneboss's immutable-version handling
and the already-installed claudock path. Existing-version preservation, explicit upgrade and failure
cases still require separate box checks.
Build and installer execution on these boxes are required runtime evidence; static checks alone
do not establish that release installation works.
