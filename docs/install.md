# Installing Laneboss

Laneboss installs as one Go binary on Linux or macOS, with the Claude Code plugin beside it.
Go is required for the build. The source installer selects **Go 1.26.0** with `GOTOOLCHAIN`;
Go downloads that toolchain and the modules pinned in `go.mod` and `go.sum` if they are not cached.
The installed command needs no language interpreter. Git and tmux are needed for lanes.

With no checkout:

```sh
curl -fsSL https://raw.githubusercontent.com/laneboss-io/laneboss/main/install.sh | sh
```

That command fetches and runs the repository's bootstrap with your rights. The bootstrap gets one source
version with Git, or with curl and tar when Git is unavailable, then invokes its `scripts/install.sh`.
It refuses root and unsupported systems. Read the script before running it if you need to review its source.

The bootstrap defaults to the moving `main` branch and does not verify a checksum or signature of the fetched source.
It runs that source's installer with your rights. This remains a known trust limit; a version tag or local source
selection chooses the input but does not add verification.

From a checkout or unpacked source archive:

```sh
sh scripts/install.sh
export PATH="$HOME/.local/bin:$PATH"
laneboss --version
laneboss plugin path
```

Both routes build `cmd/laneboss` using `go build -tags= -trimpath -buildvcs=false`, with CGO disabled and `GOENV=off`.
Saved Go settings cannot enable test instrumentation in an installation.
A temporary Go installer checks and publishes the binary and plugin files. It is not installed.
Set `LANEBOSS_GO` to choose the Go executable used to obtain the pinned toolchain.
Installation can run offline when that toolchain and all required modules are already cached.

Use `--prefix DIR` to install elsewhere:

```sh
sh scripts/install.sh --prefix "$HOME/tools"
curl -fsSL https://raw.githubusercontent.com/laneboss-io/laneboss/main/install.sh | sh -s -- --prefix "$HOME/tools"
```

For the bootstrap, `LANEBOSS_SOURCE` selects a local source directory or a `.tar`, `.tar.gz` or `.tgz` archive.
Otherwise `LANEBOSS_REPO` selects the repository and `LANEBOSS_VERSION` selects a tag or branch (default `main`).
Use a reviewed tag or commit checkout when an exact source version is required.

## Installed files

```text
PREFIX/
  bin/laneboss -> a relative link into share/laneboss/versions/VERSION, file bin/laneboss
  share/laneboss/versions/VERSION/
    bin/laneboss
    plugins/claude-code/
    MANIFEST
```

`laneboss plugin path` resolves the executable's version directory and prints the plugin directory as one
JSON string. The installer preserves executable plugin scripts as mode 755. Other plugin files have no
executable bit. Nothing is added to an agent program's settings automatically; see [plugin.md](plugin.md).

A version directory is immutable. The manifest records the version and the SHA-256 of every installed file.
Before switching the command link, the installer requires the manifest to match, verifies all hashes and
plugin modes, and refuses missing files, extra files, symlinks or nonregular files. It also refuses to replace
a regular file at `PREFIX/bin/laneboss`. A failed verification leaves that link unchanged.

Installing another version keeps the old directory. To roll back, select an installed version:

```sh
old=VERSION
ln -s "../share/laneboss/versions/$old/bin/laneboss" "$HOME/.local/bin/.laneboss.new"
mv "$HOME/.local/bin/.laneboss.new" "$HOME/.local/bin/laneboss"
```

The old binary must understand the configuration and database formats currently in use. Installing or
switching a version does not migrate configuration or state.
