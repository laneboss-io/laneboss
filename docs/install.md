# Install Laneboss

One command installs the launcher, `laneboss`, for you. It needs no administrator rights and edits no shell file.

## The one line

```sh
curl -fsSL https://raw.githubusercontent.com/laneboss-io/laneboss/main/install.sh | sh
```

The two addresses the line and this page use:

- `https://raw.githubusercontent.com/laneboss-io/laneboss/main/install.sh` is where the file `install.sh` is served as
  plain text, from the `main` branch. GitHub serves the raw files of a repository at another address than the
  repository's own, so this is not the repository's address with `/install.sh` added.
- `https://github.com/laneboss-io/laneboss.git` is the repository's own address, the one `git clone` takes. It is also
  what the line `REPO=...` of `install.sh` holds.

To install from a checkout or an archive instead, see "Where the source comes from" below, or run
`sh scripts/install.sh` in a checkout.

## What it trusts

The script runs what it fetches, with your rights: first that source's own `scripts/install.sh`, then the installed
`laneboss --version`, which is that source's code too. Nothing checks it: there is no checksum, no signature and no
pinned commit. `main` moves, and a tag can be moved. A directory or archive named in `LANEBOSS_SOURCE` is trusted in the
same way, and so is the `install.sh` that `curl` hands to `sh`: it is one file, and it can be read before it is piped.

Unpacking is done by the system's `tar` with no safety options of the script's own, so what happens to an archive with
absolute names, `..` or links is what that `tar` does. Every program is looked up on `PATH` by its bare name, so `PATH`
decides which `git`, `curl`, `tar` and Python run. The program that already stands at `PREFIX/bin/laneboss` is never
started: the script reads where that link points and nothing more.

## What it does, and what it does not do

`install.sh` at the root of the repository is a bootstrap. It gets the source of one version and runs that version's
own `scripts/install.sh`, which does the installing ([Install](architecture.md#install) in the architecture page: a
version directory that never changes, a manifest, and a link `PREFIX/bin/laneboss`). It holds no installer of its own.

It reads its options first. Then it does, in this order:

1. Refuses to run as root, as a user it cannot identify (when `id -u` prints no number), and on any system but macOS and
   Linux (when `uname -s` says another system or nothing).
2. Decides where the source comes from, and refuses an address or a version that it will not use.
3. Finds a Python 3.11 or newer with `sqlite3` and `tomllib`, and the tools of its route.
4. Gets the source: uses the directory you name where it is, or unpacks the archive you name, or clones or fetches the
   repository, into a temporary directory.
5. Runs that version's `scripts/install.sh --prefix PREFIX` with the Python it found in step 3.
6. Runs the installed `laneboss --version` and prints it, says `already installed` when the version did not change,
   prints the one `PATH` line you need when `PREFIX/bin` is not on `PATH`, warns when `tmux` is missing, and names the
   next command.

It does not:

- use `sudo`, or ask for it: it refuses to run as root;
- install Python, `git`, `tmux` or any other program or system package;
- edit `~/.profile`, `~/.zshrc` or any other shell file: it only prints the `PATH` line;
- write anywhere but under the prefix (default `~/.local`) and one temporary directory, which it removes on the exits
  it catches: a normal end, a failure, and the signals HUP, INT, QUIT, PIPE and TERM. It makes the unpacked
  directories writable before it removes them, so that an archive with read-only directories cannot keep them. Any
  other signal, KILL included, and a power cut leave the directory in `TMPDIR`. A directory named in `LANEBOSS_SOURCE`
  is used where it is and is not copied;
- touch Claude Code's settings;
- guess an address: a copy whose `REPO` line holds no address, with neither `LANEBOSS_SOURCE` nor `LANEBOSS_REPO` set,
  stops with one line that says so.

Every command of `install.sh` after its comment header is inside one brace group, and the closing brace is the last
line of the file. A shell reads a whole group before it runs any of it, so a download that stops inside the commands is
a syntax error and runs nothing, and one that stops inside the comment header is only comments and runs nothing. A
download that lacks only the final newline is the whole script.

## What it needs

- macOS or Linux, with `sh` and the ordinary tools `id`, `uname`, `mktemp`, `mkdir`, `chmod` and `rm`. `readlink` is used
  when there is one.
- Python 3.11 or newer with `sqlite3` and `tomllib`. It looks for `python3`, then `python3.14`, `python3.13`,
  `python3.12` and `python3.11` on `PATH`, or uses `LANEBOSS_PYTHON`. It never installs Python. The version's own
  installer is told to use the interpreter that was found, so it does not choose again in its own order.
- `tar`, to unpack an archive or a fetched tarball, and `gzip` for a `.tar.gz`, a `.tgz` or a fetched tarball (GNU `tar`
  runs it).
- To fetch the source from the repository, `git` or `curl`. With `LANEBOSS_SOURCE` neither is needed.
- `tmux` is not needed to install, and a missing one is only a warning: lanes run in tmux sessions, and
  `laneboss doctor` reports it.

When `id`, `uname`, Python, `tar`, `gzip`, or `git` and `curl` are missing, or `id` or `uname` gives no usable answer,
the script stops with one plain line on standard error and exit status 2, before it makes the temporary directory. The
other ordinary tools are not checked: without one of them the shell's own message appears.

## Where the source comes from

In this order:

| Variable | What it is |
|---|---|
| `LANEBOSS_SOURCE` | A directory (a checkout or an unpacked archive), or a `.tar`, `.tar.gz` or `.tgz` file, on this machine. Used first, with no network access: for an air-gapped machine, a private copy, or a test. |
| `LANEBOSS_REPO` | The repository's address. Default: the line `REPO=...` near the top of `install.sh`. With `git` on `PATH` the script runs `git clone --depth 1 --branch VERSION`, so a private repository works with your own git credentials. Without `git`, it fetches the tarball at `ADDRESS/archive/VERSION.tar.gz` with `curl` (the address without a trailing `/` or `.git`), and then the address must be an `https://` or `file://` address. The source is run after it is fetched, so only these addresses are used: `https://`, `ssh://`, the scp form `user@host:path`, `file://` and an absolute path. Every other address is refused with one line: `http://`, `git://`, `ftp://`, an address with `::` anywhere (git runs a helper program for `name::address`), and anything unknown, a bare name or `host:path` without a user included. The clone is run with `GIT_ALLOW_PROTOCOL=file:https:ssh`, which replaces a value from your environment, so that git itself also refuses a redirect from https to http and every helper. `curl` is run with `-g`, so that `[` and `{` in the address are not patterns, with `--proto =https,file`, and with `--proto-redir =https`, so that a redirect may only lead to https. |
| `LANEBOSS_VERSION` | A tag or a branch of the repository, written as the repository writes it, made of letters, digits and `.`, `_`, `/`, `+` and `-` (not starting with `-` and not holding `..`). Default: `main`. No release has been tagged yet, so `main` is the only version there is; once a release is tagged, name it to stay on it. |
| `LANEBOSS_PYTHON` | The interpreter to use, 3.11 or newer. Default: the first that is found, as above. |

The options are `--prefix DIR` or `--prefix=DIR` (default `~/.local`; a leading `~` is the home directory) and
`-h` or `--help`, which prints the usage. When the script is piped, options go after `sh -s --`.

```sh
# From a checkout or an unpacked archive, with no network access:
LANEBOSS_SOURCE=/path/to/laneboss sh install.sh

# From an archive file:
LANEBOSS_SOURCE=/path/to/laneboss.tar.gz sh install.sh

# A tag or a branch of the repository:
curl -fsSL https://raw.githubusercontent.com/laneboss-io/laneboss/main/install.sh | LANEBOSS_VERSION=TAG sh

# A copy of the repository that only you can read, with your own git credentials:
LANEBOSS_REPO=ADDRESS_OF_YOUR_COPY sh install.sh

# Another prefix:
curl -fsSL https://raw.githubusercontent.com/laneboss-io/laneboss/main/install.sh | sh -s -- --prefix "$HOME/opt/laneboss"
```

### What an address gives away

The script never prints what the address holds before its last `@` (a user name, a password), and it prints the rest as
given. That does not hide the address from the machine, and four things stay true:

- The address is an argument of `git` or `curl`, so other users of the machine can read it, password included, in the
  process list while that command runs.
- Git may store it through your credential helper.
- Git and ssh can ask for a password on the terminal even though the script gives them no standard input.
- Their prompts name the user part of the address.

While a clone exists, its configuration file holds the address too, in the private temporary directory. Prefer git's
credential helper or an ssh key to a password in the address.

## After it runs

It prints what was installed, the output of `laneboss --version`, and, when `PREFIX/bin` is not on `PATH`, the line to
add to your shell's startup file (it adds nothing itself):

```text
install: running scripts/install.sh of that source with your rights; nothing checks the source (docs/install.md)
install: installed laneboss VERSION in PREFIX
{"program": "laneboss", "protocol_version": "PROTOCOL", "version": "VERSION"}
install: PREFIX/bin is not on your PATH; add this line to your shell startup file to use laneboss:
export PATH="PREFIX/bin:$PATH"
```

The next command is `laneboss doctor --config NAME`. `doctor` checks one configuration, `git`, `tmux` and the
configuration's runner programs, and a fresh install has no configuration yet: plain `laneboss doctor` is refused with
exit status 2 and says to pass `--config`. Every field of a configuration is in [configuration.md](configuration.md),
and `examples/minimal` in the repository is an invented one to copy.

## With pipx instead

The package also installs with Python's own tools, when you would rather have them manage the command:

```sh
pipx install git+https://github.com/laneboss-io/laneboss.git@<version>
```

`<version>` is a tag or a branch, as for `LANEBOSS_VERSION`. This line has not been run with pipx (see "What is not
proven"). The package has console scripts, so it gives the commands `laneboss` and `laneboss-decisions`, and it differs
from the one-line install in these ways:

- It does not install the Claude Code plugin's files, which are outside the Python package: after a `pip install` in a
  fresh virtual environment, `laneboss plugin path` was refused with a message that says the plugin is not installed
  with this launcher. For the plugin, use the one-line install or `sh scripts/install.sh` in a checkout.
- It keeps no versioned directories and no manifest, so there is no rollback by relink.
- pipx needs the venv module of your Python (the package `python3-venv` on Debian and Ubuntu).
- To move to another version, name it: `pipx install --force
  git+https://github.com/laneboss-io/laneboss.git@<new version>`. That line has not been run either. pipx's `upgrade`
  is not the way: it reinstalls the address the package was first given, so an install that names a tag stays on that
  tag.

## Upgrade

Run the same line again. The source's version decides what happens:

- The same version as the installed one: the installed files are checked against the version's manifest, the link is
  kept where it is, and the script says `already installed`. A file that was changed, removed or added in the
  installed copy is refused with exit status 2 and the link stays where it was.
- Another version: it is installed next to the old one and the link moves. The old version's directory stays, so a
  rollback is a relink ([Install](architecture.md#install)).

The version that was installed before is read from the link at `PREFIX/bin/laneboss`, not by running what is there.

`LANEBOSS_VERSION=main` is the tip of the branch. When the branch changes without a new version number, an installed
version of the same number is not replaced: the installer refuses, names the version, and says to give new content a new
version or to remove the old version directory by hand (`PREFIX/share/laneboss/versions/VERSION`).

## Uninstall

`scripts/install.sh` writes two things under the prefix and nothing else:

- `PREFIX/bin/laneboss`, a link into a version directory;
- `PREFIX/share/laneboss/`, which holds `versions/VERSION/` for every version that was installed (the package, the
  plugin files, the manifest and the launcher).

To remove them, with the default prefix:

```sh
rm "$HOME/.local/bin/laneboss"
rm -r "$HOME/.local/share/laneboss"
```

Your configurations (`~/.config/laneboss`) and the state that lanes and events keep (`~/.local/state/laneboss`) are yours:
the installer never wrote there, and removing the program does not remove them. Delete them only to throw that data
away.

## The Claude Code plugin

The installer puts the plugin's files next to the launcher, and `laneboss plugin path` says where they are. Adding the
plugin to Claude Code is a separate step with Claude Code's own commands; [docs/plugin.md](plugin.md#add-the-plugin-to-claude-code)
states it, and this page does not repeat it.

## What is not proven

- A real `curl ... | sh` from the public address has not been run. The tests run the
  script from a file and piped on standard input, with `LANEBOSS_SOURCE`, with a repository and a tarball that live
  on the same machine, and cut at every byte of every command that is not in the function.
- The pipx line was proved with pip, not with pipx: on the test machine pipx could not make its own environment,
  because that machine's Python has no venv module and a test run may not install system packages. What ran there,
  in a fresh virtual environment, was `pip install` of a copy of this source from a local path, and `pip install
  git+ADDRESS@TAG` with a `file://` address and a tag; pipx hands the same argument to pip. Nothing that this page says
  about pipx's own commands (`install --force`, `upgrade`, its environment) was run.
- The tests were run on Linux only so far; the script uses POSIX `sh` and the tools of macOS and Linux alike. BusyBox
  was not tried at all.
- The messages of `git`, `curl` and `ssh` for a failed fetch were not run with a password in the address; the tests
  check only what the script itself prints.
