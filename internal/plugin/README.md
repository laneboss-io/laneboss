The Go locator supports `plugin path`, `--agent claude-code` and help. It returns
one JSON string and changes no launcher state or agent settings. An unknown agent
or malformed command line is refused without repeating the supplied value.

An installed binary in `VERSION/bin/` finds `VERSION/plugins/claude-code`.
Executable symlinks are resolved before locating the version directory.
For a binary built elsewhere, `LANEBOSS_PLUGIN_ROOT` can name an absolute checkout
root or version directory. A missing plugin is refused.

The installer copies the shell plugin and records every file's hash in its manifest.
No shell is used to interpret the selected plugin path.
