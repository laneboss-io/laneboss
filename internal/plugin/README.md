The Go locator supports `plugin path`, `--agent claude-code`, and help. It returns
one JSON string and changes no launcher state or agent settings. An unknown agent
or malformed command line is refused without repeating the supplied value.

An installed Go binary in `VERSION/bin/` finds `VERSION/plugins/claude-code`.
An explicitly selected checkout on `PYTHONPATH` finds that checkout's plugin;
the locator only inspects its files and never executes or imports Python.
`LANEBOSS_PLUGIN_ROOT` names either a version directory or a checkout root when
the binary is elsewhere. The forwarding launcher sets it from its own module
location before exec, so an installed launcher always selects its own installed
plugin. A direct Go invocation can explicitly set it. A missing plugin is always
refused, including an installed version that ships no plugins.

The selected root is passed as environment metadata and joined with the plugin
path inside Go. No shell is used to interpret it, so spaces in the prefix survive
unchanged in the JSON path. The locator never executes Python or searches other
installations when the selected root has no plugin.
