# Umask-independent private fixtures

All admin test temporary roots now use privateTestDir, which explicitly sets
mode 0700 after creation. This includes the retained gate storage/journal roots,
spools, source and data fixtures, recovery records, private descriptor cases
and installed work roots. Existing ownership changes and deliberate bad-mode
controls remain. The shared helper does not change the process umask.

The nested data-return baseline explicitly sets the compared directory mode.
TestFixtureUmask022 changes umask only for its own nonparallel fixture run and
restores the previous value with defer. It constructs the real retained gate
fixture, verifies ready private storage and the journal parent, reconciles the
prepared gate and requires that the real canary remains closed.

The new control changes only the test helper's mode to 0755 and requires the
existing production private-parent integrity refusal in that named regression.
No production source, integrity check or TestMain is changed. The ordinary
whole-tree Linux unit run and runtime red/candidate result remain required;
this authoring session is limited to static checks on the Mac.
