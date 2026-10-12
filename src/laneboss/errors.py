"""Errors and the exit codes they map to.

0 success; 1 a doctor check failed; 2 invalid input or a refused request; 3 an integrity problem;
70 an unexpected internal error.
"""


class LauncherError(Exception):
    exit_code = 70
    prefix = "internal error"


class Refused(LauncherError):
    """Invalid input, a refused binding, path or credential, or a missing brief section."""

    exit_code = 2
    prefix = "refused"


class InvalidConfiguration(Refused):
    prefix = "invalid configuration"


class IntegrityProblem(LauncherError):
    """Stored data does not match its hashes, schema or owner, or an id was reused with other content."""

    exit_code = 3
    prefix = "integrity problem"
