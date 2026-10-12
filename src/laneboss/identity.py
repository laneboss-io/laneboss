"""The launcher's name and version, kept in one place so the project can be renamed."""

PROGRAM = "laneboss"
ENV_PREFIX = "LANEBOSS_"
VERSION = "0.6.0-dev4"


def env_name(suffix):
    """Return the environment variable name for a setting, for example HOME -> LANEBOSS_HOME."""
    return ENV_PREFIX + suffix
