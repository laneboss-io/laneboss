"""`laneboss plugin`: where the plugin of an agent program is installed.

scripts/install.sh copies the checkout's plugins/ directory into the version directory next to lib/ and lists its
files in that version's manifest. This module finds the directory from its own place, VERSION/lib/laneboss/ in an
installed version and REPO/src/laneboss/ in a checkout, so that plugins/ lies two directories above in both. It prints
the path and changes nothing: the plugin is added to the agent program with that program's own mechanism
(docs/plugin.md).
"""

import argparse
import os
import sys

from .errors import LauncherError, Refused
from .identity import PROGRAM
from .jsonutil import output

AGENTS = ("claude-code",)


def plugin_directory(agent):
    if agent not in AGENTS:
        # The value is never repeated: a variable that holds the wrong thing could hold a secret.
        raise Refused("unknown agent; the known agents are: {}".format(", ".join(AGENTS)))
    here = os.path.dirname(os.path.realpath(__file__))
    directory = os.path.join(os.path.dirname(os.path.dirname(here)), "plugins", agent)
    if not os.path.isdir(directory):
        raise Refused("the {} plugin is not installed with this launcher ({} does not exist); install the launcher "
                      "with scripts/install.sh from a checkout that has plugins/".format(agent, directory))
    return directory


def build_parser():
    from .cli import ScreeningParser   # the launcher's own parser: a usage error never repeats a typed value
    root = ScreeningParser(prog=PROGRAM + " plugin", description="Locate the plugin that ships with the "
                                   "launcher. Nothing is installed into any agent program.")
    actions = root.add_subparsers(dest="action", metavar="ACTION", required=True)
    path = actions.add_parser("path", help="the directory of the installed plugin, as one JSON value")
    path.add_argument("--agent", default=AGENTS[0], metavar="AGENT",
                      help="the agent program; known: {} (default {})".format(", ".join(AGENTS), AGENTS[0]))
    return root


def main(argv):
    arguments = build_parser().parse_args(argv)
    try:
        sys.stdout.write(output(plugin_directory(arguments.agent)) + "\n")
        sys.stdout.flush()
        return 0
    except LauncherError as error:
        for line in str(error).splitlines() or [""]:
            print("{}: {}".format(error.prefix, line), file=sys.stderr)
        return error.exit_code
