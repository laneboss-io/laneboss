"""Parser and output for the org commands; independent of launcher bindings."""

import sys

from . import org
from .jsonutil import output


def register(commands):
    root = commands.add_parser("org", help="initialize, render and validate an org in one folder")
    register_actions(root.add_subparsers(dest="action", metavar="ACTION", required=True))


ACTIONS = ("init", "instance", "render", "validate")


def register_actions(actions):
    init = actions.add_parser("init", help="create an org tree with generic protocol sources and example instances")
    init.add_argument("org_dir", metavar="ORG_DIR")
    init.add_argument("--levels", default="3-6", metavar="LEVELS", help="levels in 3-6: a range or comma list (default 3-6)")
    init.add_argument("--name", metavar="NAME", help="a simple org name; default the folder name")
    instance = actions.add_parser("instance", help="manage an agent instance")
    instances = instance.add_subparsers(dest="instance_action", metavar="ACTION", required=True)
    add = instances.add_parser("add", help="add an instance that receives its own level's rules")
    add.add_argument("org_dir", metavar="ORG_DIR")
    add.add_argument("name")
    add.add_argument("--level", required=True, type=int, choices=(3, 4, 5, 6), metavar="N")
    add.add_argument("--role", required=True, metavar="ROLE")
    add.add_argument("--discord-channel", metavar="ID", help="a numeric channel id, never a webhook URL")
    add.add_argument("--secret", action="append", default=[], metavar="NAME", help="a secret name; may be repeated")
    render = actions.add_parser("render", help="regenerate all rules; refuse hand edits to generated files")
    render.add_argument("org_dir", metavar="ORG_DIR")
    validate = actions.add_parser("validate", help="check the tree, schemas, imports and absence of secret values")
    validate.add_argument("org_dir", metavar="ORG_DIR")
    validate.add_argument("--format", choices=("text", "json"), default="text", help="diagnostic format (default text)")


def run(arguments):
    if arguments.action == "validate":
        report = org.validate(arguments.org_dir)
        if arguments.format == "json":
            sys.stdout.write(output(report) + "\n")
        elif report["valid"]:
            sys.stdout.write("org is valid\n")
        else:
            for item in report["problems"]:
                sys.stderr.write("{}: {}\n".format(item["path"], item["message"]))
        return 0 if report["valid"] else 2
    if arguments.action == "init":
        result = org.init(arguments.org_dir, arguments.levels, arguments.name)
    elif arguments.action == "render":
        result = org.render(arguments.org_dir)
    else:
        result = org.instance_add(arguments.org_dir, arguments.name, arguments.level, arguments.role,
                                  arguments.discord_channel, arguments.secret)
    sys.stdout.write(output(result) + "\n")
    return 0
