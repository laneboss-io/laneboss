"""Exercise the installed Discord APIs with documents from files, without a gateway.

The suite first registers channels through the installed CLI. This probe then
uses the selected Go binary, or that installation's Python library, to read its
roles and convert actual payloads. A selected Go binary never falls back.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("library")
    parser.add_argument("operation", choices=("event", "line", "validate", "read"))
    parser.add_argument("org_dir")
    parser.add_argument("--message")
    parser.add_argument("--channel-names")
    arguments = parser.parse_args()
    binary = os.environ.get("LANEBOSS_ORG_GO_BIN")
    if binary is not None:
        command = [binary, "channel", "_probe", arguments.operation, arguments.org_dir]
        if arguments.message is not None:
            command.extend(["--message", arguments.message])
        if arguments.channel_names is not None:
            command.extend(["--channel-names", arguments.channel_names])
        # Forward output and the actual exit code. A failed Go probe never
        # falls back to the Python library.
        return subprocess.run(command, check=False, timeout=25).returncode
    sys.path.insert(0, arguments.library)
    from laneboss.errors import LauncherError
    from laneboss.orgdiscord import event_json_line, message_to_event, read_roles, validate_org_channels
    try:
        if arguments.operation == "validate":
            failures = validate_org_channels(arguments.org_dir)
            result = {"valid": not failures, "failures": failures}
        else:
            roles = read_roles(arguments.org_dir)
            if arguments.operation == "read":
                result = {name: role.as_dict() for name, role in roles.items()}
            else:
                message = json.loads(Path(arguments.message).read_text(encoding="utf-8"))
                names = (json.loads(Path(arguments.channel_names).read_text(encoding="utf-8"))
                         if arguments.channel_names else None)
                function = event_json_line if arguments.operation == "line" else message_to_event
                result = function(message, roles, channel_names=names)
        print(json.dumps(result, ensure_ascii=True))
        return 0
    except LauncherError as error:
        print(str(error), file=sys.stderr)
        return error.exit_code


if __name__ == "__main__":
    sys.exit(main())
