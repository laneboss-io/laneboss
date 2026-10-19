"""Export actual grants flow inputs for the Linux dispatcher regression."""

import json
from pathlib import Path
import sys
import uuid

from boot_bundle_input import BootFixture, GRANTS


case = BootFixture(Path(sys.argv[2]))
mode = sys.argv[1]
if mode == "plan":
    value = GRANTS.uploads.plan(case.root)
elif mode == "stage":
    metadata = json.loads(Path(sys.argv[3]).read_bytes())
    case.config = metadata["config"]
    value = GRANTS.sealed_canary(case, Path(metadata["sealer"]), metadata["key"],
                               "grants-dispatch-" + uuid.uuid4().hex[:12], "v1")
elif mode == "import":
    staged = json.loads(Path(sys.argv[3]).read_bytes())
    value = GRANTS.secret_import_input(staged["name"], staged["version"], staged)
else:
    raise ValueError("unknown dispatcher input export")
raw = GRANTS.io.encoded(value)
case.keep(mode + ".request.json", raw)
sys.stdout.buffer.write(raw)
