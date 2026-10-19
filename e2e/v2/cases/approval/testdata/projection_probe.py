"""Native descriptor test driver; it produces no Laneboss RPC responses."""

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(sys.argv[1])))
from harness import CaseFailure, execute, lane_projection

settings = json.loads(Path(sys.argv[2]).read_bytes())
try:
    binding, descriptors = lane_projection(settings)
    run, observation = execute([settings["binary"], "approval-descriptor-child",
                                str(descriptors[0]), str(descriptors[1]), "8"], pass_fds=descriptors)
    if run.returncode != 0 or observation["timed_out"] or not observation["group_absent"]:
        raise CaseFailure("child did not retain exactly its lane projections")
    print(json.dumps({"refused": False, "target": binding["target"], "child": json.loads(run.stdout)}))
except (CaseFailure, OSError) as error:
    print(json.dumps({"refused": True, "reason": str(error)}))
