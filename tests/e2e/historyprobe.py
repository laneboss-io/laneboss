"""CLI bridge for installed library APIs whose launcher seams have no public command."""

import json
from pathlib import Path
import sys


def main(library, request_file):
    sys.path.insert(0, library)
    request = json.loads(Path(request_file).read_text(encoding="utf-8"))
    action = request.pop("action")
    if action == "lane-end":
        from laneboss.decisions.lane import lane_end
        result = lane_end(**request)
        print(json.dumps(result))
        return 0 if result["ok"] else 2
    if action == "store":
        from laneboss.decisions.store import Store
        store = Store(**request)
        try:
            print(json.dumps(store.stats()))
        finally:
            store.close()
        return 0
    if action == "log":
        from laneboss.decisions.orgcontext import append_log
        print("ready", flush=True)
        append_log(Path(request["path"]), request["value"])
        print(json.dumps({"logged": request["value"]}))
        return 0
    raise ValueError("unknown probe action")


if __name__ == "__main__":
    raise SystemExit(main(*sys.argv[1:]))
