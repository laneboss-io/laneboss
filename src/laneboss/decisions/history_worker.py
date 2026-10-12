"""Isolated child bootstrap for source checkouts and script-based installations alike."""

from pathlib import Path
import sys


def main(arguments):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    if arguments == ["inject"]:
        from laneboss.decisions.history import worker_main
        return worker_main()
    if arguments[:1] == ["serve"]:
        from laneboss.decisions.cli import main as decisions_main
        return decisions_main(arguments)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
