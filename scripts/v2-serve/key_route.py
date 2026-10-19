"""Fake-only flag sources for private descriptor tests; never stdout or argv."""

import argparse
import importlib.util
import os
from pathlib import Path
import struct
import tempfile


spec = importlib.util.spec_from_file_location("key_route_serve", Path(__file__).with_name("run.py"))
serve = importlib.util.module_from_spec(spec)
spec.loader.exec_module(serve)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--both", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="lb-key-route-") as directory:
        root = Path(directory)
        modes = (False, True) if args.both else (False,)
        with os.fdopen(3, "wb") as output:
            for file_mode in modes:
                evidence = root / ("file" if file_mode else "fake")
                evidence.mkdir(mode=0o700)
                options = {"canary_api_key": True}
                if file_mode:
                    if os.geteuid() != 0:
                        raise ValueError("file route fixture requires the root test box")
                    path = root / "source"
                    material = b"sk-ant-api03-" + os.urandom(32).hex().encode("ascii")
                    path.write_bytes(material + b"\n")
                    path.chmod(0o400)
                    options = {"real_api_key_file": path}
                case = serve.Case(root, evidence, config="key-route", real_claudock=True,
                                  egress_anthropic=True, **options)
                source = case.api_key_canary
                if source is None or case.real_api_key != file_mode or source.real != file_mode:
                    raise ValueError("flag route did not select its declared source")
                if file_mode and (path.exists() or source.key != material):
                    raise ValueError("file route did not consume the exact selected source bytes")
                output.write(struct.pack("!I", len(source.key)))
                output.write(source.key)


if __name__ == "__main__":
    main()
