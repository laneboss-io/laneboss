"""Vendor file regressions; run only on the disposable Linux root box."""

import importlib.util
import os
from pathlib import Path
import resource
import shutil
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("provision", Path(__file__).with_name("provision.py"))
provision = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provision)


class VendorFiles(unittest.TestCase):
    def test_boot_enrolls_dependencies(self):
        class Assembled(Exception):
            """Stop after the real runtime assembly, before installation."""

        with tempfile.TemporaryDirectory(prefix="lb-runtime-", dir="/opt") as temporary:
            output = Path(temporary)
            binary = Path("/usr/bin/dash").resolve(strict=True)
            pin = provision.digest(binary)
            vendor = {name: {"path": binary, "executable": {"id": name, "sha256": pin}}
                      for name in ("claudock", "claude")}
            agent = {"path": binary, "sha256": pin, "program": "dynamic-fixture", "version": "fixture"}
            socket = provision.socket.socket

            def reservation(*args, **kwargs):
                result = socket(*args, **kwargs)
                self.addCleanup(result.close)
                return result

            def assembled(inputs, objects, boot_input, *_args, **_kwargs):
                self.addCleanup(shutil.rmtree, inputs)
                runtime = provision.document(Path(boot_input["runtime_file"]).read_bytes())
                dependencies = [row for row in runtime["objects"] if row["role"] == "runtime-interpreter"]
                self.assertTrue(dependencies, "serve boot omitted the executable's ELF interpreter")
                graph = provision.document((objects / "runtime-links.json").read_bytes())
                for name in ("claudock", "claude"):
                    row = next(row for row in graph["files"] if row["path"] == "/runtime/" + name)
                    self.assertTrue(row["interpreter"] and row["needed"],
                                    "serve boot did not record actual ELF linkage")
                    self.assertEqual(row["sha256"], pin)
                for item in runtime["objects"]:
                    path = objects / item["relative_path"]
                    self.assertEqual(provision.digest(path), item["content"]["sha256"])
                    self.assertEqual(path.stat().st_size, item["content"]["bytes"])
                    self.assertEqual(path.stat().st_mode & 0o777, item["mode"])
                raise Assembled()

            with patch.object(provision.socket, "socket", side_effect=reservation), \
                    patch.object(provision, "fixture_initial", side_effect=assembled), self.assertRaises(Assembled):
                provision.boot(binary, {"version": "fixture"}, "fixture", output, agent,
                               "runtime-fixture", "challenge", mode="lifecycle", real_vendor=vendor)

    def test_retained_vendor(self):
        with tempfile.TemporaryDirectory(prefix="lb-vendor-", dir="/opt") as temporary:
            root = Path(temporary)
            output = root / "output"
            output.mkdir()

            def command(label, argv, **kwargs):
                if label == "real-build":
                    path = Path(argv[argv.index("-o") + 1])
                    with path.open("wb") as stream:
                        stream.truncate(65 << 20)
                elif label == "claude-installer":
                    Path(argv[argv.index("--output") + 1]).write_bytes(b"installer input")
                elif label == "claude-install":
                    path = root / "home/.local/bin/claude"
                    path.parent.mkdir(parents=True)
                    with path.open("wb") as stream:
                        stream.truncate(65 << 20)
                return {"real-revision": b"public-revision\n", "real-version": b"0.1.0\n",
                        "claude-version": b"2.1.296\n"}.get(label, b"")

            with patch.object(provision, "evidence_root", return_value=root):
                result = provision.real_claudock(output, command)
            for name in ("claudock", "claude"):
                retained = output / (name + ".input")
                self.assertEqual(retained.stat().st_size, 65 << 20)
                self.assertEqual(provision.digest(retained), result[name]["executable"]["sha256"])
                self.assertEqual(os.stat(result[name]["path"]).st_mode & 0o777, 0o555)
                boot = provision._admin_boot
                ref = {"id": name, "class": "artifact", "bytes": 65 << 20,
                       "sha256": result[name]["executable"]["sha256"]}
                item = {"id": name, "role": name, "relative_path": name, "mode": 0o555, "content": ref}
                source = Path(result[name]["path"])
                self.assertEqual(boot.vendor_file(item, source), source)
                installed = root / (name + "-installed")
                boot.publish_vendor(installed, source, ref)
                self.assertEqual(boot.stream_file(installed, boot.MAX_VENDOR, mode=0o555),
                                 (ref["bytes"], ref["sha256"]))
                boot.publish_vendor(installed, source, ref)  # Exact retry preserves bytes.
                with self.assertRaises(boot.Stopped):
                    boot.read(source, boot.MAX_OBJECT)
                source.chmod(0o755)
                with self.assertRaises(boot.Stopped):
                    boot.vendor_file(item, source)
                source.chmod(0o555)
                with source.open("r+b") as stream:
                    stream.write(b"\x01")
                with self.assertRaises(boot.Stopped):
                    boot.vendor_file(item, source)
                with self.assertRaises(boot.Stopped):
                    boot.publish_vendor(installed, source, {**ref, "sha256": "0" * 64})
                with source.open("r+b") as stream:
                    stream.truncate((512 << 20) + 1)
                with self.assertRaises(boot.Stopped):
                    boot.vendor_file({**item, "content": {**ref, "bytes": (512 << 20) + 1}}, source)


if __name__ == "__main__":
    # A whole 65 MiB allocation cannot fit; all vendor stages must stream.
    resource.setrlimit(resource.RLIMIT_AS, (64 << 20, 64 << 20))
    unittest.main()
