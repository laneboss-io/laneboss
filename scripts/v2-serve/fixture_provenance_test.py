"""Fixture build-input regressions; execute only on the disposable Linux host."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import tarfile
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("provision", Path(__file__).with_name("provision.py"))
provision = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provision)


class FixtureProvenance(unittest.TestCase):
    def test_static_runtime_builds(self):
        spec = importlib.util.spec_from_file_location("serve_builds", Path(__file__).with_name("run.py"))
        serve = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(serve)
        with tempfile.TemporaryDirectory(prefix="lb-v2-case-policy-build-") as directory:
            case = serve.Case(Path(__file__).resolve().parents[2], Path(directory), config="static-build")
            case.stage = provision.stage(case.source, case.root)
            try:
                case.command("vendor", ["go", "mod", "vendor"], seconds=900)
                original = case.command
                builds = {}
                def checked(name, argv, **options):
                    if argv[:2] == ["go", "build"]:
                        builds[name] = (list(argv), dict(options))
                        selected = (options.get("environment") or {}).get("CGO_ENABLED") == "0"
                        self.assertTrue(selected, name + " has no explicit static build policy")
                    return original(name, argv, **options)
                case.command = checked
                with mock.patch.dict(os.environ, {"CGO_ENABLED": "1"}):
                    binary, _ = case.build_artifact()
                    self.assert_static_elf(binary)
                    fixture = case.build_fixture("./cmd/laneboss/serve-fixture")
                    self.assert_static_elf(fixture)
                    authenticator = case.build_authenticator()
                    self.assert_static_elf(authenticator)
                    bundle = case.build_bundle()
                    self.assert_static_elf(bundle)
                    # Change only the real artifact's output path and cgo
                    # selection. This control must retain the missing-loader
                    # defect rather than passing a reader that accepts all ELF.
                    argv, options = builds["build"]
                    dynamic = case.stage / "dynamic-control"
                    argv[argv.index("-o") + 1] = str(dynamic)
                    options["environment"] = dict(options["environment"], CGO_ENABLED="1")
                    original("dynamic-control", argv, **options)
                    dynamic.chmod(0o555)
                    with self.assertRaisesRegex(AssertionError, "dynamic segment or interpreter"):
                        self.assert_static_elf(dynamic)
            finally:
                shutil.rmtree(case.stage)

    def assert_static_elf(self, path):
        raw = path.read_bytes()
        self.assertGreater(len(raw), 64)
        self.assertEqual(raw[:4], b"\x7fELF")
        self.assertIn(raw[4], (1, 2))
        self.assertIn(raw[5], (1, 2))
        order = "<" if raw[5] == 1 else ">"
        wide = raw[4] == 2
        offset = struct.unpack_from(order + ("Q" if wide else "I"), raw, 32 if wide else 28)[0]
        size, count = struct.unpack_from(order + "HH", raw, 54 if wide else 42)
        self.assertGreaterEqual(size, 4)
        self.assertGreater(count, 0)
        self.assertLessEqual(offset + size * count, len(raw))
        types = {struct.unpack_from(order + "I", raw, offset + index * size)[0] for index in range(count)}
        self.assertFalse(types & {2, 3}, path.name + " retains an ELF dynamic segment or interpreter")
        self.assertEqual(path.stat().st_mode & 0o777, 0o555)

    def test_fixture_accounts(self):
        value = provision.fixture_accounts("e2e-serve")
        self.assertEqual(value["run"], provision.sha(b"e2e-serve")[:8])
        self.assertEqual(value["group"]["name"], "lbrpc" + value["run"])
        self.assertEqual([row["name"] for row in value["users"]],
                         ["lbsvc" + value["run"], "lbop" + value["run"], "lblane" + value["run"]])
        with self.assertRaisesRegex(ValueError, "fixture account configuration is invalid"):
            provision.fixture_accounts("bad/config")

    def inputs(self):
        temporary = tempfile.TemporaryDirectory(prefix="lb-v2-serve2-provenance-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        source, output = root / "module", root / "evidence"
        output.mkdir()
        values = {"go.mod": b"module fixture.example/main\n", "go.sum": b"retained dependency checksums\n",
                  "cmd/laneboss/serve-fixture/main.go": b"package main\nfunc main() {}\n",
                  "internal/v2/client/client.go": b"package client\n",
                  "internal/v2/client/client_test.go": b"package client\n// unselected test\n",
                  "vendor/modules.txt": b"# fixture.example/dependency v1.0.0\n",
                  "vendor/fixture.example/dependency/dependency.go": b"package dependency\n"}
        rows = []
        for name, data in values.items():
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            if not name.startswith("vendor/"):
                rows.append({"path": name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
        (output / "source-files.json").write_text(json.dumps(rows))
        (output / "vendor-manifest.input").write_bytes(values["vendor/modules.txt"])
        with tarfile.open(output / "dependencies.tar", "w") as archive:
            archive.add(source / "vendor", arcname="vendor")
        packages = [
            {"Standard": True, "Dir": "/unread-standard-library", "GoFiles": ["standard.go"]},
            {"Dir": str(source / "cmd/laneboss/serve-fixture"), "GoFiles": ["main.go"]},
            {"Dir": str(source / "internal/v2/client"), "GoFiles": ["client.go"]},
            {"Dir": str(source / "vendor/fixture.example/dependency"), "GoFiles": ["dependency.go"]},
        ]
        package_bytes = b"\n".join(json.dumps(row).encode() for row in packages)
        return source, output, package_bytes, values

    def test_actual_inputs(self):
        source, output, packages, values = self.inputs()
        provision.fixture_source(source, output, packages)
        rows = json.loads((output / "fixture-source-files.json").read_bytes())
        expected = [{"path": name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
                    for name, data in values.items() if not name.endswith("_test.go") and name != "vendor/modules.txt"]
        self.assertEqual(rows, sorted(expected, key=lambda row: row["path"]),
                         "acceptance: fixture provenance differs from actual module inputs")
        provenance = json.loads((output / "fixture-build-inputs.json").read_bytes())
        self.assertEqual(provenance["vendor_manifest_sha256"], hashlib.sha256(values["vendor/modules.txt"]).hexdigest())
        self.assertEqual(provenance["source_manifest_sha256"], hashlib.sha256((output / "source-files.json").read_bytes()).hexdigest())
        self.assertEqual(provenance["package_selection_sha256"], hashlib.sha256(packages).hexdigest())
        self.assertFalse((output / "fixture-source.tar").exists(), "unused isolated fixture source is still recorded")

    def test_changed_source(self):
        source, output, packages, _ = self.inputs()
        (source / "internal/v2/client/client.go").write_bytes(b"package changed\n")
        with self.assertRaisesRegex(ValueError, "fixture build source differs from retained inventory"):
            provision.fixture_source(source, output, packages)
        self.assertFalse((output / "fixture-source-files.json").exists())

    def test_changed_vendor(self):
        for name, reason in (("vendor/modules.txt", "fixture build vendor manifest differs"),
                             ("vendor/fixture.example/dependency/dependency.go", "fixture build dependency differs")):
            with self.subTest(input=name):
                source, output, packages, _ = self.inputs()
                (source / name).write_bytes(b"changed dependency input\n")
                with self.assertRaisesRegex(ValueError, reason):
                    provision.fixture_source(source, output, packages)
                self.assertFalse((output / "fixture-source-files.json").exists())

    def test_harness_archive(self):
        source, output, _, _ = self.inputs()
        harness = source / "scripts/v2-serve"
        harness.mkdir(parents=True)
        values = {"README": b"harness inputs\n", "authenticator.mod": b"module authenticator\n",
                  "run.py": b"# retained harness\n", "native_cleanup_control.py": b"# retained native control\n",
                  "fixture_provenance_test.py": b"# retained harness regression\n"}
        for name, data in values.items():
            (harness / name).write_bytes(data)
        provision.archive_harness(harness, output)
        with tarfile.open(output / "harness.tar", "r") as archive:
            self.assertEqual(set(archive.getnames()), set(values) | {"serve-fixture/main.go"},
                             "acceptance: harness archive lost a native control or unit test")
            for name, data in values.items():
                self.assertEqual(archive.extractfile(name).read(), data)


if __name__ == "__main__":
    unittest.main()
