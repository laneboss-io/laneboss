"""Exercise provision's full input path without opening files or installing."""

from contextlib import ExitStack
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location("boot", Path(__file__).with_name("boot.py"))
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)


class InputsDone(Exception):
    """The real provision function reached the end of input validation."""


def reference(name, kind, raw):
    return {"id": name, "class": kind, "bytes": len(raw), "sha256": boot.sha(raw)}


class ProvisionInputs(unittest.TestCase):
    def test_both_enrollments(self):
        args = SimpleNamespace(config="input-test", binary="/fixture/binary",
                               manifest="/fixture/release", boot="/fixture/boot")
        binary = b"provision input binary fixture\n"
        executable = {"id": "fixture-bin", "sha256": boot.sha(binary), "version": "0.0.0"}
        runtime = {
            "schema": "laneboss.runtime.v2", "generation": 1, "bindings": [],
            "artifact": executable, "bootstrap": executable,
            "objects": [{"id": "fixture-bin", "role": "bootstrap", "root_id": "runtime",
                         "relative_path": "program", "mode": 0o555,
                         "content": reference("fixture-bin", "artifact", binary)}],
        }
        runtime_raw = boot.encoded(runtime)
        runtime_ref = reference("runtime", "manifest", runtime_raw)
        project_ref = reference("tree", "manifest", b"{}")
        launch = {
            "schema": "laneboss.launch-enrollment.v2", "config": args.config, "generation": 1,
            "projects": [{"id": "project", "project_id": "fixture", "generation": 1,
                          "object": project_ref, "base": project_ref["sha256"], "history_scope": "tree"}],
            "runtimes": [{"enrollment_id": "runner", "generation": 1, "driver": "codex",
                          "backend": "linux-bwrap-landlock", "executable": executable,
                          "manifest": runtime_ref}],
        }
        launch_raw = boot.encoded(launch)
        admin = {"origin": "https://enroll.example", "rp_id": "enroll.example"}
        inputs = {
            "schema": "laneboss.boot-input.v2", "runtime_manifest": runtime_ref,
            "runtime_file": "/fixture/runtime", "runtime_roots": [{"id": "runtime", "path": "/fixture/assets"}],
            # This selector is served from memory; no key file exists or opens.
            "secret_key_file": "/fixture/key-input", "admin_enrollment": admin,
            "launch_enrollment": reference("launch", "manifest", launch_raw),
            "launch_enrollment_file": "/fixture/launch", "judge_endpoint": "http://judge.example",
            "judge": {"provider": "clef-sglang", "model": "Cloudflare/clef-flash",
                      "deployment_sha256": boot.sha(b"deployment"), "tokenizer_sha256": boot.sha(b"tokenizer"),
                      "context_tokens": 256, "max_bytes": 262144, "max_questions": 12,
                      "command_deadline_ms": 2000, "guidance_deadline_ms": 5000,
                      "cache_ttl_ms": 30000, "outage_policy": "critical-only"},
        }
        arch = {"x86_64": "amd64", "aarch64": "arm64"}[boot.platform.machine()]
        release = {
            "version": executable["version"], "protocol": boot.PROTOCOL, "schema": 2,
            "source_sha256": boot.sha(b"source"), "vendor_manifest": reference("vendor", "manifest", b"{}"),
            "artifacts": [{"os": "linux", "arch": arch, "sha256": boot.sha(binary), "bytes": len(binary)}],
        }
        source = Path(boot.__file__).resolve().parents[2]
        files = {
            str(source / "scripts/v2-admin/boot.py"): b"source fixture",
            str(source / "packaging/v2/linux/laneboss-helper.service.in"): b"helper template",
            str(source / "packaging/v2/linux/laneboss-service.service.in"): b"service template",
            str(source / "packaging/v2/linux/laneboss-credential.service.in"): b"credential template",
            args.binary: binary, args.manifest: boot.encoded(release), args.boot: boot.encoded(inputs),
            "/fixture/runtime": runtime_raw, "/fixture/launch": launch_raw,
            "/fixture/key-input": bytes(range(32)), "/fixture/assets/program": binary,
        }

        def read_input(path, limit=boot.MAX_OBJECT, owner=0, mode=None, allow_empty=False):
            raw = files[str(path)]  # Any unlisted read fails instead of touching the host.
            self.assertEqual(owner, 0)
            self.assertLessEqual(len(raw), limit)
            if str(path) == inputs["secret_key_file"]:
                self.assertEqual((limit, mode), (32, 0o600))
            return raw

        # Keep all parsers, pins and enrollment validators real. Only I/O is
        # supplied in memory; a sentinel stops before any publication or account work.
        with ExitStack() as stack:
            reader = stack.enter_context(mock.patch.object(boot, "read", side_effect=read_input))
            stack.enter_context(mock.patch.object(boot, "parents", side_effect=lambda path:
                                self.assertEqual(path, Path("/fixture/assets"))))
            stack.enter_context(mock.patch.object(boot, "unprivileged_file", side_effect=lambda path:
                                self.assertEqual(path, args.binary)))
            admin_call = stack.enter_context(mock.patch.object(boot, "enrollment", wraps=boot.enrollment))
            launch_call = stack.enter_context(mock.patch.object(boot, "launch_enrollment", wraps=boot.launch_enrollment))
            boundary = stack.enter_context(mock.patch.object(boot, "catalog_path", side_effect=InputsDone))
            for name in ("publish", "directory", "command"):
                stack.enter_context(mock.patch.object(boot, name, side_effect=AssertionError("unexpected install I/O")))
            stack.enter_context(mock.patch.object(boot.os, "open", side_effect=AssertionError("unexpected file open")))
            with self.assertRaises(InputsDone):
                boot.provision(args)
            admin_call.assert_called_once_with(admin)
            launch_call.assert_called_once_with(launch, args.config, runtime_ref, runtime)
            boundary.assert_called_once_with(args.config)
            self.assertIn(mock.call(inputs["launch_enrollment_file"], 1048576), reader.call_args_list)
        print("provision validated admin_enrollment and launch_enrollment; publication not entered", flush=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
