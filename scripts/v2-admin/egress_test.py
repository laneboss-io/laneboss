"""Bundle/boot regressions for the disposable Linux box; no agent is run.

Run with python3 scripts/v2-admin/egress_test.py. The printed directory retains
the real assembler, input JSON, output JSON and all published document bytes.
"""

import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import ipaddress
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


spec = importlib.util.spec_from_file_location("boot", Path(__file__).with_name("boot.py"))
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def ref(name, kind, data):
    return {"id": name, "class": kind, "sha256": digest(data), "bytes": len(data)}


def base64_text(data):
    return base64.b64encode(data).decode("ascii")


def doc_ip():
    return str(ipaddress.IPv4Address(bytes((198, 51, 100, 21))))


class EgressBoot(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if sys.platform != "linux":
            raise RuntimeError("run only on the disposable Linux test box")
        source = Path(__file__).resolve().parents[2]
        cls.root = Path(tempfile.mkdtemp(prefix="lb-v2-egresswire-"))
        print("bundle evidence:", cls.root, flush=True)
        tool = cls.root / "bundle"
        with (cls.root / "build.out").open("wb") as out, (cls.root / "build.err").open("wb") as err:
            subprocess.run(["go", "build", "-o", str(tool), "./scripts/v2-serve/bundle"],
                           cwd=source, stdout=out, stderr=err, check=True, timeout=180)
        # Like egress_test.go, pin actual executable bytes and shipped sources.
        binary = Path(sys.executable).read_bytes()
        (cls.root / "runtime-artifact").write_bytes(binary)
        executable = {"id": "boot-test", "sha256": digest(binary), "version": sys.version.split()[0]}
        cls.runtime = {
            "schema": "laneboss.runtime.v2", "generation": 1,
            "artifact": executable, "bootstrap": executable, "bindings": [],
            "objects": [
                {"id": "boot-test", "role": "bootstrap", "root_id": "assets",
                 "relative_path": "laneboss", "mode": 0o555,
                 "content": ref("boot-test", "artifact", binary)},
                {"id": "boot-agent", "role": "serve-fixture-agent", "root_id": "assets",
                 "relative_path": "agent", "mode": 0o555,
                 "content": ref("boot-agent", "artifact", binary)},
            ],
        }
        runtime_raw = boot.encoded(cls.runtime)
        cls.runtime_ref = ref("runtime", "manifest", runtime_raw)
        sources = []
        for name, relative, logical, kind in (
                ("org-prompt", "org/default.md", ".laneboss/shared/templates/default.md", "prompt"),
                ("org-drivers", "org/drivers.toml", ".laneboss/shared/templates/drivers.toml", "drivers"),
                ("workflow", "org/workflow.toml", ".laneboss/shared/workflow.toml", "policy"),
                ("l5-prompt", "roles/L5/supervisor.md", ".laneboss/L5/roles/supervisor.md", "prompt"),
                ("l5-drivers", "roles/L5/supervisor.toml", ".laneboss/L5/roles/supervisor.toml", "drivers")):
            raw = (source / "templates/v2" / relative).read_bytes()
            sources.append({"id": name, "path": logical, "kind": kind, "data": base64_text(raw)})
        project = (source / "scripts/v2-serve/fixtures/README.md").read_bytes()
        cls.expires = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        data = {
            "config": "egress-boot", "runtime_ref": cls.runtime_ref, "runtime": base64_text(runtime_raw),
            "sources": sources, "project": base64_text(project), "task": base64_text(project),
            "model": "claude-sonnet-5-5", "expires_at": cls.expires,
            "judge": {
                "provider": "clef-sglang", "model": "Cloudflare/clef-flash",
                "deployment_sha256": digest(binary), "tokenizer_sha256": digest(project),
                "context_tokens": 256, "max_bytes": 262144, "max_questions": 12,
                "command_deadline_ms": 2000, "guidance_deadline_ms": 5000,
                "cache_ttl_ms": 30000, "outage_policy": "critical-only",
            },
        }
        cls.bundles = {}
        for enabled, name in ((False, "default"), (True, "egress")):
            case = cls.root / name
            case.mkdir()
            if enabled:
                data["egress_anthropic"] = True
            path = case / "input.json"
            path.write_bytes(boot.encoded(data))
            with (case / "output.json").open("wb") as out, (case / "output.err").open("wb") as err:
                subprocess.run([str(tool), "--input", str(path)], cwd=source,
                               stdout=out, stderr=err, check=True, timeout=30)
            bundle = boot.document((case / "output.json").read_bytes())
            documents = {}
            for item in bundle["documents"]:
                raw = base64.b64decode(item["data"], validate=True)
                pin = item["ref"]
                if pin["sha256"] != digest(raw) or pin["bytes"] != len(raw) or pin["id"] in documents:
                    raise RuntimeError("assembler document bytes differ from their pins")
                documents[pin["id"]] = raw
                (case / pin["id"]).write_bytes(raw)
            cls.bundles[enabled] = (bundle, documents)

    def launch(self, enabled=True):
        bundle, documents = self.bundles[enabled]
        return boot.document(documents[bundle["initial"]["launch_enrollment"]["id"]])

    def validate(self, value):
        return boot.launch_enrollment(value, "egress-boot", self.runtime_ref, self.runtime)

    def test_bundle_egress(self):
        bundle, documents = self.bundles[True]
        launch = self.launch()
        before = copy.deepcopy(launch)
        # On 8370fbab this raises the old field-map refusal for network.
        self.assertIsNone(self.validate(launch))
        self.assertEqual(launch, before)
        self.assertEqual(launch["network"], [
            {"id": "anthropic-api", "host": "api.anthropic.com", "protocol": "tcp", "port": 443}])
        root_ref = bundle["initial"]["profiles"]
        root_raw = documents[root_ref["id"]]
        boot.blob(root_ref, root_raw)
        # The real assembler also runs manifest.Root on this exact grant JSON;
        # installation retains its Go --validate-initial gate for root grants.
        grants = boot.document(root_raw)
        self.assertEqual(grants["network"], [
            {"id": "", "endpoint_id": "anthropic-api", "mode": "internet",
             "delegate": False, "expires_at": self.expires}])
        self.assertEqual(bundle["root_request"]["manifest"], root_ref)

    def test_bundle_default(self):
        bundle, documents = self.bundles[False]
        launch = self.launch(False)
        self.assertNotIn("network", launch)
        self.assertIsNone(self.validate(launch))
        grants = boot.document(documents[bundle["initial"]["profiles"]["id"]])
        self.assertEqual(grants["network"], [])

    def test_vendor_session_enrollment(self):
        runtime = copy.deepcopy(self.runtime)
        pins = {}
        content = runtime["objects"][1]["content"]
        for name in ("claudock", "claude"):
            pins[name] = {"id": name, "sha256": content["sha256"], "version": name + "-enrolled-release"}
            runtime["objects"].append({"id": name, "role": name, "root_id": "assets",
                                       "relative_path": name, "mode": 0o555, "content": dict(content, id=name)})
        runtime_ref = ref("session-runtime", "manifest", boot.encoded(runtime))
        launch = self.launch()
        for selected in launch["runtimes"]:
            selected["manifest"] = runtime_ref
            if selected["driver"] == "claudock-cli":
                selected["executable"] = pins["claudock"]
                selected["session_executable"] = pins["claude"]
        self.assertIsNone(boot.launch_enrollment(launch, "egress-boot", runtime_ref, runtime))
        for fault in ("missing", "digest", "wrapper"):
            with self.subTest(fault=fault):
                changed = copy.deepcopy(launch)
                selected = next(row for row in changed["runtimes"] if row["driver"] == "claudock-cli")
                if fault == "missing":
                    del selected["session_executable"]
                elif fault == "digest":
                    selected["session_executable"]["sha256"] = digest(b"different vendor")
                else:
                    selected["session_executable"] = pins["claudock"]
                with self.assertRaises(boot.Stopped):
                    boot.launch_enrollment(changed, "egress-boot", runtime_ref, runtime)

    def test_wrong_host(self):
        for host in ("example.com", "API.ANTHROPIC.COM", "api.anthropic.com.", 443):
            with self.subTest(host=host):
                launch = self.launch()
                launch["network"][0]["host"] = host
                with self.assertRaisesRegex(boot.Stopped, "exact Anthropic API endpoint"):
                    self.validate(launch)

    def test_private_host(self):
        for host in ("10.0.0.1", "127.0.0.1", "::1"):
            with self.subTest(host=host):
                launch = self.launch()
                launch["network"][0]["host"] = host
                with self.assertRaisesRegex(boot.Stopped, "exact Anthropic API endpoint"):
                    self.validate(launch)

    def test_wrong_port(self):
        for port in (0, 80, 444, 65536, "443", True, 443.0):
            with self.subTest(port=port):
                launch = self.launch()
                launch["network"][0]["port"] = port
                with self.assertRaisesRegex(boot.Stopped, "exact Anthropic API endpoint"):
                    self.validate(launch)

    def test_endpoint_scope(self):
        for key, value in (("id", "another-api"), ("protocol", "udp"), ("protocol", 6)):
            with self.subTest(key=key, value=value):
                launch = self.launch()
                launch["network"][0][key] = value
                with self.assertRaisesRegex(boot.Stopped, "exact Anthropic API endpoint"):
                    self.validate(launch)

    def test_unknown_fields(self):
        for location in ("enrollment", "endpoint"):
            with self.subTest(location=location):
                launch = self.launch()
                target = launch if location == "enrollment" else launch["network"][0]
                target["extra"] = True
                with self.assertRaisesRegex(boot.Stopped, "JSON field map differs"):
                    self.validate(launch)
        for key in ("id", "host", "protocol", "port"):
            with self.subTest(missing=key):
                launch = self.launch()
                del launch["network"][0][key]
                with self.assertRaisesRegex(boot.Stopped, "JSON field map differs"):
                    self.validate(launch)

    def test_network_bounds(self):
        endpoint = self.launch()["network"][0]
        for value in ({}, "anthropic-api", None, True, [endpoint, endpoint]):
            with self.subTest(network=value):
                launch = self.launch()
                launch["network"] = value
                with self.assertRaisesRegex(boot.Stopped, "only the enrolled Anthropic"):
                    self.validate(launch)
        launch = self.launch()
        launch["network"] = []
        self.assertIsNone(self.validate(launch))

    def test_host_inventory(self):
        # Host addresses exclude self destinations; Go permits private inventory.
        address = doc_ip()
        for addresses in ([], [address, "2001:db8::1", "::ffff:" + address, "10.0.0.1"],
                          [address] * 256):
            with self.subTest(count=len(addresses)):
                launch = self.launch()
                launch["network"][0]["host_addresses"] = addresses
                self.assertIsNone(self.validate(launch))

    def test_bad_addresses(self):
        padded = doc_ip().replace(".51.", ".051.")
        for address in (padded, "2001:DB8::1", "2001:db8:0:0:0:0:0:1",
                        "::ffff:c000:201", "fe80::1%eth0", "not-an-ip", "", 123, True):
            with self.subTest(address=address):
                launch = self.launch()
                launch["network"][0]["host_addresses"] = [address]
                with self.assertRaisesRegex(boot.Stopped, "invalid host address inventory"):
                    self.validate(launch)

    def test_inventory_bounds(self):
        address = doc_ip()
        for addresses in ({}, address, None, True, [address] * 257):
            with self.subTest(addresses=addresses):
                launch = self.launch()
                launch["network"][0]["host_addresses"] = addresses
                with self.assertRaisesRegex(boot.Stopped, "exact Anthropic API endpoint"):
                    self.validate(launch)


if __name__ == "__main__":
    unittest.main()
