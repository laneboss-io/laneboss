"""Execute the actual enrollment producer on the disposable Linux box."""

import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[4]
PRODUCER = ROOT / "scripts/v2-serve/case_judge.py"


class ProducerTests(unittest.TestCase):
    def test_boot_measures_actual_bytes(self):
        self.assertTrue(PRODUCER.is_file(), "installed judge producer is absent")
        spec = importlib.util.spec_from_file_location("case_judge", PRODUCER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory(prefix="lb-v2-case-judge-") as directory:
            root = Path(directory)
            stage, output = root / "stage", root / "evidence"
            stage.mkdir()
            output.mkdir()
            for relative in ("go.mod", "go.sum", "e2e/v2/cases/judge/run.py",
                             "e2e/v2/cases/judge/fit/main.go"):
                target = stage / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, target)
            subprocess.run(["go", "mod", "vendor"], cwd=stage,
                           capture_output=True, timeout=120, check=True)

            class Case:
                def __init__(self):
                    self.stage, self.root = stage, output
                def keep(self, name, raw):
                    path = output / name
                    with path.open("xb") as stream:
                        stream.write(raw)
                    return path
                def keep_json(self, name, value):
                    return self.keep(name, json.dumps(value).encode())
                def command(self, _name, argv, seconds):
                    result = subprocess.run(argv, cwd=stage, capture_output=True,
                                            timeout=seconds, check=False)
                    if result.returncode:
                        raise AssertionError(result.stderr.decode("utf-8", errors="replace"))
                    return result.stdout

            case = Case()
            value = module.boot(case)
            worker = value["enrollment"]["judge_worker"]
            program = Path(worker["tokenizer_path"])
            self.assertEqual(hashlib.sha256(program.read_bytes()).hexdigest(),
                             worker["tokenizer_executable_sha256"])
            self.assertEqual(program.read_bytes(), (output / "judge-fit.input").read_bytes())
            self.assertEqual(hashlib.sha256(Path(worker["price_file"]).read_bytes()).hexdigest(),
                             worker["price_sha256"])
            config = value["enrollment"]["judge"]
            self.assertEqual(config["tokenizer_sha256"], hashlib.sha256(
                (output / "judge-fit.spec").read_bytes()).hexdigest())
            self.assertEqual(config["deployment_sha256"], hashlib.sha256(
                (output / "judge-stack.input").read_bytes()).hexdigest())
            self.assertEqual(value["assets"][0]["file"], str(program))
            self.assertNotIn("credential_file", worker)
            for raw in (b'{"state":"short"}', '{"state":"longer 完整"}'.encode()):
                measured = subprocess.run([str(program), *worker["tokenizer_args"]],
                    input=raw, capture_output=True, timeout=10, check=True)
                fit = json.loads(measured.stdout)
                self.assertEqual(fit["InputBytes"], len(raw))
                self.assertEqual(fit["InputTokens"], 2 * len(raw) + 32)
                self.assertEqual(fit["ContextTokens"], config["context_tokens"])
                self.assertEqual(fit["TokenizerSHA256"], config["tokenizer_sha256"])
            rejected = subprocess.run([str(program), *worker["tokenizer_args"]],
                input=b'{"broken"', capture_output=True, timeout=10, check=False)
            self.assertEqual(rejected.returncode, 2)
            self.assertEqual(rejected.stdout, b"")


if __name__ == "__main__":
    unittest.main()
