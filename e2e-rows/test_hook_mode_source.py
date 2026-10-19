"""Source-editing unit controls; execute only on the disposable test machine."""

from pathlib import Path
import stat
import tempfile
import tomllib
import unittest

from orgsupport import set_hook_mode


class HookModeSourceTest(unittest.TestCase):
    def test_existing_hooks_and_defaults(self):
        text = ('schema_version = 1\nlevels = [3]\n[hooks]\nmode = "blacklist"\n'
                '[[hooks.blacklist]]\nid = "fixture"\ndescription = "Fixture rule."\n'
                '[defaults]\nrole = "executor"\n')
        self.check_source(text, True)

    def test_absent_hooks_after_defaults(self):
        text = 'schema_version = 1\nlevels = [3]\n[defaults]\nrole = "executor"\n'
        self.check_source(text, False)

    def check_source(self, text, has_entry):
        with tempfile.TemporaryDirectory(prefix="lb-hook-mode-") as directory:
            source = Path(directory) / "org.toml"
            source.write_text(text, encoding="utf-8")
            source.chmod(0o444)
            for mode in ("strict", "blacklist"):
                set_hook_mode(self, source, mode)
                data = tomllib.loads(source.read_text(encoding="utf-8"))
                self.assertEqual(data["hooks"]["mode"], mode)
                self.assertEqual(data["defaults"], {"role": "executor"})
                self.assertEqual(data["levels"], [3])
                self.assertEqual(stat.S_IMODE(source.stat().st_mode), 0o444)
                self.assertEqual("blacklist" in data["hooks"], has_entry)
                if has_entry:
                    self.assertEqual(data["hooks"]["blacklist"][0]["id"], "fixture")


if __name__ == "__main__":
    unittest.main()
