"""Model-flag regressions through the installed launcher on the disposable Linux box.

Run beside the private suite with its tests package on PYTHONPATH. The shared
fixture doubles only the providers; CLI validation and events are real. On the
release base, the diagnostic assertion fails because typed settings validation
returns its generic model error before the established CLI check can run.
"""

import unittest

from tests.e2e import test_runner_models as models


setUpModule = models.setUpModule
tearDownModule = models.tearDownModule


class RunnerModelFlagsTest(models.RunnerModelsTest):
    def test_invalid_model_flag_diagnostic(self):
        cases = (
            ("family-alias", models.API),
            ("unsafe-character", "model-1;extra"),
            ("too-long", "m1" + "x" * 127),
        )
        for name, value in cases:
            with self.subTest(case=name):
                result = self.start("web-model-flag-" + name, "--project", "web",
                                    "--runner", "deepseek", "--model", value, code=2)
                self.assertEqual(result.stdout, "", "a refused model must produce no launch result")
                self.assertEqual(self.calls(), [], "a refused model must not invoke a provider")
                self.assertEqual(self.events(), [], "a refused model must append no event")
                self.assertNotIn(value, result.stderr, "the rejected model value must be withheld")
                self.assertIn(
                    "--model must be a full model name that includes its version, not a family alias",
                    result.stderr,
                    "invalid CLI model input must retain its established diagnostic",
                )


def load_tests(loader, standard_tests, pattern):
    # Contribute only this module's regression; shared model rows stay private.
    return unittest.TestSuite([RunnerModelFlagsTest("test_invalid_model_flag_diagnostic")])
